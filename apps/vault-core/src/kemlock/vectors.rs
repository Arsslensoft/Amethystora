//! Kemlock's CC0 test vectors (`tests/kemlock-vectors`, commit 05a71bbf of Kemlock-Server's `test-vectors/`), and the
//! refusals the formats ask for. Each vector file is read whole: every case is held to, and every "must be refused" one.

use serde_json::Value;

use super::bundle::{Bundle, fingerprint_groups, fingerprint_text};
use super::conv::{Owner, Uuid, b64_decode, b64_encode, item_uuid, legacy_item_uuid, legacy_space_uuid, lp};
use super::item::{Kem1Body, Kem1Item, WireItem, item_aad, wrap_aad};
use super::keys::{Child, PrivateKeys, child_key, password_wrap_key, root_wrap_aad, unwrap_root_key, user_key, wrap_root_key_with_nonce};
use super::kx1::{Kx1PrivateKey, Kx1PublicKey};
use super::manifest::{Entry, Manifest};
use super::master::{Confirm, DEFAULT_PARAMS, KdfParams, master_key};
use super::sealedbox::{self, CONTEXT_DEVICE_APPROVAL, device_approval_aad};
use super::sig1::{Sig1PrivateKey, Sig1PublicKey};
use super::{Error, Key, RootKey, aead, kma1, opaque, phrase};

fn load(text: &str) -> Value {
    serde_json::from_str(text).expect("a vector file is JSON")
}

fn cases(file: &Value) -> &Vec<Value> {
    assert_eq!(file["version"], 1);
    file["cases"].as_array().expect("cases")
}

fn bytes(v: &Value) -> Vec<u8> {
    crate::seal::unhex(v.as_str().expect("a hex string")).expect("lower-case hex")
}

fn key(v: &Value) -> Key {
    Key::from_slice(&bytes(v)).expect("32 bytes")
}

fn uuid(v: &Value) -> Uuid {
    Uuid(bytes(v).try_into().expect("16 bytes"))
}

fn nonce_of(sealed: &[u8]) -> [u8; 12] {
    sealed[..12].try_into().expect("a nonce")
}

/// A copy with one byte flipped
fn flipped(data: &[u8], at: usize) -> Vec<u8> {
    let mut out = data.to_vec();
    out[at] ^= 1;
    out
}

// --- account keys, the master key, the wraps ------------------------------------------------------------------------------

#[test]
fn account_keys() {
    let file = load(include_str!("../../tests/kemlock-vectors/account-keys.json"));
    for case in cases(&file) {
        let root = RootKey::from_slice(&bytes(&case["root_key"])).expect("64 bytes");
        let user = user_key(&root);
        assert_eq!(user, key(&case["user_key"]), "{}", case["name"]);
        for child in case["children"].as_array().unwrap() {
            let label = child["label"].as_str().unwrap();
            let which =
                [Child::ItemWrap, Child::PrivateKeys, Child::Manifest].into_iter().find(|c| c.label() == label).expect("a known label");
            assert_eq!(child_key(&user, which), key(&child["key"]), "{label}");
        }
    }
}

#[test]
fn argon2id_master_key() {
    let file = load(include_str!("../../tests/kemlock-vectors/argon2id.json"));
    for case in cases(&file) {
        let params = KdfParams {
            memory_kib: case["memory_kib"].as_u64().unwrap() as u32,
            iterations: case["iterations"].as_u64().unwrap() as u32,
            parallelism: case["parallelism"].as_u64().unwrap() as u32,
        };
        let salt = bytes(&case["salt"]);
        let text = case["password_text"].as_str().unwrap();
        assert_eq!(text.as_bytes(), &bytes(&case["password"])[..]);
        let expected = key(&case["master_key"]);
        assert_eq!(super::master::derive(text, &salt, &params).unwrap(), expected, "{}", case["name"]);
        // The password is hashed in its NFC form: a decomposed one gives the same key
        let decomposed: String = text.chars().flat_map(|c| if c == '\u{e9}' { vec!['e', '\u{301}'] } else { vec![c] }).collect();
        assert_eq!(super::master::derive(&decomposed, &salt, &params).unwrap(), expected);
        if params == DEFAULT_PARAMS {
            assert_eq!(master_key(text, &salt, &params).unwrap(), expected);
        } else {
            // A few KiB is what a vector is made with, and what no server may ask for
            assert!(matches!(master_key(text, &salt, &params), Err(Error::Refused(_))));
        }
    }
}

#[test]
fn argon2id_settings_are_bounded() {
    let salt = [7u8; 16];
    let too = |p: KdfParams| matches!(master_key("pw", &salt, &p), Err(Error::Refused(_)));
    assert!(too(KdfParams { memory_kib: 16_383, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { memory_kib: 1_048_577, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { iterations: 1, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { iterations: 11, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { parallelism: 0, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { parallelism: 17, ..DEFAULT_PARAMS }));
    assert!(too(KdfParams { memory_kib: u32::MAX, iterations: u32::MAX, parallelism: u32::MAX }));
    let small = KdfParams { memory_kib: 16_384, iterations: 2, parallelism: 1 };
    assert!(master_key("pw", &salt, &small).is_ok());
    assert!(matches!(master_key("pw", &salt[..15], &small), Err(Error::Refused(_))));
    assert!(matches!(master_key("pw", &[0u8; 65], &small), Err(Error::Refused(_))));
}

#[test]
fn password_wrap() {
    let file = load(include_str!("../../tests/kemlock-vectors/password-wrap.json"));
    for case in cases(&file) {
        let master = key(&case["master_key"]);
        let export: [u8; 64] = bytes(&case["export_key"]).try_into().unwrap();
        let root = RootKey::from_slice(&bytes(&case["root_key"])).unwrap();
        let account = uuid(&case["account_id"]);
        let version = case["key_version"].as_u64().unwrap() as u32;
        let wrap = password_wrap_key(&master, &export);
        assert_eq!(wrap, key(&case["wrap_key"]));
        assert_eq!(root_wrap_aad(&account, version), bytes(&case["aad"]));
        let wrapped = bytes(&case["wrapped"]);
        assert_eq!(unwrap_root_key(&wrapped, &wrap, &account, version).unwrap(), root);
        // Made again with the nonce the vector carries, it is the same bytes
        assert_eq!(wrap_root_key_with_nonce(&root, &wrap, &nonce_of(&wrapped), &account, version), wrapped);
        // Neither the master key nor the export key alone opens it, and no other account, version, byte or length does
        let master_alone = password_wrap_key(&master, &[0u8; 64]);
        assert_eq!(unwrap_root_key(&wrapped, &master_alone, &account, version), Err(Error::Unopened));
        let export_alone = password_wrap_key(&Key::new([0u8; 32]), &export);
        assert_eq!(unwrap_root_key(&wrapped, &export_alone, &account, version), Err(Error::Unopened));
        assert_eq!(unwrap_root_key(&wrapped, &wrap, &Uuid([9; 16]), version), Err(Error::Unopened));
        assert_eq!(unwrap_root_key(&wrapped, &wrap, &account, version + 1), Err(Error::Unopened));
        for at in [0, 12, 40, wrapped.len() - 1] {
            assert_eq!(unwrap_root_key(&flipped(&wrapped, at), &wrap, &account, version), Err(Error::Unopened));
        }
        assert!(matches!(unwrap_root_key(&wrapped[..91], &wrap, &account, version), Err(Error::Malformed(_))));
        assert!(matches!(unwrap_root_key(&[wrapped.clone(), vec![0]].concat(), &wrap, &account, version), Err(Error::Malformed(_))));
    }
}

#[test]
fn sealed_private_keys() {
    let file = load(include_str!("../../tests/kemlock-vectors/private-keys.json"));
    for case in cases(&file) {
        let user = key(&case["user_key"]);
        assert_eq!(child_key(&user, Child::PrivateKeys), key(&case["child_key"]));
        let account = uuid(&case["account_id"]);
        let version = case["key_version"].as_u64().unwrap() as u32;
        let sealed = bytes(&case["sealed"]);
        let opened = PrivateKeys::open(&sealed, &user, &account, version).unwrap();
        assert_eq!(opened.kx1.as_bytes()[..], bytes(&case["kx1_private_key"])[..]);
        assert_eq!(opened.sig1.as_bytes()[..], bytes(&case["sig1_private_key"])[..]);
        let mut plain = vec![1u8];
        plain.extend_from_slice(opened.kx1.as_bytes());
        plain.extend_from_slice(opened.sig1.as_bytes());
        assert_eq!(plain, bytes(&case["plaintext"]));
        assert_eq!(opened.seal_with_nonce(&user, &nonce_of(&sealed), &account, version), sealed);
        // Another account, key version or key, and a changed byte, do not open it
        assert!(PrivateKeys::open(&sealed, &user, &Uuid([1; 16]), version).is_err());
        assert!(PrivateKeys::open(&sealed, &user, &account, version + 1).is_err());
        assert!(PrivateKeys::open(&sealed, &Key::new([3; 32]), &account, version).is_err());
        assert!(PrivateKeys::open(&flipped(&sealed, 30), &user, &account, version).is_err());
        assert!(matches!(PrivateKeys::open(&sealed[..sealed.len() - 1], &user, &account, version), Err(Error::Malformed(_))));
    }
    let fresh = PrivateKeys::generate();
    let user = Key::random();
    let account = Uuid::random_v4();
    let again = PrivateKeys::open(&fresh.seal(&user, &account, 3), &user, &account, 3).unwrap();
    assert_eq!(again.kx1.as_bytes(), fresh.kx1.as_bytes());
}

// --- kx1 and the sealed box -----------------------------------------------------------------------------------------------

#[test]
fn kx1_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/kx1.json"));
    for case in cases(&file) {
        let private = Kx1PrivateKey::from_bytes(&bytes(&case["private_key"])).unwrap();
        let mut joined = bytes(&case["mlkem_seed"]);
        joined.extend_from_slice(&bytes(&case["x25519_secret"]));
        assert_eq!(private.as_bytes()[..], joined[..]);
        let public = private.public_key();
        assert_eq!(public.as_bytes()[..], bytes(&case["public_key"])[..], "{}", case["name"]);
        let ciphertext = bytes(&case["ciphertext"]);
        assert_eq!(private.decapsulate(&ciphertext).unwrap(), key(&case["shared_secret"]));
        // ML-KEM rejects implicitly: a changed ciphertext gives another secret and no error
        for changed in case["changed_ciphertexts"].as_array().unwrap() {
            let secret = private.decapsulate(&bytes(&changed["ciphertext"])).unwrap();
            assert_eq!(secret, key(&changed["shared_secret"]), "{}", changed["description"]);
            assert_ne!(secret, key(&case["shared_secret"]));
        }
        // Encapsulating to the public key gives a ciphertext this key opens
        let (ct, secret) = public.encapsulate().unwrap();
        assert_eq!(ct.len(), 1600);
        assert_eq!(private.decapsulate(&ct).unwrap(), secret);
        // Another private key does not
        assert_ne!(Kx1PrivateKey::generate().decapsulate(&ct).unwrap(), secret);
    }
}

#[test]
fn kx1_refusals() {
    let private = Kx1PrivateKey::generate();
    let public = private.public_key();
    let (ct, _) = public.encapsulate().unwrap();
    // Lengths
    assert!(matches!(private.decapsulate(&ct[..1599]), Err(Error::Malformed(_))));
    assert!(matches!(private.decapsulate(&[ct.clone(), vec![0]].concat()), Err(Error::Malformed(_))));
    assert!(matches!(Kx1PublicKey::from_bytes(&public.as_bytes()[..1599]), Err(Error::Malformed(_))));
    assert!(matches!(Kx1PrivateKey::from_bytes(&[0u8; 95]), Err(Error::Malformed(_))));
    // An all-zero X25519 shared secret (the ephemeral key a point of low order) is refused, on both sides
    let mut zero_x = ct.clone();
    zero_x[1568..].fill(0);
    assert_eq!(private.decapsulate(&zero_x), Err(Error::Unopened));
    let mut low_order = public.as_bytes().to_vec();
    low_order[1568..].fill(0);
    let low_order = Kx1PublicKey::from_bytes(&low_order).unwrap();
    assert_eq!(low_order.encapsulate().unwrap_err(), Error::Unopened);
    // An ML-KEM public key whose coefficients are out of range
    let mut bad = public.as_bytes().to_vec();
    bad[..3].fill(0xff);
    assert!(matches!(Kx1PublicKey::from_bytes(&bad), Err(Error::Malformed(_))));
}

fn sealed_box_aad(context: &str, parts: &Value) -> Vec<u8> {
    let b = |name: &str| bytes(&parts[name]);
    let v32 = |name: &str| (parts[name].as_u64().unwrap() as u32).to_be_bytes().to_vec();
    match context {
        "device-approval" => device_approval_aad(&uuid(&parts["account_id"]), &uuid(&parts["request_id"])),
        "space-key" => [b("space_id"), v32("key_version"), b("recipient_id")].concat(),
        "collection-key" => [b("space_id"), b("collection_id"), v32("key_version"), b("recipient_id")].concat(),
        "emergency-access" => b("contact_id"),
        "account-recovery" => [b("space_id"), b("account_id"), parts["key_seq"].as_u64().unwrap().to_be_bytes().to_vec()].concat(),
        other => panic!("a context the vector does not name: {other}"),
    }
}

#[test]
fn sealed_box_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/sealed-box.json"));
    assert_eq!(cases(&file).len(), 5);
    for case in cases(&file) {
        let context = case["context"].as_str().unwrap();
        let private = Kx1PrivateKey::from_bytes(&bytes(&case["private_key"])).unwrap();
        assert_eq!(private.public_key().as_bytes()[..], bytes(&case["public_key"])[..]);
        let aad = sealed_box_aad(context, &case["aad_parts"]);
        assert_eq!(aad, bytes(&case["aad"]), "{context}");
        let boxed = bytes(&case["sealed_box"]);
        let secret = bytes(&case["secret"]);
        assert_eq!(sealedbox::open(&private, context, &aad, &boxed).unwrap()[..], secret[..], "{context}");
        // Sealed again with the nonce and the key exchange the vector carries, it is the same bytes
        let ct = boxed[1..1601].to_vec();
        let shared = private.decapsulate(&ct).unwrap();
        assert_eq!(sealedbox::seal_with(ct, &shared, &nonce_of(&boxed[1601..]), context, &aad, &secret), boxed);
        // Under any other context, it fails
        for wrong in case["wrong_contexts"].as_array().unwrap() {
            assert!(sealedbox::open(&private, wrong.as_str().unwrap(), &aad, &boxed).is_err(), "{wrong}");
        }
        // With any byte of the aad changed, or the aad empty, it fails
        for at in 0..aad.len() {
            assert!(sealedbox::open(&private, context, &flipped(&aad, at), &boxed).is_err());
        }
        assert!(sealedbox::open(&private, context, &[], &boxed).is_err());
        // With a byte of the box changed, it fails: its version, the key exchange, the sealed part and the tag
        for at in [0, 1, 1000, 1599, 1600, 1601, 1612, boxed.len() - 1] {
            assert!(sealedbox::open(&private, context, &aad, &flipped(&boxed, at)).is_err(), "byte {at}");
        }
        // Another key does not open it
        assert!(sealedbox::open(&Kx1PrivateKey::generate(), context, &aad, &boxed).is_err());
        // A fresh seal to the same key opens
        let again = sealedbox::seal(&private.public_key(), context, &aad, &secret).unwrap();
        assert_eq!(sealedbox::open(&private, context, &aad, &again).unwrap()[..], secret[..]);
    }
    assert_eq!(CONTEXT_DEVICE_APPROVAL, "device-approval");
}

#[test]
fn sealed_box_lengths_are_checked_first() {
    let private = Kx1PrivateKey::generate();
    let boxed = sealedbox::seal(&private.public_key(), "c", b"a", b"secret").unwrap();
    assert_eq!(boxed.len(), 1 + 1600 + 12 + 6 + 16);
    for len in [0, 1, 1600, 1601, 1628, boxed.len() - 7] {
        assert!(matches!(sealedbox::open(&private, "c", b"a", &boxed[..len]), Err(Error::Malformed(_))), "{len}");
    }
    let mut version = boxed.clone();
    version[0] = 2;
    assert!(matches!(sealedbox::open(&private, "c", b"a", &version), Err(Error::Malformed(_))));
    // A box that claims more than a short secret is refused unopened, and a secret that long is not sealed
    let long = vec![0u8; sealedbox::MAX_SECRET + 1];
    assert!(matches!(sealedbox::seal(&private.public_key(), "c", b"a", &long), Err(Error::Refused(_))));
    assert!(matches!(
        sealedbox::open(&private, "c", b"a", &[boxed.clone(), vec![0; sealedbox::MAX_SECRET]].concat()),
        Err(Error::Malformed(_))
    ));
    // Trailing bytes after the tag are part of the tag's input and fail it
    assert!(sealedbox::open(&private, "c", b"a", &[boxed.clone(), vec![0]].concat()).is_err());
}

// --- sig1, the bundle and the fingerprint -----------------------------------------------------------------------------

#[test]
fn sig1_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/sig1.json"));
    for case in cases(&file) {
        let private = Sig1PrivateKey::from_bytes(&bytes(&case["private_key"])).unwrap();
        let mut seeds = bytes(&case["mldsa_seed"]);
        seeds.extend_from_slice(&bytes(&case["ed25519_seed"]));
        assert_eq!(private.as_bytes()[..], seeds[..]);
        let public = private.public_key();
        assert_eq!(public.as_bytes()[..], bytes(&case["public_key"])[..], "{}", case["name"]);
        let context = case["context"].as_str().unwrap();
        let message = bytes(&case["message"]);
        let signature = bytes(&case["signature"]);
        assert_eq!(signature.len(), 3373);
        public.verify(context, &message, &signature).unwrap();
        // The vector's signatures are deterministic; ours are hedged and verify just the same
        assert_eq!(private.sign_deterministic(context, &message).unwrap(), signature);
        let hedged = private.sign(context, &message).unwrap();
        assert_ne!(hedged, signature);
        public.verify(context, &message, &hedged).unwrap();
        // Another context, a changed message and a changed byte in either half fail
        assert_eq!(public.verify("manifest-x", &message, &signature), Err(Error::Unopened));
        assert_eq!(public.verify(context, &[message.clone(), vec![0]].concat(), &signature), Err(Error::Unopened));
        if !message.is_empty() {
            assert_eq!(public.verify(context, &flipped(&message, 0), &signature), Err(Error::Unopened));
        }
        for at in [0, 100, 3308, 3309, 3340, 3372] {
            assert_eq!(public.verify(context, &message, &flipped(&signature, at)), Err(Error::Unopened), "byte {at}");
        }
        // Both halves must verify: each half alone, with the other from another key's signature, fails
        let other = Sig1PrivateKey::generate().sign_deterministic(context, &message).unwrap();
        let ml_only = [&signature[..3309], &other[3309..]].concat();
        let ed_only = [&other[..3309], &signature[3309..]].concat();
        assert_eq!(public.verify(context, &message, &ml_only), Err(Error::Unopened));
        assert_eq!(public.verify(context, &message, &ed_only), Err(Error::Unopened));
        // Lengths, and another key
        assert!(matches!(public.verify(context, &message, &signature[..3372]), Err(Error::Malformed(_))));
        assert!(matches!(public.verify(context, &message, &[signature.clone(), vec![0]].concat()), Err(Error::Malformed(_))));
        assert_eq!(Sig1PrivateKey::generate().public_key().verify(context, &message, &signature), Err(Error::Unopened));
    }
}

#[test]
fn bundle_and_fingerprint() {
    let file = load(include_str!("../../tests/kemlock-vectors/bundle.json"));
    for case in cases(&file) {
        let kx1 = Kx1PrivateKey::from_bytes(&bytes(&case["kx1_private_key"])).unwrap();
        let sig1 = Sig1PrivateKey::from_bytes(&bytes(&case["sig1_private_key"])).unwrap();
        let bundle = Bundle {
            account_id: uuid(&case["account_id"]),
            key_version: case["key_version"].as_u64().unwrap() as u32,
            kx1: kx1.public_key(),
            sig1: sig1.public_key(),
        };
        assert_eq!(bundle.kx1.as_bytes()[..], bytes(&case["kx1_public_key"])[..]);
        assert_eq!(bundle.sig1.as_bytes()[..], bytes(&case["sig1_public_key"])[..]);
        let wire = bytes(&case["bundle"]);
        assert_eq!(bundle.to_bytes(), wire);
        assert_eq!(wire.len(), 3621);
        let fingerprint = bundle.fingerprint();
        assert_eq!(fingerprint[..], bytes(&case["fingerprint"])[..]);
        let groups: Vec<String> = case["fingerprint_groups"].as_array().unwrap().iter().map(|g| g.as_str().unwrap().to_owned()).collect();
        assert_eq!(fingerprint_groups(&fingerprint).iter().map(|g| format!("{g:05}")).collect::<Vec<_>>(), groups);
        assert_eq!(fingerprint_text(&fingerprint), case["fingerprint_text"].as_str().unwrap());
        assert_eq!(fingerprint_text(&fingerprint).len(), 71);
        let signature = bytes(&case["signature"]);
        assert_eq!(sig1.sign_deterministic("bundle", &wire).unwrap(), signature);
        assert_eq!(Bundle::parse_signed(&wire, &signature).unwrap(), bundle);
        assert_eq!(Bundle::parse_signed(&wire, &bundle.sign(&sig1).unwrap()).unwrap(), bundle);
        // Refused: a changed byte of the bundle or the signature, another context's signature, trailing bytes, a cut, a label
        assert!(Bundle::parse_signed(&flipped(&wire, 20), &signature).is_err());
        assert!(Bundle::parse_signed(&flipped(&wire, 3000), &signature).is_err());
        assert!(Bundle::parse_signed(&wire, &flipped(&signature, 5)).is_err());
        assert!(Bundle::parse_signed(&wire, &sig1.sign_deterministic("manifest", &wire).unwrap()).is_err());
        assert!(matches!(Bundle::parse(&[wire.clone(), vec![0]].concat()), Err(Error::Malformed(_))));
        assert!(matches!(Bundle::parse(&wire[..wire.len() - 1]), Err(Error::Malformed(_))));
        assert!(matches!(Bundle::parse(&flipped(&wire, 0)), Err(Error::Malformed(_))));
        // A bundle signed by a key other than its own is not accepted
        let other = Sig1PrivateKey::generate().sign_deterministic("bundle", &wire).unwrap();
        assert!(Bundle::parse_signed(&wire, &other).is_err());
    }
}

// --- kem1 ------------------------------------------------------------------------------------------------------------------

#[test]
fn kem1_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/kem1.json"));
    for case in cases(&file) {
        let root = RootKey::from_slice(&bytes(&case["root_key"])).unwrap();
        let user = user_key(&root);
        assert_eq!(user, key(&case["user_key"]));
        let item_wrap = child_key(&user, Child::ItemWrap);
        assert_eq!(item_wrap, key(&case["wrap_key"]));
        let id = uuid(&case["item_id"]);
        let owner = Owner::from_bytes(&bytes(&case["owner"])).unwrap();
        let kind = case["kind"].as_str().unwrap();
        let revision = case["revision"].as_u64().unwrap();
        let key_version = case["key_version"].as_u64().unwrap() as u32;
        assert_eq!(item_aad(&id, revision, kind, &owner).unwrap(), bytes(&case["aad"]));
        assert_eq!(wrap_aad(&id, &owner, key_version), bytes(&case["wrap_aad"]));
        let ciphertext = bytes(&case["ciphertext"]);
        let wrapped = bytes(&case["wrapped_item_key"]);
        let item_key = key(&case["item_key"]);
        let json = case["item_json"].as_str().unwrap();
        // The pieces
        assert_eq!(super::item::unwrap_item_key(&item_wrap, &wrapped, &id, &owner, key_version).unwrap(), item_key);
        assert_eq!(super::item::open_item(&item_key, &id, revision, kind, &owner, &ciphertext).unwrap()[..], *json.as_bytes());
        assert_eq!(
            super::item::seal_item_with_nonce(&item_key, &nonce_of(&ciphertext), &id, revision, kind, &owner, json.as_bytes()).unwrap(),
            ciphertext
        );
        assert_eq!(super::item::wrap_item_key_with_nonce(&item_wrap, &nonce_of(&wrapped), &item_key, &id, &owner, key_version), wrapped);
        // The item, through its wire form and back
        let item = Kem1Item {
            id,
            owner,
            kind: kind.to_owned(),
            revision,
            key_version,
            body: Kem1Body::Live { ciphertext: ciphertext.clone(), item_key: wrapped.clone() },
        };
        // (An item of a space is wrapped under a collection key a personal client does not hold, and its wire form names a
        // collection: it is refused there, but its envelope opens with the key it is given.)
        let read = if owner.kind == super::conv::OwnerKind::User {
            let text = item.to_wire().to_json();
            let read = WireItem::from_json(&text).unwrap().kem1().unwrap();
            assert_eq!(read, item);
            read
        } else {
            assert!(WireItem::from_json(&item.to_wire().to_json()).unwrap().kem1().is_err());
            item.clone()
        };
        let (opened_key, opened) = read.open(&item_wrap).unwrap();
        assert_eq!(opened_key, item_key);
        assert_eq!(opened[..], *json.as_bytes());
        // It opens only as what it was sealed as: another id, revision, kind, owner and key version fail
        let open_as = |id: Uuid, revision: u64, kind: &str, owner: Owner, key_version: u32| {
            Kem1Item { id, owner, kind: kind.to_owned(), revision, key_version, body: item.body.clone() }.open(&item_wrap).is_err()
        };
        assert!(open_as(Uuid([5; 16]), revision, kind, owner, key_version));
        assert!(open_as(id, revision + 1, kind, owner, key_version));
        assert!(open_as(id, revision, "other", owner, key_version));
        assert!(open_as(
            id,
            revision,
            kind,
            Owner {
                kind: if owner.kind == super::conv::OwnerKind::User { super::conv::OwnerKind::Space } else { super::conv::OwnerKind::User },
                id: owner.id
            },
            key_version
        ));
        assert!(open_as(id, revision, kind, Owner { kind: owner.kind, id: Uuid([5; 16]) }, key_version));
        assert!(open_as(id, revision, kind, owner, key_version + 1));
        // Another key, and a changed byte of either sealed value
        assert!(read.open(&Key::new([4; 32])).is_err());
        for at in [0, 12, ciphertext.len() - 1] {
            let mut changed = item.clone();
            if let Kem1Body::Live { ciphertext, .. } = &mut changed.body {
                *ciphertext = flipped(ciphertext, at);
            }
            assert!(changed.open(&item_wrap).is_err());
        }
        for at in [0, 12, wrapped.len() - 1] {
            let mut changed = item.clone();
            if let Kem1Body::Live { item_key, .. } = &mut changed.body {
                *item_key = flipped(item_key, at);
            }
            assert!(changed.open(&item_wrap).is_err());
        }
        // A new item sealed here opens, and an edit that keeps the item key does too, with a new revision
        let made = Kem1Item::seal(&item_wrap, key_version, id, owner, kind, 1, b"{\"name\":\"n\"}").unwrap();
        let (made_key, plain) = made.open(&item_wrap).unwrap();
        assert_eq!(plain[..], *b"{\"name\":\"n\"}");
        let edited = Kem1Item::seal_under(&item_wrap, key_version, &made_key, id, owner, kind, 2, b"{\"name\":\"m\"}").unwrap();
        assert_eq!(edited.open(&item_wrap).unwrap().1[..], *b"{\"name\":\"m\"}");
        assert!(matches!(Kem1Item::seal(&item_wrap, key_version, id, owner, kind, 0, b"{}"), Err(Error::Malformed(_))));
    }
}

fn wire(text: &str) -> Result<Kem1Item, Error> {
    WireItem::from_json(text).and_then(|w| w.kem1())
}

fn live_json(extra: &str) -> String {
    let ct = b64_encode(&[7u8; 40]);
    let ik = b64_encode(&[8u8; 60]);
    format!(
        "{{\"id\":\"3c9d34fa-589c-5b3b-c6e9-d4ee23ace132\",\"owner\":\"user:3c9d34fa-589c-5b3b-c6e9-d4ee23ace132\",\"kind\":\"login\",\"format\":\"kem1\",\"revision\":4,\"keyVersion\":1,\"ciphertext\":\"{ct}\",\"itemKey\":\"{ik}\",\"deleted\":false{extra}}}"
    )
}

#[test]
fn wire_items_are_strict() {
    assert!(wire(&live_json("")).is_ok());
    // The fields the server sets are read and ignored
    assert!(wire(&live_json(",\"held\":true,\"deletedAt\":null")).is_ok());
    // `deleted` is always present, in both directions
    assert!(wire(&live_json("").replace(",\"deleted\":false", "")).is_err());
    assert!(wire(&live_json("").replace("\"deleted\":false", "\"deleted\":null")).is_err());
    // Unknown fields, a wrong format, owner, id or kind
    assert!(wire(&live_json(",\"extra\":1")).is_err());
    assert!(wire(&live_json("").replace("kem1", "kem2")).is_err());
    assert!(wire(&live_json("").replace("\"format\":\"kem1\"", "\"format\":\"bw\"")).is_err());
    assert!(wire(&live_json("").replace("user:", "group:")).is_err());
    assert!(wire(&live_json("").replace("\"owner\":\"user:3c9d34fa", "\"owner\":\"space:3c9d34fa")).is_err());
    assert!(wire(&live_json(",\"collectionId\":\"3c9d34fa-589c-5b3b-c6e9-d4ee23ace132\"")).is_err());
    assert!(wire(&live_json("").replacen("3c9d34fa-589c", "3C9D34FA-589C", 1)).is_err());
    assert!(wire(&live_json("").replace("\"login\"", "\"Login\"")).is_err());
    assert!(wire(&live_json("").replace("\"login\"", "\"\"")).is_err());
    assert!(wire(&live_json("").replace("\"login\"", &format!("\"{}\"", "a".repeat(65)))).is_err());
    assert!(wire(&live_json("").replace("\"login\"", &format!("\"{}\"", "a".repeat(64)))).is_ok());
    // Revision and key version
    assert!(wire(&live_json("").replace("\"revision\":4", "\"revision\":0")).is_err());
    assert!(wire(&live_json("").replace("\"revision\":4", "\"revision\":-1")).is_err());
    assert!(wire(&live_json("").replace("\"keyVersion\":1", "\"keyVersion\":0")).is_err());
    // What is sealed: padding, the standard alphabet, whitespace, lengths
    let ct = b64_encode(&[7u8; 40]);
    assert!(wire(&live_json("").replace(&ct, &format!("{ct}="))).is_err());
    assert!(wire(&live_json("").replace(&ct, &"+/+/".repeat(10))).is_err());
    assert!(wire(&live_json("").replace(&ct, &"-_-_".repeat(10))).is_ok());
    assert!(wire(&live_json("").replace(&ct, &format!(" {ct}"))).is_err());
    assert!(wire(&live_json("").replace(&ct, &b64_encode(&[7u8; 27]))).is_err());
    assert!(wire(&live_json("").replace(&b64_encode(&[8u8; 60]), &b64_encode(&[8u8; 59]))).is_err());
    assert!(wire(&live_json("").replace(&b64_encode(&[8u8; 60]), &b64_encode(&[8u8; 61]))).is_err());
    assert!(wire(&live_json("").replace(&ct, &"A".repeat(super::item::MAX_CIPHERTEXT / 3 * 4 + 8))).is_err());
    // A live item has both, a null is none
    assert!(wire(&live_json("").replacen(&format!(",\"ciphertext\":\"{ct}\""), "", 1)).is_err());
    assert!(wire(&live_json("").replace(&format!("\"ciphertext\":\"{ct}\""), "\"ciphertext\":null")).is_err());
    // Not JSON, or not an object
    for bad in ["", "[]", "null", "{", "\"x\"", "{}"] {
        assert!(wire(bad).is_err(), "{bad}");
    }
}

#[test]
fn tombstones_have_no_ciphertext() {
    let id = Uuid::random_v4();
    let owner = Owner::user(Uuid::random_v4());
    let tomb = Kem1Item::tombstone(id, owner, "login", 5, 1).unwrap();
    let text = tomb.to_wire().to_json();
    assert!(text.contains("\"deleted\":true"));
    assert!(!text.contains("ciphertext") && !text.contains("itemKey"));
    let read = wire(&text).unwrap();
    assert!(read.deleted() && read.ciphertext().is_none());
    assert_eq!(read, tomb);
    assert!(matches!(read.open(&Key::random()), Err(Error::Malformed(_))));
    // A live item says `"deleted":false`, always
    let live = Kem1Item::seal(&Key::random(), 1, id, owner, "note", 1, b"{}").unwrap();
    assert!(live.to_wire().to_json().contains("\"deleted\":false"));
    // A tombstone with a ciphertext or an item key is refused
    let with = |extra: &str| text.replace("\"deleted\":true", &format!("\"deleted\":true,{extra}"));
    assert!(wire(&with(&format!("\"ciphertext\":\"{}\"", b64_encode(&[1; 40])))).is_err());
    assert!(wire(&with(&format!("\"itemKey\":\"{}\"", b64_encode(&[1; 60])))).is_err());
    // A tombstone's key version is not checked: a deleted item needs none
    assert!(wire(&text.replace("\"keyVersion\":1", "\"keyVersion\":0")).is_ok());
}

// --- the manifest ---------------------------------------------------------------------------------------------------------

#[test]
fn manifest_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/manifest.json"));
    for case in cases(&file) {
        let owner = Owner::from_bytes(&bytes(&case["owner"])).unwrap();
        let entries: Vec<Entry> = case["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                let id = uuid(&e["item_id"]);
                let revision = e["revision"].as_u64().unwrap();
                let entry = if e["deleted"].as_bool().unwrap() {
                    Entry::tombstone(id, revision)
                } else {
                    Entry::live(id, revision, &bytes(&e["ciphertext"]))
                };
                assert_eq!(entry.ciphertext_hash[..], bytes(&e["ciphertext_hash"])[..]);
                entry
            })
            .collect();
        let manifest = Manifest::new(owner, case["counter"].as_u64().unwrap(), entries).unwrap();
        let wire = bytes(&case["manifest"]);
        assert_eq!(manifest.to_bytes(), wire, "{}", case["name"]);
        let signing = Sig1PrivateKey::from_bytes(&bytes(&case["signing_private_key"])).unwrap();
        let public = Sig1PublicKey::from_bytes(&bytes(&case["signing_public_key"])).unwrap();
        assert_eq!(signing.public_key(), public);
        let signature = bytes(&case["signature"]);
        assert_eq!(signing.sign_deterministic("manifest", &wire).unwrap(), signature);
        assert_eq!(Manifest::parse_signed(&wire, &signature, &public).unwrap(), manifest);
        assert_eq!(Manifest::parse_signed(&wire, &manifest.sign(&signing).unwrap(), &public).unwrap(), manifest);
        // A changed byte, another context, another key
        assert!(Manifest::parse_signed(&flipped(&wire, wire.len() - 1), &signature, &public).is_err());
        assert!(Manifest::parse_signed(&wire, &flipped(&signature, 7), &public).is_err());
        assert!(Manifest::parse_signed(&wire, &signing.sign_deterministic("bundle", &wire).unwrap(), &public).is_err());
        assert!(Manifest::parse_signed(&wire, &signature, &Sig1PrivateKey::generate().public_key()).is_err());
        // Strict reading
        assert!(matches!(Manifest::parse(&[wire.clone(), vec![0]].concat()), Err(Error::Malformed(_))));
        assert!(matches!(Manifest::parse(&wire[..wire.len() - 1]), Err(Error::Malformed(_))));
        assert!(matches!(Manifest::parse(&flipped(&wire, 0)), Err(Error::Malformed(_))));
    }
}

#[test]
fn manifest_refusals() {
    let owner = Owner::user(Uuid([1; 16]));
    let a = Entry::live(Uuid([1; 16]), 1, b"a");
    let b = Entry::tombstone(Uuid([2; 16]), 2);
    // Sorted by id whatever the order given, each id once
    let m = Manifest::new(owner, 3, vec![b.clone(), a.clone()]).unwrap();
    assert_eq!(m.entries, vec![a.clone(), b.clone()]);
    assert!(Manifest::new(owner, 3, vec![a.clone(), a.clone()]).is_err());
    // A tombstone's hash is zeros and a live entry's is not
    assert!(Manifest::new(owner, 3, vec![Entry { deleted: true, ..a.clone() }]).is_err());
    assert!(Manifest::new(owner, 3, vec![Entry { deleted: false, ciphertext_hash: [0; 32], ..b.clone() }]).is_err());
    // Reading: unsorted, a repeated id, `deleted` of 2, a count that does not fit
    let wire = m.to_bytes();
    let header = wire.len() - 2 * 57;
    let swapped = [&wire[..header], &wire[header + 57..], &wire[header..header + 57]].concat();
    assert!(Manifest::parse(&swapped).is_err());
    let twice = [&wire[..header], &wire[header..header + 57], &wire[header..header + 57]].concat();
    assert!(Manifest::parse(&twice).is_err());
    assert!(
        Manifest::parse(
            &flipped(&wire, wire.len() - 1).iter().enumerate().map(|(i, x)| if i == wire.len() - 1 { 2 } else { *x }).collect::<Vec<_>>()
        )
        .is_err()
    );
    let mut count = wire.clone();
    count[header - 1] = 3;
    assert!(Manifest::parse(&count).is_err());
    count[header - 4..header].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(Manifest::parse(&count).is_err());
    // An owner of type 3
    let mut third = wire.clone();
    third[19] = 3;
    assert!(Manifest::parse(&third).is_err());
}

// --- the phrase, the word list and the legacy ids -------------------------------------------------------------------

#[test]
fn eff_list_is_the_one_the_format_fixes() {
    use sha2::{Digest, Sha256};
    let words = phrase::list();
    assert_eq!(words.len(), phrase::WORDS);
    assert_eq!(words[0], "abacus");
    assert_eq!(words[7775], "zoom");
    let mut text = words.join("\n");
    text.push('\n');
    let sum: String = Sha256::digest(text.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(sum, phrase::LIST_SHA256);
    assert!(words.iter().all(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_lowercase() || b == b'-')));
}

#[test]
fn approval_phrases() {
    let file = load(include_str!("../../tests/kemlock-vectors/phrase.json"));
    assert!(cases(&file).len() >= 8);
    for case in cases(&file) {
        let public = bytes(&case["public_key"]);
        let digest = phrase::digest(public.as_slice().try_into().unwrap());
        assert_eq!(digest[..], bytes(&case["digest"])[..], "{}", case["name"]);
        let groups: Vec<u64> = case["groups"].as_array().unwrap().iter().map(|g| g.as_u64().unwrap()).collect();
        assert_eq!(phrase::groups(&digest).iter().map(|g| u64::from(*g)).collect::<Vec<_>>(), groups);
        let words = phrase::list();
        let indexes: Vec<u64> = case["indexes"].as_array().unwrap().iter().map(|g| g.as_u64().unwrap()).collect();
        assert_eq!(groups.iter().map(|g| g % 7776).collect::<Vec<_>>(), indexes);
        let expected = case["phrase"].as_str().unwrap();
        assert_eq!(indexes.iter().map(|i| words[*i as usize]).collect::<Vec<_>>().join(" "), expected);
        assert_eq!(phrase::phrase_of_bytes(&public).unwrap(), expected);
        // A different key gives a different phrase
        assert_ne!(phrase::phrase_of_bytes(&flipped(&public, 100)).unwrap(), expected);
        assert!(phrase::phrase_of_bytes(&public[..1599]).is_err());
    }
    // A key of ours: the phrase is the one the bytes give
    let public = Kx1PrivateKey::generate().public_key();
    assert_eq!(phrase::phrase(&public), phrase::phrase_of_bytes(public.as_bytes()).unwrap());
    assert_eq!(phrase::phrase(&public).split(' ').count(), 5);
}

#[test]
fn legacy_ids() {
    let file = load(include_str!("../../tests/kemlock-vectors/legacy-ids.json"));
    for case in cases(&file) {
        match case["type"].as_str().unwrap() {
            "space" => {
                let got = legacy_space_uuid(case["old"].as_str().unwrap()).unwrap();
                assert_eq!(got, uuid(&case["uuid"]));
                assert_eq!(got.to_string(), case["uuid_text"].as_str().unwrap());
            }
            "item" => {
                let owner = Owner::from_bytes(&bytes(&case["owner"])).unwrap();
                let old = case["old"].as_str().unwrap();
                let got = legacy_item_uuid(&owner, old);
                assert_eq!(got, uuid(&case["uuid"]), "{} {}", old, case["owner_label"]);
                assert_eq!(got.to_string(), case["uuid_text"].as_str().unwrap());
                assert_eq!(item_uuid(&owner, old), got);
            }
            "is_uuid" => {
                assert_eq!(Uuid::is_uuid(case["input"].as_str().unwrap()), case["is_uuid"].as_bool().unwrap(), "{}", case["input"])
            }
            other => panic!("{other}"),
        }
    }
    // An id that already is a UUID is never mapped
    let owner = Owner::user(Uuid([1; 16]));
    let id = Uuid::random_v4();
    assert_eq!(item_uuid(&owner, &id.to_string()), id);
    // The same old id under two owners is two items
    assert_ne!(legacy_item_uuid(&owner, "acc-1"), legacy_item_uuid(&Owner::user(Uuid([2; 16])), "acc-1"));
    // A space id is 1 to 64 characters of A-Z a-z 0-9 _ -
    assert!(legacy_space_uuid("").is_err());
    assert!(legacy_space_uuid(&"a".repeat(65)).is_err());
    assert!(legacy_space_uuid("a b").is_err());
    assert!(legacy_space_uuid(&"a".repeat(64)).is_ok());
}

// --- KMA1 ------------------------------------------------------------------------------------------------------------------

#[test]
fn kma1_vector() {
    let file = load(include_str!("../../tests/kemlock-vectors/send.json"));
    let case = cases(&file).iter().find(|c| c["kind"] == "file").expect("the file case");
    let payload_key = key(&case["payload_key"]);
    let plain = bytes(&case["file_plain"]);
    let sealed = bytes(&case["file"]);
    assert_eq!(sealed.len(), kma1::sealed_len(plain.len()));
    assert_eq!(kma1::decrypt(&payload_key, &sealed, 1 << 20).unwrap()[..], plain[..]);
    let prefix: [u8; 8] = sealed[4..12].try_into().unwrap();
    assert_eq!(kma1::encrypt_with_prefix(&payload_key, &prefix, &plain, 1 << 20).unwrap(), sealed);
    // Another key, a changed byte of the header, the chunk or the tag, a cut, an added byte
    assert!(kma1::decrypt(&Key::new([1; 32]), &sealed, 1 << 20).is_err());
    for at in [0, 3, 4, 11, 12, 30, sealed.len() - 1] {
        assert!(kma1::decrypt(&payload_key, &flipped(&sealed, at), 1 << 20).is_err(), "byte {at}");
    }
    assert!(kma1::decrypt(&payload_key, &sealed[..sealed.len() - 1], 1 << 20).is_err());
    assert!(kma1::decrypt(&payload_key, &[sealed.clone(), vec![0]].concat(), 1 << 20).is_err());
    assert!(kma1::decrypt(&payload_key, &sealed[..12], 1 << 20).is_err());
    assert!(kma1::decrypt(&payload_key, &[], 1 << 20).is_err());
}

#[test]
fn kma1_chunks() {
    let key = Key::random();
    for len in [0usize, 1, 27, 65_535, 65_536, 65_537, 131_071, 131_072, 131_073, 200_000] {
        let plain: Vec<u8> = (0..len).map(|i| (i * 31 % 251) as u8).collect();
        let sealed = kma1::encrypt(&key, &plain, 1 << 20).unwrap();
        assert_eq!(sealed.len(), 12 + len + 16 * len.div_ceil(65_536).max(1), "{len}");
        assert_eq!(sealed.len(), kma1::sealed_len(len));
        assert_eq!(&sealed[..4], b"KMA1");
        assert_eq!(kma1::decrypt(&key, &sealed, 1 << 20).unwrap()[..], plain[..], "{len}");
        assert!(kma1::decrypt(&key, &sealed, len.saturating_sub(1)).is_err() || len == 0);
        // Two files of the same bytes differ: the prefix is random
        assert_ne!(sealed, kma1::encrypt(&key, &plain, 1 << 20).unwrap());
    }
    // Chunks reordered, a whole last chunk cut (a file must end in its one last chunk), a chunk repeated
    let plain = vec![9u8; 65_536 * 2 + 5];
    let sealed = kma1::encrypt(&key, &plain, 1 << 20).unwrap();
    let c0 = &sealed[12..12 + 65_552];
    let c1 = &sealed[12 + 65_552..12 + 2 * 65_552];
    let c2 = &sealed[12 + 2 * 65_552..];
    assert_eq!(c2.len(), 21);
    let join = |parts: &[&[u8]]| [&sealed[..12], &parts.concat()[..]].concat();
    assert!(kma1::decrypt(&key, &join(&[c0, c1, c2]), 1 << 20).is_ok());
    assert!(kma1::decrypt(&key, &join(&[c1, c0, c2]), 1 << 20).is_err());
    assert!(kma1::decrypt(&key, &join(&[c0, c1]), 1 << 20).is_err());
    assert!(kma1::decrypt(&key, &join(&[c0, c0, c2]), 1 << 20).is_err());
    assert!(kma1::decrypt(&key, &join(&[c0, c2]), 1 << 20).is_err());
    // A last chunk of fewer than 16 bytes, a length no chunks make, is refused before anything is decrypted; one that is only
    // a tag is a length chunks make, and fails as a chunk that was not sealed
    assert!(matches!(kma1::decrypt(&key, &join(&[c0, &[0u8; 15]]), 1 << 20), Err(Error::Malformed(_))));
    assert!(matches!(kma1::decrypt(&key, &join(&[c0, &[0u8; 16]]), 1 << 20), Err(Error::Unopened)));
    // The size bound is checked before anything is decrypted, on both sides
    assert!(matches!(kma1::encrypt(&key, &plain, 100), Err(Error::Refused(_))));
    assert!(matches!(kma1::decrypt(&key, &sealed, 100), Err(Error::Refused(_))));
    assert!(kma1::decrypt(&key, &sealed, plain.len()).is_ok());
}

// --- OPAQUE ------------------------------------------------------------------------------------------------------------

/// The random bytes a vector lists, served in the order opaque-ke draws them: a draw of anything else is a mismatch
struct Script {
    bytes: Vec<u8>,
    at: usize,
}

impl Script {
    fn new(parts: &[&[u8]]) -> Script {
        Script { bytes: parts.concat(), at: 0 }
    }
}

use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};

impl RngCore for Script {
    fn next_u32(&mut self) -> u32 {
        panic!("opaque-ke draws bytes")
    }

    fn next_u64(&mut self) -> u64 {
        panic!("opaque-ke draws bytes")
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        let end = self.at + dest.len();
        assert!(end <= self.bytes.len(), "opaque-ke drew more than the vector lists");
        dest.copy_from_slice(&self.bytes[self.at..end]);
        self.at = end;
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), RandError> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl CryptoRng for Script {}

/// The blind scalars are 32-byte little-endian scalars, drawn by opaque-ke as 64 bytes
const ZEROS: [u8; 32] = [0; 32];

#[test]
fn opaque_vectors() {
    let file = load(include_str!("../../tests/kemlock-vectors/opaque.json"));
    assert_eq!(cases(&file).len(), 1);
    for case in cases(&file) {
        assert_eq!(bytes(&case["context"]), opaque::CONTEXT);
        let master = key(&case["password"]);
        let r = &case["random_inputs"];
        let registration = &case["registration"];
        let login = &case["login"];
        // Registration: the request, then the upload and the export key from the server's response
        let (state, request) =
            opaque::registration_start_with(&mut Script::new(&[&bytes(&r["blind_registration"]), &ZEROS]), &master).unwrap();
        assert_eq!(request, bytes(&registration["request"]));
        let finished = opaque::registration_finish_with(
            &mut Script::new(&[&bytes(&r["envelope_nonce"])]),
            state,
            &master,
            &bytes(&registration["response"]),
        )
        .unwrap();
        assert_eq!(finished.upload, bytes(&registration["upload"]));
        assert_eq!(finished.upload, bytes(&registration["record"]));
        assert_eq!(finished.export_key.as_bytes()[..], bytes(&registration["export_key"])[..]);
        // Login: KE1, then KE3, the export key and the session key from the server's KE2
        let (state, ke1) = opaque::login_start_with(
            &mut Script::new(&[&bytes(&r["blind_login"]), &ZEROS, &bytes(&r["client_keyshare_seed"]), &bytes(&r["client_nonce"])]),
            &master,
        )
        .unwrap();
        assert_eq!(ke1, bytes(&login["ke1"]));
        let ke2 = bytes(&login["ke2"]);
        let done = opaque::login_finish_with(&mut Script::new(&[]), state, &master, &ke2).unwrap();
        assert_eq!(done.ke3, bytes(&login["ke3"]));
        assert_eq!(done.export_key.as_bytes()[..], bytes(&login["export_key"])[..]);
        assert_eq!(done.export_key.as_bytes()[..], finished.export_key.as_bytes()[..]);
        assert_eq!(done.session_key.as_bytes()[..], bytes(&login["client_session_key"])[..]);
        assert_eq!(bytes(&login["server_session_key"]), bytes(&login["client_session_key"]));
        // Refused: a wrong password, a changed byte anywhere in KE2, a short or long message
        let start = |master: &Key| {
            opaque::login_start_with(
                &mut Script::new(&[&bytes(&r["blind_login"]), &ZEROS, &bytes(&r["client_keyshare_seed"]), &bytes(&r["client_nonce"])]),
                master,
            )
            .unwrap()
            .0
        };
        assert!(matches!(
            opaque::login_finish_with(&mut Script::new(&[]), start(&Key::new([5; 32])), &Key::new([5; 32]), &ke2),
            Err(Error::Unopened)
        ));
        for at in [0, 31, 32, 63, 64, 100, 200, 288, 319] {
            assert!(opaque::login_finish_with(&mut Script::new(&[]), start(&master), &master, &flipped(&ke2, at)).is_err(), "byte {at}");
        }
        assert!(matches!(opaque::login_finish_with(&mut Script::new(&[]), start(&master), &master, &ke2[..319]), Err(Error::Malformed(_))));
        assert!(matches!(
            opaque::login_finish_with(&mut Script::new(&[]), start(&master), &master, &[ke2.clone(), vec![0]].concat()),
            Err(Error::Malformed(_))
        ));
        let response = bytes(&registration["response"]);
        let again = || opaque::registration_start_with(&mut Script::new(&[&bytes(&r["blind_registration"]), &ZEROS]), &master).unwrap().0;
        assert!(matches!(
            opaque::registration_finish_with(&mut Script::new(&[&[0u8; 32]]), again(), &master, &response[..63]),
            Err(Error::Malformed(_))
        ));
        // A response that is the request reflected back is refused
        assert!(
            opaque::registration_finish_with(&mut Script::new(&[&[0u8; 32]]), again(), &master, &[request.clone(), vec![0; 32]].concat())
                .is_err()
        );
    }
}

/// The server's half, from the vector's setup, to run the whole exchange against it with fresh randomness
#[test]
fn opaque_against_a_server() {
    use opaque_ke::{
        CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters,
        ServerRegistration, ServerSetup,
    };
    let file = load(include_str!("../../tests/kemlock-vectors/opaque.json"));
    let case = &cases(&file)[0];
    let setup = ServerSetup::<opaque::Suite>::deserialize(&bytes(&case["server_setup"])).unwrap();
    let email = opaque::credential_identifier("  Alice@Example.COM ");
    assert_eq!(email, "alice@example.com");
    let id = email.as_bytes();
    let master = Key::random();
    let mut rng = opaque::Kernel;

    // Register
    let (state, request) = opaque::registration_start(&master).unwrap();
    let response =
        ServerRegistration::<opaque::Suite>::start(&setup, RegistrationRequest::deserialize(&request).unwrap(), id).unwrap().message;
    let registered = opaque::registration_finish(state, &master, &response.serialize()).unwrap();
    let record = ServerRegistration::<opaque::Suite>::finish(RegistrationUpload::deserialize(&registered.upload).unwrap());

    // Log in with the same password, under the context the format fixes
    let params = || ServerLoginParameters { context: Some(opaque::CONTEXT), identifiers: Default::default() };
    let (state, ke1) = opaque::login_start(&master).unwrap();
    let server =
        ServerLogin::start(&mut rng, &setup, Some(record.clone()), CredentialRequest::deserialize(&ke1).unwrap(), id, params()).unwrap();
    let done = opaque::login_finish(state, &master, &server.message.serialize()).unwrap();
    let server_done = server.state.finish(CredentialFinalization::deserialize(&done.ke3).unwrap(), params()).unwrap();
    assert_eq!(server_done.session_key.as_slice(), done.session_key.as_bytes());
    assert_eq!(done.export_key.as_bytes(), registered.export_key.as_bytes());

    // The export key and the master key together make the wrap key of the root key
    let wrap = password_wrap_key(&master, done.export_key.as_bytes());
    assert_eq!(wrap, password_wrap_key(&master, registered.export_key.as_bytes()));

    // The wrong password does not log in; nor does a server that answers under another context
    let wrong = Key::random();
    let (state, ke1) = opaque::login_start(&wrong).unwrap();
    let server =
        ServerLogin::start(&mut rng, &setup, Some(record.clone()), CredentialRequest::deserialize(&ke1).unwrap(), id, params()).unwrap();
    assert!(opaque::login_finish(state, &wrong, &server.message.serialize()).is_err());
    let other = ServerLoginParameters { context: Some(b"another/context"), identifiers: Default::default() };
    let (state, ke1) = opaque::login_start(&master).unwrap();
    let server = ServerLogin::start(&mut rng, &setup, Some(record), CredentialRequest::deserialize(&ke1).unwrap(), id, other).unwrap();
    assert!(opaque::login_finish(state, &master, &server.message.serialize()).is_err());
    // An unknown account is answered with a record that is not one: the same failure
    let (state, ke1) = opaque::login_start(&master).unwrap();
    let server = ServerLogin::start(&mut rng, &setup, None, CredentialRequest::deserialize(&ke1).unwrap(), id, params()).unwrap();
    assert_eq!(opaque::login_finish(state, &master, &server.message.serialize()).err(), Some(Error::Unopened));
}

// --- conventions -----------------------------------------------------------------------------------------------------------

#[test]
fn base64url_is_strict() {
    for good in ["", "AA", "AAA", "AAAA", "-_-_", "abcdefgh"] {
        let decoded = b64_decode(good).unwrap();
        assert_eq!(b64_encode(&decoded), good);
    }
    // Padding, the standard alphabet, whitespace, a length no encoding has, spare bits that are not zero
    for bad in ["AA==", "AAA=", "+/+/", "AAAA ", " AAAA", "AA\nAA", "A", "AAAAA", "AB", "AAB", "é", "AA\0A"] {
        assert!(b64_decode(bad).is_err(), "{bad:?}");
    }
    let all: Vec<u8> = (0..=255).collect();
    assert_eq!(b64_decode(&b64_encode(&all)).unwrap(), all);
}

#[test]
fn lp_uuid_and_owner() {
    assert_eq!(lp(b""), [0, 0, 0, 0]);
    assert_eq!(lp(b"ab"), [0, 0, 0, 2, b'a', b'b']);
    let id = Uuid::parse("0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b").unwrap();
    assert_eq!(id.to_string(), "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b");
    for bad in [
        "",
        "0190a1b2c3d48e5f9a0b1c2d3e4f5a6b",
        "0190A1B2-C3D4-8E5F-9A0B-1C2D3E4F5A6B",
        "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6",
        "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6bb",
        "g190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b",
        "{0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b}",
        "0190a1b2_c3d4-8e5f-9a0b-1c2d3e4f5a6b",
    ] {
        assert!(Uuid::parse(bad).is_err(), "{bad}");
    }
    let v4 = Uuid::random_v4();
    assert_eq!(v4.0[6] >> 4, 4);
    assert_eq!(v4.0[8] >> 6, 2);
    let owner = Owner::parse(&format!("user:{id}")).unwrap();
    assert_eq!(owner.to_bytes()[0], 1);
    assert_eq!(&owner.to_bytes()[1..], id.as_bytes());
    assert_eq!(owner.to_string(), format!("user:{id}"));
    assert_eq!(Owner::parse(&format!("space:{id}")).unwrap().to_bytes()[0], 2);
    assert_eq!(Owner::from_bytes(&owner.to_bytes()).unwrap(), owner);
    for bad in [
        "",
        "user:",
        "User:0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b",
        "0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b",
        "team:0190a1b2-c3d4-8e5f-9a0b-1c2d3e4f5a6b",
    ] {
        assert!(Owner::parse(bad).is_err(), "{bad}");
    }
    assert!(Owner::from_bytes(&[0; 17]).is_err());
    assert!(Owner::from_bytes(&[3; 17]).is_err());
    assert!(Owner::from_bytes(&[1; 16]).is_err());
}

#[test]
fn aead_refuses_short_and_trailing() {
    let key = [1u8; 32];
    let sealed = aead::seal(&key, b"hello", b"aad");
    assert_eq!(sealed.len(), 12 + 5 + 16);
    assert_eq!(aead::open(&key, &sealed, b"aad").unwrap()[..], *b"hello");
    assert!(matches!(aead::open(&key, &sealed[..27], b"aad"), Err(Error::Malformed(_))));
    assert!(aead::open(&key, &sealed, b"aae").is_err());
    assert!(aead::open(&key, &[sealed.clone(), vec![0]].concat(), b"aad").is_err());
    assert_eq!(aead::open(&key, &aead::seal(&key, b"", b""), b"").unwrap().len(), 0);
}

// --- decoders never panic ------------------------------------------------------------------------------------------------

/// A xorshift stream: the same "random" inputs every run
struct Noise(u64);

impl Noise {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Every prefix of a value (for a short one) or a spread of them, the value with a byte more, one changed, one removed from the
/// middle, and pure noise of its length and of nearby lengths
fn mutations(valid: &[u8], noise: &mut Noise) -> Vec<Vec<u8>> {
    let mut out = vec![];
    let step = (valid.len() / 97).max(1);
    for cut in (0..valid.len()).step_by(step) {
        out.push(valid[..cut].to_vec());
    }
    out.push(valid[..valid.len().saturating_sub(1)].to_vec());
    out.push([valid, &[0]].concat());
    out.push([valid, &noise.bytes(33)].concat());
    for _ in 0..24 {
        let mut changed = valid.to_vec();
        if !changed.is_empty() {
            let at = noise.next() as usize % changed.len();
            changed[at] = noise.next() as u8;
            out.push(changed);
        }
        let mut removed = valid.to_vec();
        if !removed.is_empty() {
            removed.remove(noise.next() as usize % valid.len());
            out.push(removed);
        }
    }
    for len in [0, 1, valid.len().saturating_sub(1), valid.len(), valid.len() + 1] {
        out.push(noise.bytes(len));
    }
    out
}

#[test]
fn decoders_never_panic_on_damaged_input() {
    let mut noise = Noise(0x9e37_79b9_7f4a_7c15);
    let user = Key::random();
    let account = Uuid::random_v4();
    let private = PrivateKeys::generate();
    let owner = Owner::user(account);

    // The sealed private keys, the wrapped root key, the sealed box, a bundle, a manifest, an item key
    let sealed = private.seal(&user, &account, 1);
    for input in mutations(&sealed, &mut noise) {
        let _ = PrivateKeys::open(&input, &user, &account, 1);
    }
    let wrap = password_wrap_key(&user, &[2; 64]);
    let wrapped = super::keys::wrap_root_key(&RootKey::random(), &wrap, &account, 1);
    for input in mutations(&wrapped, &mut noise) {
        let _ = unwrap_root_key(&input, &wrap, &account, 1);
    }
    let boxed = sealedbox::seal(&private.kx1.public_key(), "c", b"a", &[7; 64]).unwrap();
    for input in mutations(&boxed, &mut noise) {
        let _ = sealedbox::open(&private.kx1, "c", b"a", &input);
        let _ = private.kx1.decapsulate(&input);
    }
    let bundle = Bundle { account_id: account, key_version: 1, kx1: private.kx1.public_key(), sig1: private.sig1.public_key() };
    let bundle_bytes = bundle.to_bytes();
    let bundle_sig = bundle.sign(&private.sig1).unwrap();
    for input in mutations(&bundle_bytes, &mut noise) {
        let _ = Bundle::parse(&input);
        let _ = Kx1PublicKey::from_bytes(&input);
        let _ = Sig1PublicKey::from_bytes(&input);
        let _ = phrase::phrase_of_bytes(&input);
    }
    for input in mutations(&bundle_sig, &mut noise) {
        let _ = bundle.sig1.verify("bundle", &bundle_bytes, &input);
    }
    let manifest = Manifest::new(owner, 4, vec![Entry::live(Uuid([1; 16]), 1, b"x"), Entry::tombstone(Uuid([2; 16]), 3)]).unwrap();
    for input in mutations(&manifest.to_bytes(), &mut noise) {
        let _ = Manifest::parse(&input);
    }
    let item_wrap = child_key(&user, Child::ItemWrap);
    let item = Kem1Item::seal(&item_wrap, 1, Uuid([3; 16]), owner, "login", 1, b"{\"name\":\"x\"}").unwrap();
    let Kem1Body::Live { ciphertext, item_key } = &item.body else { unreachable!() };
    for input in mutations(item_key, &mut noise) {
        let _ = super::item::unwrap_item_key(&item_wrap, &input, &item.id, &owner, 1);
    }
    for input in mutations(ciphertext, &mut noise) {
        let _ = super::item::open_item(&Key::random(), &item.id, 1, "login", &owner, &input);
    }
    // The item's JSON, cut and changed at every place, as text
    let text = item.to_wire().to_json();
    for cut in 0..text.len() {
        if text.is_char_boundary(cut) {
            let _ = wire(&text[..cut]);
        }
    }
    for input in mutations(text.as_bytes(), &mut noise) {
        if let Ok(text) = String::from_utf8(input) {
            let _ = wire(&text);
        }
    }
    // KMA1
    let file = kma1::encrypt(&user, &[5u8; 70_000], 1 << 20).unwrap();
    for input in mutations(&file, &mut noise) {
        let _ = kma1::decrypt(&user, &input, 1 << 20);
    }
    for input in mutations(b"KMA1\0\0\0\0\0\0\0\0", &mut noise) {
        let _ = kma1::decrypt(&user, &input, 1 << 20);
    }
    // OPAQUE messages
    let (state, _) = opaque::login_start(&user).unwrap();
    let _ = opaque::login_finish(state, &user, &noise.bytes(320));
    for len in [0, 1, 63, 64, 65, 319, 320, 321] {
        let (state, _) = opaque::login_start(&user).unwrap();
        let _ = opaque::login_finish(state, &user, &noise.bytes(len));
        let (state, _) = opaque::registration_start(&user).unwrap();
        let _ = opaque::registration_finish(state, &user, &noise.bytes(len));
    }
    // Text: base64url, uuid, owner
    for input in mutations(b"AAAA-_-_AAAA", &mut noise) {
        if let Ok(text) = String::from_utf8(input) {
            let _ = b64_decode(&text);
            let _ = Uuid::parse(&text);
            let _ = Owner::parse(&text);
        }
    }
}
