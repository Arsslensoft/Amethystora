//! Each kind of the Vault as the Kemlock item it goes as, and back, with the examples of `spec-items.md` section 4: what is written is
//! the input with only the mapped keys changed, and every key this client does not know comes back as it was.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use super::common::*;
use crate::items::{OldPassword, Password, Secret};
use crate::keys::KeyType;
use crate::kemlock::sync::items::{self, Taken};
use crate::sync::convert::Direct;
use crate::sync::map::{self, Local};

const NOW: i64 = 1_765_000_000_000;

fn local(kind: &str, id: &str, value: Value) -> Local {
    let meta = map::meta_of(kind, &value);
    Local { kind: kind.into(), id: id.into(), name: map::name_of(kind, &value), meta, approval: crate::protocol::Approval::WhileOpen, value }
}

fn compose(local: &Local, base: Option<&Value>) -> items::Mapped {
    match items::compose(local, base, NOW, None, &Direct) {
        Ok(mapped) => mapped,
        Err(_) => panic!("an item that does not map: {} {}", local.kind, local.id),
    }
}

fn read(kem_kind: &str, plain: &Value, existing: Option<&Local>) -> Box<items::Read> {
    match items::take(kem_kind, plain, existing, None, NOW, &Direct) {
        Taken::Item(read) => read,
        Taken::Untouched => panic!("left alone: {plain}"),
        Taken::Conflict => panic!("a conflict: {plain}"),
    }
}

fn untouched(kem_kind: &str, plain: &Value, existing: Option<&Local>) -> bool {
    matches!(items::take(kem_kind, plain, existing, None, NOW, &Direct), Taken::Untouched)
}

fn conflict(kem_kind: &str, plain: &Value, existing: Option<&Local>) -> bool {
    matches!(items::take(kem_kind, plain, existing, None, NOW, &Direct), Taken::Conflict)
}

/// Every key of `inner` is in `outer` with the same value
fn assert_contains(outer: &Value, inner: &Value) {
    for (key, value) in inner.as_object().unwrap() {
        assert_eq!(outer.get(key), Some(value), "`{key}` of {outer}");
    }
}

fn vault_login() -> Local {
    let value = serde_json::to_value(Password {
        id: PASSWORD_ID.into(),
        title: "Larkspur Mail".into(),
        username: "sam@example.org".into(),
        address: "https://mail.larkspur.example/login".into(),
        password: Secret::new("cobalt-otter-41"),
        note: Some(Secret::new("Recovery phone is the work one.")),
        history: vec![OldPassword { password: Secret::new("old-otter-40"), changed_at: 1_764_000_000_000 }],
        tags: Some(vec!["work".into()]),
        order: Some(3),
        added_at: 1_760_000_000_000,
        updated_at: Some(1_764_000_000_000),
        ..Password::default()
    })
    .unwrap();
    local("password", PASSWORD_ID, value)
}

// --- login ---------------------------------------------------------------------------------------------------------------------

#[test]
fn a_login_the_vault_wrote_is_the_example_and_reads_back_as_it_was() {
    let held = vault_login();
    let mapped = compose(&held, None);
    assert_eq!(mapped.kind, "login");
    assert!(mapped.file.is_none());
    assert_eq!(
        mapped.plain,
        json!({"id": PASSWORD_ID, "name": "Larkspur Mail", "username": "sam@example.org", "password": "cobalt-otter-41",
               "websites": ["mail.larkspur.example"], "uris": [{"uri": "https://mail.larkspur.example/login"}],
               "note": "Recovery phone is the work one.", "previousPasswords": [{"password": "old-otter-40", "until": 1_764_000_000_000i64}],
               "tags": ["work"], "addedAt": 1_760_000_000_000i64, "updatedAt": 1_764_000_000_000i64, "amethystora": {"order": 3}})
    );
    let back = read("login", &mapped.plain, None);
    assert_eq!((back.kind, back.id.as_str(), back.name.as_str()), ("password", PASSWORD_ID, "Larkspur Mail"));
    assert_eq!(back.value, held.value, "what comes back is what went");
    let existing = read("login", &mapped.plain, Some(&held));
    assert_eq!(map::hash(&Local { kind: "password".into(), id: PASSWORD_ID.into(), name: existing.name.clone(), meta: existing.meta.clone(), approval: held.approval, value: existing.value.clone() }), map::hash(&held));
    // Changing the password over what the server held puts the time of the change beside it
    let mut edited = held.clone();
    edited.value["password"] = json!("cobalt-otter-42");
    let again = compose(&edited, Some(&mapped.plain));
    assert_eq!(again.plain["password"], "cobalt-otter-42");
    assert_eq!(again.plain["passwordChangedAt"], 1_764_000_000_000i64);
    assert_eq!(again.plain["websites"], mapped.plain["websites"]);
}

#[test]
fn a_login_the_kemlock_app_wrote_reads_in_and_an_edit_keeps_what_the_vault_does_not_know() {
    let plain = json!({"id": "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257", "name": "GitHub", "username": "sam", "password": "hunter2-but-longer",
                       "websites": ["github.com"], "pinned": true, "accountId": "848d7ae8-73b0-431e-8f3a-0efce7efc966", "addedAt": 1_762_000_000_000i64,
                       "x-from-the-future": {"a": [1, 2]}});
    let read = read("login", &plain, None);
    assert_eq!(read.id, "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257");
    assert_eq!((read.value["title"].as_str(), read.value["username"].as_str(), read.value["address"].as_str()), (Some("GitHub"), Some("sam"), Some("github.com")));
    let held = local("password", &read.id, read.value.clone());
    let mut edited = held.clone();
    edited.value["note"] = json!("a note");
    let again = compose(&edited, Some(&plain));
    assert_contains(&again.plain, &json!({"pinned": true, "accountId": "848d7ae8-73b0-431e-8f3a-0efce7efc966", "x-from-the-future": {"a": [1, 2]}, "websites": ["github.com"], "note": "a note"}));
    assert!(again.plain.get("uris").is_none(), "no rule was made for a host that is its own default rule");
}

#[test]
fn a_login_in_the_web_vaults_dialect_reads_in_and_keeps_its_own_keys() {
    let plain = json!({"id": "e431ee74-7a9a-45e5-8d9c-5f38810450d4", "name": "Router", "username": "admin", "password": "",
                       "urls": ["https://192.168.1.1"], "notes": "Admin page", "favorite": true, "updatedAt": 1_764_100_000_000i64});
    let read = read("login", &plain, None);
    assert_eq!(read.value["address"], "https://192.168.1.1");
    assert_eq!(read.value["note"], "Admin page");
    assert_eq!(read.value["password"], "");
    assert_eq!(read.value["addedAt"], 0);
    let held = local("password", &read.id, read.value.clone());
    // An edit keeps `urls` and `favorite`, and the web vault's `notes` is kept in step with the note
    let mut edited = held;
    edited.value["note"] = json!("Admin page, changed");
    edited.value["address"] = json!("https://192.168.1.2");
    let again = compose(&edited, Some(&plain));
    assert_contains(&again.plain, &json!({"favorite": true, "notes": "Admin page, changed", "note": "Admin page, changed"}));
    assert_eq!(again.plain["urls"][0], "https://192.168.1.2");
}

#[test]
fn a_hosts_websites_and_rules_agree_whatever_the_address_looks_like() {
    // spec-items 2.1: punycode, `www.`, ports, IPv4, a trailing dot; what is no host is none
    for (address, host) in [
        ("https://BÜCHER.example/login", Some("xn--bcher-kva.example")),
        ("https://www.example.org/", Some("example.org")),
        ("https://example.org:8443/x?y=1#z", Some("example.org")),
        ("http://192.168.1.1:8080/", Some("192.168.1.1")),
        ("https://example.org./", Some("example.org")),
        ("https://user:pw@Example.ORG/", Some("example.org")),
        ("example.org", Some("example.org")),
        ("//example.org/path", Some("example.org")),
        ("localhost", None),
        ("https://[::1]/", None),
        ("a b.example", None),
        ("https://example.123/", None),
        ("https://-bad-.example/", None),
        ("", None),
    ] {
        assert_eq!(items::host_of(address).as_deref(), host, "{address}");
    }
    // Every rule the vault writes that fills on a host has its host in `websites`, or the app deletes the rule on read
    for address in ["https://BÜCHER.example/login", "https://www.example.org/x", "https://example.org:8443/x", "http://192.168.1.1:8080/", "https://example.org./", "example.org", "localhost", "https://[::1]/x"] {
        let mut held = vault_login();
        held.value["address"] = json!(address);
        let plain = compose(&held, None).plain;
        let websites: Vec<String> = plain["websites"].as_array().map(|list| list.iter().map(|h| h.as_str().unwrap().to_string()).collect()).unwrap_or_default();
        for rule in plain["uris"].as_array().into_iter().flatten() {
            if let Some(host) = items::host_of(rule["uri"].as_str().unwrap()) {
                assert!(websites.contains(&host), "{address}: {host} is not in {websites:?}");
            }
        }
        // And it reads back as the address the person typed
        assert_eq!(read("login", &plain, None).value["address"], address, "{address}");
    }
}

// --- otp and backup codes -----------------------------------------------------------------------------------------------------

#[test]
fn authenticator_accounts_round_trip_with_the_keys_the_vault_does_not_know() {
    let cases = [
        json!({"id": ACCOUNT_ID, "type": "totp", "issuer": "GitHub", "label": "sam", "secret": "JBSWY3DPEHPK3PXP", "algorithm": "SHA1", "digits": 6, "period": 30,
               "tags": ["work"], "order": 2, "addedAt": 1_762_000_000_000i64, "updatedAt": 1_763_000_000_000i64}),
        json!({"id": "6eee4b71-a647-4a93-ad46-3ed1e91e3457", "type": "hotp", "issuer": "Bank", "label": "card-reader", "secret": "GEZDGNBVGY3TQOJQ", "algorithm": "SHA1",
               "digits": 8, "period": 30, "counter": 17, "noBackupCodes": true, "addedAt": 1_761_000_000_000i64}),
        json!({"id": "58a24d70-ba26-4ed6-ac37-02bc47e63c51", "type": "steam", "issuer": "Steam", "label": "sam_plays", "secret": "KRSXG5CTMVRXEZLU", "algorithm": "SHA1",
               "digits": 6, "period": 30, "addedAt": 1_761_500_000_000i64, "breachesDismissed": ["Steam2011"], "websites": ["steampowered.com"]}),
    ];
    for plain in cases {
        let id = plain["id"].as_str().unwrap();
        let taken = read("otp", &plain, None);
        assert_eq!((taken.kind, taken.id.as_str()), ("authenticator", id));
        let held = local("authenticator", id, taken.value.clone());
        let mapped = compose(&held, None);
        assert_eq!(mapped.kind, "otp");
        // The input with only the mapped keys changed: every key of it comes back, and the unknown ones with it
        assert_contains(&mapped.plain, &plain);
        // Composed over what the server held, the same
        assert_contains(&compose(&held, Some(&plain)).plain, &plain);
    }
}

#[test]
fn backup_codes_round_trip_with_used_on_every_code() {
    let plain = json!({"id": CODES_ID, "serviceName": "GitHub", "codes": [{"code": "a1b2-c3d4", "used": false}, {"code": "e5f6-a7b8", "used": true, "usedAt": 1_763_500_000_000i64}],
                       "note": "Printed copy in the drawer.", "addedAt": 1_762_000_000_000i64, "updatedAt": 1_763_500_000_000i64, "account": ACCOUNT_ID, "tags": ["work"]});
    let taken = read("backup-codes", &plain, None);
    assert_eq!(taken.kind, "backup-codes");
    let held = local("backup-codes", CODES_ID, taken.value.clone());
    let mapped = compose(&held, None);
    assert_contains(&mapped.plain, &plain);
    let another = json!({"id": "9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f", "serviceName": "Proton", "codes": [{"code": "11111111"}], "addedAt": 1_762_500_000_000i64, "breachesDismissed": ["Proton2024"]});
    let held = local("backup-codes", "9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f", read("backup-codes", &another, None).value.clone());
    let mapped = compose(&held, Some(&another));
    assert_eq!(mapped.plain["codes"][0]["used"], false, "the app wants `used` on every code");
    assert_eq!(mapped.plain["breachesDismissed"], json!(["Proton2024"]));
    // A list of codes that are not objects fails the app itself: not an item to take
    let broken = json!({"id": "9c0d1e2f-3a4b-4c5d-8e6f-7a8b9c0d1e2f", "serviceName": "X", "codes": ["a", "b"], "addedAt": 1});
    assert!(conflict("backup-codes", &broken, None));
}

// --- keys ------------------------------------------------------------------------------------------------------------------------

#[test]
fn an_ssh_key_goes_as_an_ssh_item_and_comes_back_as_the_same_key() {
    let held = key_local(SSH_ID, "laptop", "ssh", KeyType::Ed25519);
    let mapped = compose(&held, None);
    assert_eq!(mapped.kind, "ssh-key");
    assert_eq!((mapped.plain["kind"].as_str(), mapped.plain["algorithm"].as_str(), mapped.plain["origin"].as_str()), (Some("ssh"), Some("ed25519"), Some("imported")));
    assert_eq!(mapped.plain["private"], held.value["key"], "PKCS#8 as the Vault holds it");
    assert!(mapped.plain["public"].as_str().is_some_and(|public| held.value["public"]["pem"].as_str().unwrap().contains(public)));
    let back = read("ssh-key", &mapped.plain, None);
    assert_eq!((back.kind, back.id.as_str(), back.value["key_kind"].as_str(), back.value["type"].as_str()), ("key", SSH_ID, Some("ssh"), Some("ed25519")));
    assert_eq!(back.value["key"], held.value["key"]);
    // The same key taken over the item it is: nothing else changes
    let again = read("ssh-key", &mapped.plain, Some(&held));
    assert_eq!(again.value["key"], held.value["key"]);
    // A public half that is not this key's, an algorithm that is not its type, and another key under a held id are not taken
    let mut wrong_public = mapped.plain.clone();
    wrong_public["public"] = json!(key_local("x", "x", "ssh", KeyType::Ed25519).value["public"]["pem"].as_str().unwrap().lines().filter(|l| !l.starts_with("-----")).collect::<String>());
    assert!(conflict("ssh-key", &wrong_public, None));
    let mut wrong_algorithm = mapped.plain.clone();
    wrong_algorithm["algorithm"] = json!("ecdsa-p256");
    assert!(conflict("ssh-key", &wrong_algorithm, None));
    let other = key_local(SSH_ID, "laptop", "ssh", KeyType::Ed25519);
    assert!(conflict("ssh-key", &mapped.plain, Some(&other)), "another key under the same id is a conflict, never an overwrite");
}

#[test]
fn an_exchange_key_a_p521_ssh_key_and_an_aes_key_each_have_their_place() {
    let exchange = key_local(EXCHANGE_ID, "backup recipient", "exchange", KeyType::X25519);
    let mapped = compose(&exchange, None);
    assert_eq!((mapped.kind, mapped.plain["kind"].as_str(), mapped.plain["algorithm"].as_str()), ("key", Some("exchange"), Some("x25519")));
    let back = read("key", &mapped.plain, None);
    assert_eq!(back.value["key_kind"], "exchange");
    // An imported P-521 SSH key has no SSH form in the app: a `key` of kind `other`, with the vault's own word for what it is
    let p521 = {
        use openssl::ec::{EcGroup, EcKey};
        use openssl::nid::Nid;
        use openssl::pkey::PKey;
        let pkey = PKey::from_ec_key(EcKey::generate(&EcGroup::from_curve_name(Nid::SECP521R1).unwrap()).unwrap()).unwrap();
        let value = json!({"key_kind": "ssh", "type": "ecdsa-p521", "key": B64.encode(pkey.private_key_to_pkcs8().unwrap()), "exportable": true, "public": null, "comment": null});
        local("key", "c41d7f0a9b2e3c58", value)
    };
    let mapped = compose(&p521, None);
    assert_eq!(mapped.kind, "key");
    assert_eq!((mapped.plain["kind"].as_str(), mapped.plain["algorithm"].as_str()), (Some("other"), Some("1.3.132.0.35")));
    assert_eq!(mapped.plain["amethystora"]["key_kind"], "ssh");
    assert!(mapped.plain.get("public").is_none(), "the app has no public half to name for it");
    let back = read("key", &mapped.plain, None);
    assert_eq!((back.value["type"].as_str(), back.value["key_kind"].as_str()), (Some("ecdsa-p521"), Some("ssh")));
    // An AES key goes as a note whose text is the key, and reads back only by the mark the vault put in it
    let aes = key_local(AES_ID, "disk image key", "symmetric", KeyType::Aes256);
    let mapped = compose(&aes, None);
    assert_eq!(mapped.kind, "note");
    assert_eq!(mapped.plain["text"], format!("{}\n", aes.value["key"].as_str().unwrap()));
    assert_eq!(mapped.plain["amethystora"], json!({"kind": "key", "key_kind": "symmetric", "type": "aes-256"}));
    let back = read("note", &mapped.plain, None);
    assert_eq!((back.value["type"].as_str(), back.value["key"].as_str()), (Some("aes-256"), aes.value["key"].as_str()));
    // A note of the app's own, with no such mark, is not the vault's to read
    let wifi = json!({"id": "2f6b8d0e-4a1c-4e3f-a5b7-c9d1e3f5a7b9", "title": "Wi-Fi", "text": "Network: Larkspur\nPassword: correct horse", "pinned": true, "addedAt": 1_761_000_000_000i64});
    assert!(untouched("note", &wifi, None));
    assert!(items::reads("note", &wifi).is_none());
}

#[test]
fn a_certificate_goes_with_its_chain_and_is_taken_back_only_over_the_same_certificate() {
    let held = cert_local(CERT_ID, "Document signing");
    let mapped = compose(&held, None);
    assert_eq!((mapped.kind, mapped.plain["kind"].as_str(), mapped.plain["algorithm"].as_str()), ("certificate", Some("signing"), Some("ed25519")));
    assert!(mapped.plain["certificate"].as_str().unwrap().starts_with("-----BEGIN CERTIFICATE-----"));
    assert_eq!(mapped.plain["amethystora"]["kind"], "certificate");
    assert_eq!(mapped.plain["amethystora"]["profile"], "code");
    // A certificate the vault does not have is not taken in (nothing says it is the person's), and the same one is the same
    assert!(untouched("certificate", &mapped.plain, None));
    let same = read("certificate", &mapped.plain, Some(&held));
    assert_eq!(same.value["cert"], held.value["cert"]);
    // Another certificate over a held id is a conflict: the vault's stays and nothing is deleted
    let other = cert_local(CERT_ID, "Another");
    assert!(conflict("certificate", &mapped.plain, Some(&other)));
    // The web vault's, with no vault mark, is left alone
    let web = json!({"id": "7d2f9a40-1c3b-4e5d-9f60-718293a4b5c6", "name": "Home NAS", "kind": "signing", "algorithm": "ed25519", "private": mapped.plain["private"], "origin": "imported",
                     "certificate": mapped.plain["certificate"], "addedAt": 1});
    assert!(untouched("certificate", &web, None));
}

// --- notes with a file ------------------------------------------------------------------------------------------------------------

#[test]
fn a_protected_file_is_a_note_with_one_attachment_and_a_second_write_does_not_make_another() {
    let held = file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's");
    let mapped = compose(&held, None);
    assert_eq!(mapped.kind, "note");
    let file = mapped.file.as_ref().expect("the file goes beside the note");
    assert_eq!((file.name.as_str(), file.bytes.as_slice()), ("tax-2025.pdf", &b"a file of the person's"[..]));
    let attachment = items::attachment_of(&mapped.plain).expect("the note names it");
    assert_eq!((attachment["name"].as_str(), attachment["size"].as_u64()), (Some("tax-2025.pdf"), Some(22)));
    assert!(attachment.get("kemlockFile").is_none(), "before the upload the note names no file the server lacks");
    assert_eq!(B64.decode(attachment["key"].as_str().unwrap()).unwrap().len(), 32, "a key of its own, in the app's own base64");
    assert_eq!(mapped.plain["amethystora"]["kind"], "protected");
    assert_eq!(mapped.plain["amethystora"]["what"], "file");
    assert_eq!((mapped.plain["title"].as_str(), mapped.plain["text"].as_str()), (Some("tax-2025.pdf"), Some("")));
    // After the upload the note names it, and writing again with the file unchanged sends nothing and makes no second attachment
    let mut named = mapped.plain.clone();
    items::name_file(&mut named, "server-file-id");
    assert_eq!(items::files_named(&named), vec!["server-file-id".to_string()]);
    let again = items::compose(&held, Some(&named), NOW, Some(&file.sha256), &Direct).ok().unwrap();
    assert!(again.file.is_none());
    assert_eq!(again.plain["attachments"], named["attachments"]);
    // A changed file is a new attachment, and the old one is dropped from the note once the new is named
    let mut changed = held.clone();
    changed.value["files"][0]["data"] = json!(B64.encode(b"another file entirely"));
    let new = items::compose(&changed, Some(&named), NOW, Some(&file.sha256), &Direct).ok().unwrap();
    assert!(new.file.is_some());
    let list = new.plain["attachments"].as_array().unwrap();
    assert_eq!(list.len(), 1, "the note names the new file alone: the old one is dropped from the server once the write is taken");
    assert_ne!(list[0]["id"], attachment["id"]);
    // It reads back over the item, only with the file fetched and opened
    let wanting = items::take("note", &mapped.plain, Some(&held), None, NOW, &Direct);
    assert!(matches!(wanting, Taken::Item(read) if read.needs_file));
    let whole = match items::take("note", &mapped.plain, Some(&held), Some(&file.bytes), NOW, &Direct) {
        Taken::Item(read) => read,
        _ => panic!("not taken"),
    };
    assert!(!whole.needs_file);
    assert_eq!(whole.value, held.value);
    // A note of this kind that the vault does not hold is not made from the server's
    assert!(untouched("note", &mapped.plain, None));
}

#[test]
fn a_protected_folder_is_a_tar_with_its_own_media_type() {
    let held = folder_local(FOLDER_ID, "keys");
    let mapped = compose(&held, None);
    let attachment = items::attachment_of(&mapped.plain).unwrap();
    assert_eq!((attachment["name"].as_str(), attachment["type"].as_str()), (Some("keys.tar"), Some("application/x-tar")));
    assert_eq!(mapped.plain["amethystora"]["what"], "folder");
    let file = mapped.file.unwrap();
    assert_eq!(file.media, Some("application/x-tar"));
    // The tar reads back as the same folder
    let whole = match items::take("note", &mapped.plain, Some(&held), Some(&file.bytes), NOW, &Direct) {
        Taken::Item(read) => read,
        _ => panic!("not taken"),
    };
    assert_eq!(whole.value["files"], held.value["files"]);
}

// --- What is not the vault's ------------------------------------------------------------------------------------------------------

#[test]
fn items_of_kinds_the_vault_does_not_read_are_untouched() {
    for kind in ["pgp-key", "secure-note", "card", "identity", "bank-account", "cipher", "future-kind"] {
        assert!(items::reads(kind, &json!({"id": "x"})).is_none(), "{kind}");
        assert!(untouched(kind, &json!({"id": "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257", "name": "x"}), None), "{kind}");
    }
    // An item with a space is not the person's own vault's
    let spaced = json!({"id": "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257", "name": "GitHub", "password": "x", "spaceId": "a-space"});
    assert!(items::reads("login", &spaced).is_none());
    assert!(items::reads("login", &json!({"spaceId": null})).is_some());
    // An id that is not an id the vault knows is not taken
    assert!(untouched("login", &json!({"id": "../etc/passwd", "name": "x"}), None));
    assert!(untouched("login", &json!({"name": "no id at all"}), None));
}

#[test]
fn what_a_vault_item_becomes_is_decided_by_its_kind_and_its_key_kind() {
    let kind_of = |local: &Local| items::kem_kind_for(local);
    assert_eq!(kind_of(&vault_login()), Some("login"));
    assert_eq!(kind_of(&local("authenticator", ACCOUNT_ID, totp_account("A", "b"))), Some("otp"));
    assert_eq!(kind_of(&local("backup-codes", CODES_ID, backup_codes("A"))), Some("backup-codes"));
    assert_eq!(kind_of(&key_local("a", "a", "ssh", KeyType::Ed25519)), Some("ssh-key"));
    assert_eq!(kind_of(&key_local("a", "a", "ssh", KeyType::Rsa3072)), Some("ssh-key"));
    assert_eq!(kind_of(&key_local("a", "a", "ssh", KeyType::EcdsaP256)), Some("ssh-key"));
    assert_eq!(kind_of(&key_local("a", "a", "ssh", KeyType::MlDsa65)), Some("key"), "no SSH form for it");
    assert_eq!(kind_of(&key_local("a", "a", "signing", KeyType::Ed25519)), Some("key"));
    assert_eq!(kind_of(&key_local("a", "a", "exchange", KeyType::X25519)), Some("key"));
    assert_eq!(kind_of(&key_local("a", "a", "symmetric", KeyType::Aes256)), Some("note"));
    assert_eq!(kind_of(&cert_local("c", "c")), Some("certificate"));
    assert_eq!(kind_of(&file_local("f", "f", b"x")), Some("note"));
    assert_eq!(kind_of(&local("logo", "l", json!({}))), None);
    assert_eq!(kind_of(&local("anything-else", "l", json!({}))), None);
}
