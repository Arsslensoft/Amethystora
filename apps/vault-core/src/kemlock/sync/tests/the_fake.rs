//! The fake server's own rules, called as a client would call them: the places a test of the back end leans on it being as strict as the
//! real one (revisions, preconditions, what a batch takes, the sync's cursor, the manifest's counter, the files' length and magic).

use serde_json::{Value, json};

use super::common::*;
use crate::kemlock::conv::{Uuid, b64_encode};
use crate::kemlock::item::Kem1Item;
use crate::kemlock::kma1;
use crate::kemlock::sync::api::{Answer, KemApi};
use crate::kemlock::sync::dpop::DpopKey;
use crate::kemlock::sync::fake::FakeKemlock;
use crate::kemlock::sync::word;
use crate::sync::api::Problem;

const A: &str = "00000000-0000-4000-8000-00000000000a";
const B: &str = "00000000-0000-4000-8000-00000000000b";

/// A signed-in session on `fake`, and the closure's use of it
fn with_api<T>(fake: &mut FakeKemlock, then: impl FnOnce(&mut KemApi<'_>) -> T) -> T {
    let key = DpopKey::generate();
    let done = connected(sign(fake, EMAIL, PASSWORD, &key, |_| {}));
    let address = fake.server();
    let mut api = KemApi::new(fake, &address, &key);
    api.access = Some(done.tokens.access.clone());
    then(&mut api)
}

fn wire(fake: &FakeKemlock, id: &str, kind: &str, revision: u64) -> Value {
    let account = fake.account(EMAIL);
    let keys = account.keys();
    let sealed = Kem1Item::seal(&keys.item_wrap, 1, Uuid::parse(id).unwrap(), account.owner(), kind, revision, json!({"id": id, "name": "x"}).to_string().as_bytes()).unwrap();
    serde_json::to_value(sealed.to_wire()).unwrap()
}

fn tomb(fake: &FakeKemlock, id: &str, kind: &str, revision: u64) -> Value {
    let account = fake.account(EMAIL);
    serde_json::to_value(Kem1Item::tombstone(Uuid::parse(id).unwrap(), account.owner(), kind, revision, 1).unwrap().to_wire()).unwrap()
}

fn put(api: &mut KemApi<'_>, id: &str, item: &Value, headers: &[(&'static str, String)]) -> Answer {
    api.authed_with("PUT", &format!("/items/{id}"), Some(serde_json::to_vec(item).unwrap()), "application/json", headers).unwrap_or_else(|_| panic!("no answer"))
}

fn batch(api: &mut KemApi<'_>, writes: Value) -> Answer {
    api.authed("POST", "/items:batch", Some(serde_json::to_vec(&json!({"writes": writes})).unwrap())).unwrap_or_else(|_| panic!("no answer"))
}

fn slug(answer: &Answer) -> (u16, String) {
    (answer.status, answer.slug.clone().unwrap_or_default())
}

#[test]
fn one_item_is_written_under_the_precondition_it_names() {
    let mut fake = server();
    let (first, second) = (wire(&fake, A, "login", 1), wire(&fake, A, "login", 2));
    let (third, wrong_kind) = (wire(&fake, A, "login", 3), wire(&fake, A, "note", 3));
    with_api(&mut fake, |api| {
        let created = put(api, A, &first, &[("If-None-Match", "*".into())]);
        assert_eq!(created.status, 201);
        assert_eq!(created.header("etag"), Some("\"1\""));
        // A new item over one that is there, and a revision that is not the stored one
        let again = put(api, A, &first, &[("If-None-Match", "*".into())]);
        assert_eq!(slug(&again), (409, "stale-revision".into()));
        assert_eq!((again.item_id().as_deref(), again.current_revision()), (Some(A), Some(1)));
        assert_eq!(slug(&put(api, A, &second, &[("If-Match", "5".into())])), (409, "stale-revision".into()));
        // Replaced, with the revision named as a number, quoted, or weak
        assert_eq!(put(api, A, &second, &[("If-Match", "1".into())]).status, 200);
        assert_eq!(put(api, A, &third, &[("If-Match", "W/\"2\"".into())]).status, 200);
        // Neither precondition, both, a revision that is not the next, a kind that changes, an id that is not the path's
        assert_eq!(slug(&put(api, A, &second, &[])), (428, "precondition-required".into()));
        assert_eq!(put(api, A, &second, &[("If-Match", "3".into()), ("If-None-Match", "*".into())]).status, 400);
        let skip = wire_with(&third, |item| item["revision"] = json!(9));
        assert_eq!(slug(&put(api, A, &skip, &[("If-Match", "3".into())])), (422, "invalid-revision".into()));
        assert_eq!(slug(&put(api, A, &wrong_kind, &[("If-Match", "3".into())])), (422, "invalid-revision".into()));
        assert_eq!(put(api, B, &third, &[("If-None-Match", "*".into())]).status, 400);
        // Members the server does not know are refused, and so is an item of another owner
        let extra = wire_with(&third, |item| item["extra"] = json!(1));
        assert_eq!(put(api, A, &extra, &[("If-Match", "3".into())]).status, 400);
        let foreign = wire_with(&third, |item| item["owner"] = json!(format!("user:{}", Uuid::random_v4())));
        assert_eq!(slug(&put(api, A, &foreign, &[("If-Match", "3".into())])), (403, "forbidden".into()));
    });
    assert_eq!(fake.revision_of(EMAIL, A), Some(3));
}

fn wire_with(item: &Value, change: impl FnOnce(&mut Value)) -> Value {
    let mut item = item.clone();
    change(&mut item);
    item
}

#[test]
fn a_batch_is_all_or_none_and_takes_only_what_the_real_one_takes() {
    let mut fake = server();
    let (a1, b1) = (wire(&fake, A, "login", 1), wire(&fake, B, "login", 1));
    let b_stale = wire(&fake, B, "login", 2);
    let (a_tomb, a_too_short) = (tomb(&fake, A, "login", 2), wire_with(&a1, |item| item["ciphertext"] = json!(b64_encode(&[1u8; 10]))));
    let bad_key = wire_with(&a1, |item| item["itemKey"] = json!(b64_encode(&[1u8; 59])));
    let big = wire_with(&a1, |item| item["ciphertext"] = json!(b64_encode(&vec![1u8; 1024 * 1024 + 1])));
    let tomb_with_text = wire_with(&tomb(&fake, A, "login", 1), |item| item["ciphertext"] = json!(b64_encode(&[1u8; 40])));
    let spaced = wire_with(&a1, |item| item["collectionId"] = json!("c"));
    let not_an_id = wire_with(&a1, |item| item["id"] = json!("not-a-uuid"));
    let bad_kind = wire_with(&a1, |item| item["kind"] = json!("Not A Kind"));
    with_api(&mut fake, |api| {
        // Empty, a write twice, a write of nothing, and more than five hundred
        assert_eq!(batch(api, json!([])).status, 400);
        assert_eq!(batch(api, json!([{"expectedRevision": null, "item": a1}, {"expectedRevision": null, "item": a1}])).status, 400);
        assert_eq!(batch(api, json!([{"expectedRevision": null, "item": a1, "surprise": 1}])).status, 400);
        let many: Vec<Value> = (0..501).map(|_| json!({"expectedRevision": null, "item": a1})).collect();
        assert_eq!(batch(api, json!(many)).status, 400);
        // What an item has to be
        for (why, item, status, word) in [
            ("a short ciphertext", &a_too_short, 400, "invalid-item"),
            ("an item key of the wrong length", &bad_key, 400, "invalid-item"),
            ("a ciphertext over a mebibyte", &big, 413, "item-too-large"),
            ("a tombstone with a ciphertext", &tomb_with_text, 400, "invalid-item"),
            ("an id that is not one", &not_an_id, 400, "invalid-item"),
            ("a kind that is not one", &bad_kind, 400, "invalid-item"),
        ] {
            assert_eq!(slug(&batch(api, json!([{"expectedRevision": null, "item": item}]))), (status, word.into()), "{why}");
        }
        assert_eq!(batch(api, json!([{"expectedRevision": null, "item": spaced}])).status, 400);
        // All or none: the second write is stale, so the first is not stored either
        let refused = batch(api, json!([{"expectedRevision": null, "item": a1}, {"expectedRevision": 4, "item": b_stale}]));
        assert_eq!(slug(&refused), (409, "stale-revision".into()));
        assert_eq!(refused.item_id().as_deref(), Some(B));
        // Taken: in the order written, as stored, a tombstone with the time of it
        let stored = batch(api, json!([{"expectedRevision": null, "item": a1}, {"expectedRevision": null, "item": b1}]));
        assert_eq!(stored.status, 200);
        let body = stored.json().ok().unwrap();
        assert_eq!((body["items"][0]["id"].as_str(), body["items"][1]["id"].as_str()), (Some(A), Some(B)));
        let gone = batch(api, json!([{"expectedRevision": 1, "item": a_tomb}])).json().ok().unwrap();
        assert!(gone["items"][0]["deletedAt"].as_str().is_some_and(|at| at.ends_with('Z')));
    });
    assert_eq!(fake.live_ids(EMAIL), vec![B.to_string()]);
    assert_eq!(fake.revision_of(EMAIL, A), Some(2));
}

#[test]
fn a_body_over_two_mebibytes_is_refused_before_it_is_read() {
    let mut fake = server();
    with_api(&mut fake, |api| {
        let big = vec![b' '; 2 * 1024 * 1024 + 1];
        let answer = api.authed("POST", "/items:batch", Some(big)).ok().unwrap();
        assert_eq!(slug(&answer), (413, "payload-too-large".into()));
    });
}

#[test]
fn the_sync_pages_by_a_cursor_answers_304_and_forgets_what_it_cannot_serve() {
    let mut fake = server();
    for n in 0..5 {
        fake.plant_item(EMAIL, "login", &json!({"id": format!("00000000-0000-4000-8000-{n:012}"), "name": "x"}));
    }
    with_api(&mut fake, |api| {
        let first = api.authed("GET", "/sync?limit=2", None).ok().unwrap();
        let body = first.json().ok().unwrap();
        assert_eq!((body["items"].as_array().unwrap().len(), body["more"].as_bool()), (2, Some(true)));
        assert!(first.header("etag").is_none(), "the tag only comes with the last page");
        let cursor = body["cursor"].as_str().unwrap().to_string();
        let rest = api.authed("GET", &format!("/sync?since={cursor}&limit=500"), None).ok().unwrap();
        let rest_body = rest.json().ok().unwrap();
        assert_eq!((rest_body["items"].as_array().unwrap().len(), rest_body["more"].as_bool()), (3, Some(false)));
        let last = rest_body["cursor"].as_str().unwrap().to_string();
        assert_eq!(rest.header("etag"), Some(format!("\"{last}\"").as_str()));
        // Nothing since the last cursor
        let nothing = api.authed("GET", &format!("/sync?since={last}"), None).ok().unwrap();
        assert_eq!((nothing.status, nothing.body.len()), (304, 0));
        // The same by a POST, as the long cursor of an account in spaces would be asked
        let posted = api.authed("POST", "/sync", Some(serde_json::to_vec(&json!({"since": cursor})).unwrap())).ok().unwrap();
        assert_eq!(posted.json().ok().unwrap()["items"].as_array().unwrap().len(), 3);
        // A cursor nobody made, and one that is not text at all
        assert_eq!(slug(&api.authed("GET", "/sync?since=AAAA", None).ok().unwrap()), (410, "full-sync-required".into()));
        assert_eq!(slug(&api.authed("GET", "/sync?since=%00%01", None).ok().unwrap()).0, 410);
    });
}

#[test]
fn the_manifest_is_stored_only_if_it_verifies_for_its_owner_and_the_counter_rises() {
    let mut fake = server();
    fake.plant_item(EMAIL, "login", &json!({"id": A, "name": "x"}));
    let keys = fake.account(EMAIL).keys();
    let owner = fake.account(EMAIL).owner();
    let entries = || vec![crate::kemlock::manifest::Entry::tombstone(Uuid::parse(A).unwrap(), 1)];
    let signed = |counter: u64| {
        let manifest = crate::kemlock::manifest::Manifest::new(owner, counter, entries()).unwrap();
        (manifest.to_bytes(), manifest.sign(&keys.sig_private).unwrap())
    };
    let owner_path = owner.to_string();
    with_api(&mut fake, |api| {
        assert_eq!(slug(&api.authed("GET", &format!("/manifests/{owner_path}"), None).ok().unwrap()), (404, "not-found".into()));
        let (bytes, signature) = signed(1);
        let mut broken = signature.clone();
        broken[100] ^= 1;
        assert!(matches!(api.put_manifest(&owner_path, &bytes, &broken), Err(crate::sync::api::Expired::Problem(_))), "a signature that does not verify");
        assert!(matches!(api.put_manifest(&owner_path, &bytes, &signature[..100]), Err(crate::sync::api::Expired::Problem(_))), "a signature of the wrong length");
        assert!(api.put_manifest(&owner_path, &bytes, &signature).ok().unwrap().is_ok());
        // The same counter again, and a lower one: another device signed first
        let (again, again_signature) = signed(1);
        assert_eq!(api.put_manifest(&owner_path, &again, &again_signature).ok().unwrap(), Err(Some(1)));
        // Another owner's path
        let other = format!("user:{}", Uuid::random_v4());
        assert!(matches!(api.put_manifest(&other, &again, &again_signature), Err(crate::sync::api::Expired::Problem(Problem::Kemlock(word::ACCOUNT_REFUSED)))));
        let (two, two_signature) = signed(2);
        assert!(api.put_manifest(&owner_path, &two, &two_signature).ok().unwrap().is_ok());
        let stored = api.manifest(&owner_path).ok().unwrap().unwrap();
        assert_eq!((stored["counter"].as_u64(), stored["signer"].as_str().is_some()), (Some(2), true));
    });
}

#[test]
fn a_file_is_announced_sent_whole_in_its_own_format_and_read_back() {
    let mut fake = server();
    let key = crate::kemlock::Key::random();
    let sealed = kma1::encrypt(&key, b"some bytes", 1 << 20).unwrap();
    with_api(&mut fake, |api| {
        // Too large for the server, and the account's storage off
        let too_big = api.authed("POST", &format!("/items/{A}/files"), Some(serde_json::to_vec(&json!({"size": 200 * 1024 * 1024u64})).unwrap())).ok().unwrap();
        assert_eq!((slug(&too_big), too_big.max_size()), ((413, "file-too-large".into()), Some(100 * 1024 * 1024)));
        let slot = api.file_start(A, sealed.len() as u64).ok().unwrap().ok().unwrap();
        assert!(!slot.presigned);
        // Not what was announced, not KMA1, whole, and a second time
        let mut short = sealed.clone();
        short.pop();
        assert_eq!(api.file_upload(A, &slot.file, short).ok().unwrap(), Err(crate::kemlock::sync::api::FileRefusal::Refused));
        assert_eq!(api.file_upload(A, &slot.file, vec![0u8; sealed.len()]).ok().unwrap(), Err(crate::kemlock::sync::api::FileRefusal::Refused));
        assert!(api.file_upload(A, &slot.file, sealed.clone()).ok().unwrap().is_ok());
        assert_eq!(api.file_upload(A, &slot.file, sealed.clone()).ok().unwrap(), Err(crate::kemlock::sync::api::FileRefusal::Refused), "a second time");
        // Read back: the same bytes, and nothing for a file of another item or one nobody made
        assert_eq!(api.file_download(A, &slot.file, 1 << 20).ok().unwrap().as_deref().map(|bytes| bytes.as_slice()), Some(&sealed[..]));
        assert!(api.file_download(B, &slot.file, 1 << 20).ok().unwrap().is_none());
        assert!(api.file_download(A, &Uuid::random_v4().to_string(), 1 << 20).ok().unwrap().is_none());
        // More than the note's size is not the file
        assert!(api.file_download(A, &slot.file, 5).ok().unwrap().is_none());
        // Deleted, and again, which is not an error
        assert!(api.file_delete(A, &slot.file).is_ok());
        assert!(api.file_delete(A, &slot.file).is_ok());
        assert!(api.file_download(A, &slot.file, 1 << 20).ok().unwrap().is_none());
    });
}

#[test]
fn the_devices_are_listed_and_only_the_accounts_own_can_be_signed_out() {
    let mut fake = server();
    with_api(&mut fake, |api| {
        let devices = api.devices().ok().unwrap();
        assert_eq!(devices["devices"].as_array().unwrap().len(), 1);
        for field in ["id", "name", "kind", "createdAt", "lastSeenAt", "current", "trusted"] {
            assert!(devices["devices"][0].get(field).is_some(), "{field}");
        }
        let answer = api.authed("POST", "/devices/sign-out", Some(serde_json::to_vec(&json!({"deviceId": Uuid::random_v4().to_string()})).unwrap())).ok().unwrap();
        assert_eq!(slug(&answer), (404, "not-found".into()));
    });
}
