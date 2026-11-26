//! What a hostile or broken server can do, and that the client is not fooled by any of it: each with the exact problem it stops with, or
//! the item it leaves alone and never writes, deletes or takes.

use serde_json::json;

use super::common::*;
use crate::kemlock::conv::{Uuid, b64_decode, item_uuid};
use crate::kemlock::item::Kem1Item;
use crate::kemlock::manifest::Manifest;
use crate::kemlock::sig1::Sig1PrivateKey;
use crate::kemlock::sync::fake::{Attack, FakeKemlock, StoredManifest};
use crate::kemlock::sync::word;
use crate::sync::api::Problem;

fn sid(fake: &FakeKemlock, vault_id: &str) -> String {
    item_uuid(&fake.account(EMAIL).owner(), vault_id).to_string()
}

fn login_plain(id: &str, name: &str) -> serde_json::Value {
    json!({"id": id, "name": name, "username": "u", "password": "p", "websites": [format!("{}.example", name.to_lowercase())], "addedAt": 1})
}

/// A server with one login on it, signed for, and a client that has synced it
fn with_one() -> (FakeKemlock, Client, String) {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    assert_clean(&client.sync(&mut fake).problem);
    let id = sid(&fake, PASSWORD_ID);
    (fake, client, id)
}

// --- The manifest ------------------------------------------------------------------------------------------------------------------

#[test]
fn a_manifest_with_a_lower_counter_than_one_already_seen_stops_the_run() {
    let (mut fake, mut client, _) = with_one();
    // The app writes another login and signs: counter 2, which this client verifies and keeps
    fake.plant_item(EMAIL, "login", &login_plain("00000000-0000-4000-8000-000000000001", "Other"));
    assert_eq!(fake.sign_manifest(EMAIL), 2);
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.connection.kemlock.as_ref().unwrap().manifest_counter, 2);
    // Served the first one again: older than what it has seen
    fake.attack(Attack::ManifestRolledBack);
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::MANIFEST_ROLLED_BACK)));
    // Or not served at all, which is a manifest the server had and has not
    fake.clear_attacks();
    fake.attack(Attack::ManifestMissing);
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::MANIFEST_ROLLED_BACK)));
    // Nothing was written meanwhile, and the vault is as it was
    assert_eq!(fake.account(EMAIL).manifests.len(), 2);
    fake.clear_attacks();
    assert_clean(&client.sync(&mut fake).problem);
}

#[test]
fn a_manifest_that_does_not_verify_is_never_believed() {
    let (mut fake, mut client, _) = with_one();
    fake.attack(Attack::ManifestBadSignature);
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::MANIFEST_INVALID)));
    fake.clear_attacks();
    // One signed with another key, whatever it lists
    let owner = fake.account(EMAIL).owner();
    let manifest = Manifest::new(owner, 99, Vec::new()).unwrap();
    let (bytes, signature) = (manifest.to_bytes(), manifest.sign(&Sig1PrivateKey::generate()).unwrap());
    fake.account_mut(EMAIL).manifests.push(StoredManifest { counter: 99, bytes, signature, stored_at: "2026-11-25T00:00:00Z".into() });
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::MANIFEST_INVALID)));
    // And one that is another owner's, signed by the right key
    let keys = fake.account(EMAIL).keys();
    let mut other = fake.account(EMAIL).owner();
    other.id = Uuid::random_v4();
    let manifest = Manifest::new(other, 100, Vec::new()).unwrap();
    let (bytes, signature) = (manifest.to_bytes(), manifest.sign(&keys.sig_private).unwrap());
    fake.account_mut(EMAIL).manifests.push(StoredManifest { counter: 100, bytes, signature, stored_at: "2026-11-25T00:00:00Z".into() });
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::MANIFEST_INVALID)));
}

// --- Items ---------------------------------------------------------------------------------------------------------------------------

#[test]
fn an_item_whose_plaintext_id_is_not_its_own_is_left_alone_and_never_written_or_deleted() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let victim = "00000000-0000-4000-8000-0000000000f0";
    client.put("password", victim, with_id(password("Victim", "sam", "the-real-one", "victim.example"), victim));
    // A server that files an item under another id with the victim's id inside it, to be taken in the victim's place
    let forged = "00000000-0000-4000-8000-0000000000c1";
    fake.plant_item_as(EMAIL, forged, "login", &json!({"id": victim, "name": "Victim", "username": "sam", "password": "the-attackers", "websites": ["evil.example"], "addedAt": 9}));
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(outcome.report.left_alone >= 1);
    assert_eq!(client.value("password", victim)["password"], "the-real-one", "the vault's item is not replaced");
    assert_eq!(client.of_kind("password").len(), 1);
    // The forged one is as the server had it, and the victim went to the server under its own id
    assert_eq!(fake.revision_of(EMAIL, forged), Some(1));
    assert!(!fake.wire_of(EMAIL, forged).unwrap().deleted);
    assert_eq!(fake.plain_of(EMAIL, victim).unwrap()["password"], "the-real-one");
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(fake.revision_of(EMAIL, forged), Some(1));
    // It is in the manifest the client signs, as it is
    assert!(fake.manifest(EMAIL).unwrap().entries.iter().any(|entry| entry.item_id.to_string() == forged));
}

#[test]
fn an_item_with_a_space_in_it_or_a_kind_that_is_unknown_is_not_the_vaults() {
    let mut fake = server();
    let mut spaced = login_plain("00000000-0000-4000-8000-0000000000d1", "Spaced");
    spaced["spaceId"] = json!("a-space");
    fake.plant_item(EMAIL, "login", &spaced);
    fake.plant_item(EMAIL, "pgp-key", &json!({"id": "00000000-0000-4000-8000-0000000000d2", "name": "PGP"}));
    fake.plant_item(EMAIL, "kind-from-the-future", &json!({"id": "00000000-0000-4000-8000-0000000000d3"}));
    fake.sign_manifest(EMAIL);
    let mut client = Client::connect(&mut fake, EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(client.locals.is_empty());
    assert_eq!(outcome.report.left_alone, 3);
    assert!(fake.account(EMAIL).items.values().all(|stored| stored.wire.revision == 1 && !stored.wire.deleted));
}

#[test]
fn an_item_served_under_another_kind_stays_opaque() {
    let (mut fake, _, id) = with_one();
    let mut fresh = Client::connect(&mut fake, EMAIL);
    // The kind is inside what is authenticated: relabelled, the item does not open, and is neither taken nor written over
    fake.attack(Attack::Relabel { item: id.clone(), kind: "note".into() });
    let outcome = fresh.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(fresh.locals.is_empty());
    assert_eq!(outcome.report.left_alone, 1);
    fresh.put("backup-codes", CODES_ID, with_id(backup_codes("GitHub"), CODES_ID));
    fake.clear_attacks();
    assert_clean(&fresh.sync(&mut fake).problem);
    assert_eq!(fake.revision_of(EMAIL, &id), Some(1));
    assert!(!fake.wire_of(EMAIL, &id).unwrap().deleted);
    assert_eq!(fake.wire_of(EMAIL, &id).unwrap().kind, "login");
}

#[test]
fn a_tombstone_that_still_carries_its_ciphertext_stops_the_run() {
    let (mut fake, _, id) = with_one();
    let mut fresh = Client::connect(&mut fake, EMAIL);
    fake.attack(Attack::TombstoneWithCiphertext { item: id });
    let outcome = fresh.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::BAD_ANSWER)));
    assert!(fresh.locals.is_empty() && fresh.links.is_empty());
}

#[test]
fn an_item_served_at_a_lower_revision_than_was_seen_or_listed_stops_the_run() {
    let (mut fake, mut client, id) = with_one();
    // The app changes it (revision 2) and signs
    let mut plain = fake.plain_of(EMAIL, &id).unwrap();
    plain["name"] = json!("Changed elsewhere");
    fake.plant_item_as(EMAIL, &id, "login", &plain);
    fake.sign_manifest(EMAIL);
    assert_clean(&client.sync(&mut fake).problem);
    // This client saw revision 2: read from nothing again, the server gives 1 back
    fake.attack(Attack::RollBack { item: id.clone() });
    assert_eq!(client.accept(&mut fake).problem, Some(Problem::Kemlock(word::ITEM_ROLLED_BACK)));
    // A device that never saw it has the manifest, which lists revision 2
    let mut fresh = Client::connect(&mut fake, EMAIL);
    assert_eq!(fresh.sync(&mut fake).problem, Some(Problem::Kemlock(word::ITEM_ROLLED_BACK)));
    assert!(fresh.locals.is_empty());
    // The same revision with other bytes is a server that changed an item without saying so
    fake.clear_attacks();
    let keys = fake.account(EMAIL).keys();
    let other = Kem1Item::seal(&keys.item_wrap, 1, Uuid::parse(&id).unwrap(), fake.account(EMAIL).owner(), "login", 2, login_plain(PASSWORD_ID, "Swapped").to_string().as_bytes()).unwrap();
    fake.plant_wire(EMAIL, other.to_wire());
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::ITEM_ROLLED_BACK)));
}

#[test]
fn an_item_the_manifest_lists_that_the_server_does_not_serve_stops_the_run() {
    let (mut fake, _, id) = with_one();
    let mut fresh = Client::connect(&mut fake, EMAIL);
    fake.attack(Attack::Hide { item: id });
    assert_eq!(fresh.sync(&mut fake).problem, Some(Problem::Kemlock(word::ITEM_MISSING)));
    assert!(fresh.locals.is_empty());
}

#[test]
fn an_item_deleted_and_back_with_no_manifest_listing_it_is_a_server_putting_an_old_item_back() {
    let (mut fake, mut client, id) = with_one();
    fake.plant_tombstone(EMAIL, &id);
    fake.sign_manifest(EMAIL);
    assert_clean(&client.sync(&mut fake).problem);
    assert!(crate::sync::map::deleted(&client.locals[&("password".to_string(), PASSWORD_ID.to_string())]));
    // It comes back live and no manifest lists that
    let mut plain = login_plain(PASSWORD_ID, "Back");
    plain["password"] = json!("p-back");
    fake.plant_item_as(EMAIL, &id, "login", &plain);
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::ITEM_RESURRECTED)));
    // A manifest that lists the later live revision settles it
    fake.sign_manifest(EMAIL);
    assert_clean(&client.sync(&mut fake).problem);
}

#[test]
fn a_server_that_says_it_holds_two_versions_of_an_item_is_left_for_the_kemlock_app() {
    let (mut fake, mut client, _) = with_one();
    fake.plant_item(EMAIL, "login", &login_plain("00000000-0000-4000-8000-000000000001", "Other"));
    fake.sign_manifest(EMAIL);
    fake.attack(Attack::Siblings);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.refused_total, 1);
    assert_eq!(outcome.report.refused[0]["why"], word::SIBLINGS);
}

#[test]
fn a_file_served_with_a_byte_changed_is_never_taken() {
    let mut fake = server();
    let mut a = Client::connect(&mut fake, EMAIL);
    a.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
    assert_clean(&a.sync(&mut fake).problem);
    let mut b = Client::connect(&mut fake, EMAIL);
    b.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
    assert_clean(&b.sync(&mut fake).problem);
    let local = a.locals.get_mut(&("protected".to_string(), FILE_ID.to_string())).unwrap();
    local.value["files"][0]["data"] = json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"changed"));
    assert_clean(&a.sync(&mut fake).problem);
    fake.attack(Attack::FileTampered);
    let outcome = b.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.received, 0);
    assert_eq!(b.value("protected", FILE_ID)["files"][0]["data"], base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"a file of the person's"), "the vault's file is as it was");
    // The honest file is taken at the next run
    fake.clear_attacks();
    assert_clean(&b.sync(&mut fake).problem);
    assert_eq!(b.value("protected", FILE_ID)["files"][0]["data"], base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"changed"));
}

// --- Sign-in and the nonce, as a run meets them --------------------------------------------------------------------------------------

#[test]
fn a_run_that_cannot_get_its_proofs_accepted_says_so() {
    let (mut fake, mut client, _) = with_one();
    client.access = None;
    fake.attack(Attack::StaleNonce(2));
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::DPOP_NONCE)));
    fake.clear_attacks();
    fake.attack(Attack::NonceNeverAccepted);
    client.access = None;
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::DPOP_NONCE)));
    // The Date of the answers is right, the address is not what the proofs are checked against: not read as a login gone
    fake.clear_attacks();
    fake.domain = "https://somewhere-else.example.test".into();
    client.access = None;
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::DPOP_REFUSED)));
}

#[test]
fn a_server_that_serves_an_item_it_cannot_have_written_does_not_stop_a_run_that_has_nothing_to_do_with_it() {
    // A run of an account holding one item a stranger planted under the person's own id: the vault's copy of the id is not touched
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let stranger = "00000000-0000-4000-8000-0000000000e1";
    fake.plant_item_as(EMAIL, stranger, "login", &json!("not an object at all"));
    fake.sign_manifest(EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.left_alone, 1);
    assert_eq!(fake.revision_of(EMAIL, stranger), Some(1));
    assert!(b64_decode(fake.wire_of(EMAIL, stranger).unwrap().ciphertext.as_deref().unwrap()).is_ok());
}
