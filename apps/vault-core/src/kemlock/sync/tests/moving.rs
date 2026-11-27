//! The move (`spec-protocol.md` 10): a vault whose items were synced as Bitwarden copies connects to the Kemlock API. Every item is written
//! under the id it has, the login both apps hold is adopted rather than written twice, what was written is read back and compared, and
//! nothing is trashed on the way.

use serde_json::json;

use super::common::*;
use crate::kemlock::conv::item_uuid;
use crate::kemlock::sync::fake::{Attack, FakeKemlock};
use crate::kemlock::sync::state::{Adoption, MoveRecord};
use crate::kemlock::sync::word;
use crate::sync::api::Problem;

const KEMLOCK_ENTRY: &str = "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257";
const SHARED_ID: &str = "vault-shared-login";

fn sid(fake: &FakeKemlock, vault_id: &str) -> String {
    item_uuid(&fake.account(EMAIL).owner(), vault_id).to_string()
}

/// The vault of a person who synced with Bitwarden's copies until now: a few of each kind, and a login the Kemlock app wrote, which the
/// vault took in through the Bitwarden API as its own item
fn moving_vault(fake: &mut FakeKemlock) -> Client {
    // The Kemlock app's own item, on the server as a `kem1` item under its entry id, and signed for
    let shared = json!({"id": KEMLOCK_ENTRY, "name": "GitHub", "username": "sam", "password": "hunter2-but-longer", "websites": ["github.com"], "pinned": true, "addedAt": 1_762_000_000_000i64});
    fake.plant_item(EMAIL, "login", &shared);
    fake.sign_manifest(EMAIL);
    let mut client = Client::connect(fake, EMAIL);
    every_kind(&mut client);
    client.put("password", SHARED_ID, with_id(password("GitHub", "sam", "hunter2-but-longer", "github.com"), SHARED_ID));
    let state = client.connection.kemlock.as_mut().unwrap();
    state.moved = Some(MoveRecord { started_ms: now_ms(), ..MoveRecord::default() });
    state.adopt = vec![Adoption { kind: "password".into(), id: SHARED_ID.into(), entry: KEMLOCK_ENTRY.into() }];
    client
}

#[test]
fn a_move_writes_every_item_under_its_id_adopts_the_login_both_hold_and_checks_what_it_wrote() {
    let mut fake = server();
    let mut client = moving_vault(&mut fake);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    // Nine items written, the same ids as the vault gives them, and the tenth, the shared login, not written at all
    assert_eq!(outcome.report.created_there, 9, "{:?}", outcome.report.refused);
    for vault_id in [PASSWORD_ID, ACCOUNT_ID, CODES_ID, SSH_ID, EXCHANGE_ID, AES_ID, CERT_ID, FILE_ID, FOLDER_ID] {
        let id = sid(&fake, vault_id);
        assert_eq!(fake.plain_of(EMAIL, &id).unwrap()["id"], vault_id);
    }
    // The shared login is Kemlock's own item and nothing else: no second one under the vault's id, and the app's keys are as they were
    assert!(fake.wire_of(EMAIL, &sid(&fake, SHARED_ID)).is_none());
    assert_eq!(fake.live_ids(EMAIL).len(), 10);
    let theirs = fake.plain_of(EMAIL, KEMLOCK_ENTRY).unwrap();
    assert_eq!((theirs["pinned"].as_bool(), fake.revision_of(EMAIL, KEMLOCK_ENTRY)), (Some(true), Some(1)), "an item that is the same is not written over");
    assert!(client.links.contains_key(KEMLOCK_ENTRY), "the vault's login is linked to Kemlock's item");
    assert_eq!(client.links[KEMLOCK_ENTRY].parts[0].id, SHARED_ID);
    // The record says what was sent, and that the read-back agreed; the adoption is used up
    let state = client.connection.kemlock.as_ref().unwrap();
    let record = state.moved.as_ref().unwrap();
    assert!(record.finished_ms.is_some(), "{record:?}");
    assert_eq!(record.sent.len(), 9);
    assert!(!record.sent.contains_key(KEMLOCK_ENTRY));
    assert!(state.adopt.is_empty());
    // Nothing was trashed anywhere, and the manifest lists everything, the adopted item too
    assert!(fake.account(EMAIL).items.values().all(|stored| !stored.wire.deleted));
    assert!(client.locals.values().all(|local| !crate::sync::map::deleted(local)));
    let manifest = fake.manifest(EMAIL).unwrap();
    assert_eq!((manifest.counter, manifest.entries.len()), (2, 10));
    // And it goes on as an ordinary connection
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!((outcome.report.sent, outcome.report.created_there), (0, 0));
    assert_eq!(client.links.len(), 10);
}

#[test]
fn what_was_written_that_does_not_read_back_as_it_was_sent_fails_the_check_and_is_sent_again() {
    let mut fake = server();
    let mut client = moving_vault(&mut fake);
    let tampered = sid(&fake, PASSWORD_ID);
    // The server hands back something else under the item's id and revision when the move reads everything again
    fake.attack(Attack::Tamper { item: tampered.clone() });
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::MOVE_CHECK)));
    let record = client.connection.kemlock.as_ref().unwrap().moved.clone().unwrap();
    assert!(record.finished_ms.is_none());
    assert_eq!(record.redone, 1);
    assert_eq!(record.sent.len(), 9, "what was sent is remembered, to be compared with");
    // Nothing is trashed because the check failed, and the adoption waits
    assert!(fake.account(EMAIL).items.values().all(|stored| !stored.wire.deleted));
    assert!(client.locals.values().all(|local| !crate::sync::map::deleted(local)));
    assert!(!client.connection.kemlock.as_ref().unwrap().adopt.is_empty());
    // The server is honest again: the next run finds all of it in place, pairs the vault's items with it, and finishes
    fake.clear_attacks();
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    let record = client.connection.kemlock.as_ref().unwrap().moved.clone().unwrap();
    assert!(record.finished_ms.is_some());
    assert_eq!(fake.live_ids(EMAIL).len(), 10, "no item was made twice");
    assert_eq!(client.links.len(), 10);
    assert!(client.connection.kemlock.as_ref().unwrap().adopt.is_empty());
}

#[test]
fn a_move_that_is_not_one_adopts_nothing_and_a_move_over_a_server_with_the_items_already_makes_none_twice() {
    // The same vault moving twice (a second device): what is there is paired by id and left as it is
    let mut fake = server();
    let mut first = moving_vault(&mut fake);
    assert_clean(&first.sync(&mut fake).problem);
    let revisions: Vec<(String, u64)> = fake.account(EMAIL).items.iter().map(|(id, stored)| (id.clone(), stored.wire.revision)).collect();
    let mut second = Client::connect(&mut fake, EMAIL);
    every_kind_from(&first, &mut second);
    let state = second.connection.kemlock.as_mut().unwrap();
    state.moved = Some(MoveRecord { started_ms: now_ms(), ..MoveRecord::default() });
    state.adopt = vec![Adoption { kind: "password".into(), id: SHARED_ID.into(), entry: KEMLOCK_ENTRY.into() }];
    second.put("password", SHARED_ID, with_id(password("GitHub", "sam", "hunter2-but-longer", "github.com"), SHARED_ID));
    let outcome = second.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.created_there, 0);
    let now: Vec<(String, u64)> = fake.account(EMAIL).items.iter().map(|(id, stored)| (id.clone(), stored.wire.revision)).collect();
    assert_eq!(now, revisions, "nothing was written over what was there");
    assert_eq!(fake.live_ids(EMAIL).len(), 10);
    assert!(second.connection.kemlock.as_ref().unwrap().moved.as_ref().unwrap().finished_ms.is_some());
}

fn every_kind_from(from: &Client, to: &mut Client) {
    for local in from.locals.values() {
        if local.id != SHARED_ID {
            to.add(local.clone());
        }
    }
}

#[test]
fn an_edit_made_elsewhere_after_a_failed_check_is_no_mismatch_and_what_differed_is_sent_again() {
    let mut fake = server();
    let mut client = moving_vault(&mut fake);
    let tampered = sid(&fake, PASSWORD_ID);
    fake.attack(Attack::Tamper { item: tampered.clone() });
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::MOVE_CHECK)));
    let record = client.connection.kemlock.as_ref().unwrap().moved.clone().unwrap();
    assert_eq!(record.redo, vec![tampered.clone()], "the check says which items it will send again");
    // The server is honest again, and the Kemlock app edits another moved item meanwhile
    fake.clear_attacks();
    let edited = sid(&fake, ACCOUNT_ID);
    let mut plain = fake.plain_of(EMAIL, &edited).unwrap();
    plain["label"] = json!("renamed over there");
    plain["updatedAt"] = json!(now_ms() + 60_000);
    fake.plant_item(EMAIL, "otp", &plain);
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    // The edit was taken, not held against the move; the item that differed was written again over the server's revision
    assert_eq!(client.value("authenticator", ACCOUNT_ID)["label"], "renamed over there");
    assert_eq!(fake.revision_of(EMAIL, &tampered), Some(2), "sent again");
    assert_eq!(fake.plain_of(EMAIL, &tampered).unwrap()["id"], PASSWORD_ID);
    let record = client.connection.kemlock.as_ref().unwrap().moved.clone().unwrap();
    assert!(record.finished_ms.is_some() && record.redo.is_empty(), "{record:?}");
    // An item the other device deleted for good does not hold the move either, and a later run goes on as usual
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.links.len(), 10);
}
