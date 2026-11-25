//! The run (`spec-protocol.md` 5, 6, 7): what a first run writes, revisions, two devices, conflicts, tombstones, the signed manifest,
//! files, the removal guard, and the items no manifest lists.

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::common::*;
use crate::kemlock::conv::{Owner, item_uuid};
use crate::kemlock::manifest::Manifest;
use crate::kemlock::sync::fake::{Attack, FakeKemlock};
use crate::kemlock::sync::word;
use crate::kemlock::kma1;
use crate::sync::api::Problem;

fn sid(fake: &FakeKemlock, vault_id: &str) -> String {
    item_uuid(&fake.account(EMAIL).owner(), vault_id).to_string()
}

fn edit(client: &mut Client, kind: &str, id: &str, change: impl FnOnce(&mut Value)) {
    let local = client.locals.get_mut(&(kind.to_string(), id.to_string())).expect("an item to edit");
    change(&mut local.value);
    local.name = crate::sync::map::name_of(kind, &local.value);
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn everything_sent(fake: &FakeKemlock) -> String {
    fake.seen.iter().map(|seen| format!("{} {} {}\n", seen.method, seen.url, seen.body)).collect()
}

fn owner_of(fake: &FakeKemlock) -> Owner {
    fake.account(EMAIL).owner()
}

/// The manifest the server holds, verified under the account's own key
fn verified_manifest(fake: &FakeKemlock) -> Manifest {
    let account = fake.account(EMAIL);
    let stored = account.manifests.last().expect("a manifest");
    Manifest::parse_signed(&stored.bytes, &stored.signature, &account.keys().sig_public).expect("it verifies")
}

// --- Writing ---------------------------------------------------------------------------------------------------------------------

#[test]
fn a_first_run_writes_every_kind_as_its_kemlock_item_and_signs_the_manifest() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.created_there, 9, "{:?}", outcome.report.refused);
    let expected = [
        (PASSWORD_ID, "login"),
        (ACCOUNT_ID, "otp"),
        (CODES_ID, "backup-codes"),
        (SSH_ID, "ssh-key"),
        (EXCHANGE_ID, "key"),
        (AES_ID, "note"),
        (CERT_ID, "certificate"),
        (FILE_ID, "note"),
        (FOLDER_ID, "note"),
    ];
    for (vault_id, kind) in expected {
        let id = sid(&fake, vault_id);
        let wire = fake.wire_of(EMAIL, &id).unwrap_or_else(|| panic!("{vault_id} was not written"));
        assert_eq!((wire.kind.as_str(), wire.format.as_str(), wire.revision, wire.key_version, wire.deleted), (kind, "kem1", 1, 1, false), "{vault_id}");
        let plain = fake.plain_of(EMAIL, &id).expect("it opens under the account's keys");
        assert_eq!(plain["id"], vault_id, "the vault's own id is inside, which is how another client pairs its copy");
    }
    // The ids that are UUIDs are kept, the others are the legacy mapping of them
    assert!(fake.wire_of(EMAIL, PASSWORD_ID).is_some());
    assert!(fake.wire_of(EMAIL, SSH_ID).is_none());
    // The manifest: one entry for each, sorted, at revision 1, the hash of the ciphertext, signed by the account
    let manifest = verified_manifest(&fake);
    assert_eq!((manifest.counter, manifest.entries.len(), manifest.owner), (1, 9, owner_of(&fake)));
    assert!(manifest.entries.windows(2).all(|pair| pair[0].item_id < pair[1].item_id));
    for entry in &manifest.entries {
        let wire = fake.wire_of(EMAIL, &entry.item_id.to_string()).unwrap();
        assert_eq!((entry.revision, entry.deleted), (1, false));
        assert_eq!(entry.ciphertext_hash, sha(&crate::kemlock::conv::b64_decode(wire.ciphertext.as_deref().unwrap()).unwrap()));
    }
    // One batch, one manifest, and nothing the person keeps secret in the clear
    assert_eq!(fake.requests_to("items:batch"), 1);
    assert_eq!(fake.requests_to("/manifests/"), 2, "one read, one write");
    let sent = everything_sent(&fake);
    for secret in ["cobalt-otter-41", "JBSWY3DPEHPK3PXP", "1111-2222", "a file of the person's", PASSWORD] {
        assert!(!sent.contains(secret), "{secret} went out in the clear");
    }
    // The connection keeps where it stands
    let state = client.connection.kemlock.as_ref().unwrap();
    assert!(state.cursor.is_some());
    assert_eq!(state.manifest_counter, 1);
    assert_eq!(client.links.len(), 9);
    assert!(client.links.values().all(|link| link.parts.len() == 1 && !link.deleted));
}

#[test]
fn a_second_run_with_nothing_changed_writes_and_signs_nothing() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    let (batches, manifests) = (fake.requests_to("items:batch"), fake.account(EMAIL).manifests.len());
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!((outcome.report.sent, outcome.report.received, outcome.report.created_there), (0, 0, 0));
    assert_eq!(fake.requests_to("items:batch"), batches);
    assert_eq!(fake.account(EMAIL).manifests.len(), manifests);
    // The cursor held, so what is asked is answered with a 304
    let last = fake.seen.iter().rev().find(|seen| seen.path().ends_with("/sync")).unwrap();
    assert!(last.url.contains("since="));
}

#[test]
fn an_edit_is_the_next_revision_over_the_one_the_server_holds() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    edit(&mut client, "password", PASSWORD_ID, |value| {
        value["password"] = json!("cobalt-otter-42");
        value["updatedAt"] = json!(1_765_000_000_000i64);
    });
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.sent, 1);
    let id = sid(&fake, PASSWORD_ID);
    assert_eq!(fake.revision_of(EMAIL, &id), Some(2));
    assert_eq!(fake.plain_of(EMAIL, &id).unwrap()["password"], "cobalt-otter-42");
    // The write named the revision it replaced, and no other item moved
    let batch = fake.seen.iter().rev().find(|seen| seen.path().ends_with("items:batch")).unwrap();
    assert!(batch.body.contains("\"expectedRevision\":1"), "{}", batch.body);
    assert_eq!(fake.live_ids(EMAIL).len(), 9);
    assert!(fake.account(EMAIL).items.values().filter(|stored| stored.wire.revision == 2).count() == 1);
    // The manifest went up, and lists the new revision
    let manifest = verified_manifest(&fake);
    assert_eq!(manifest.counter, 2);
    assert!(manifest.entries.iter().any(|entry| entry.revision == 2));
}

#[test]
fn what_the_server_keeps_that_this_client_does_not_know_survives_an_edit() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("GitHub", "sam", "p1", "github.com"), PASSWORD_ID));
    assert_clean(&client.sync(&mut fake).problem);
    // The Kemlock app edits it: a pin, a link to a code, a key of a later version
    let id = sid(&fake, PASSWORD_ID);
    let mut plain = fake.plain_of(EMAIL, &id).unwrap();
    plain["pinned"] = json!(true);
    plain["accountId"] = json!(ACCOUNT_ID);
    plain["x-future"] = json!({"a": [1, 2]});
    fake.plant_item_as(EMAIL, &id, "login", &plain);
    fake.sign_manifest(EMAIL);
    // The vault takes the new revision (writing nothing), then edits: the write starts from what the server had
    assert_clean(&client.sync(&mut fake).problem);
    edit(&mut client, "password", PASSWORD_ID, |value| value["username"] = json!("sam2"));
    assert_clean(&client.sync(&mut fake).problem);
    let after = fake.plain_of(EMAIL, &id).unwrap();
    assert_eq!(fake.revision_of(EMAIL, &id), Some(3));
    assert_eq!((after["username"].as_str(), after["pinned"].as_bool(), after["x-future"].clone()), (Some("sam2"), Some(true), json!({"a": [1, 2]})));
    assert_eq!(after["accountId"], ACCOUNT_ID);
}

#[test]
fn a_write_another_device_beat_it_to_is_read_again_and_tried_again_and_three_times_is_enough() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("A", "u", "p", "a.example"), PASSWORD_ID));
    // The server says another device wrote first, once: the run reads again and goes on
    fake.attack(Attack::StaleOnce);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(fake.requests_to("items:batch"), 2);
    assert_eq!(fake.live_ids(EMAIL).len(), 1);
    // Three times is all a run makes
    edit(&mut client, "password", PASSWORD_ID, |value| value["password"] = json!("p2"));
    for _ in 0..3 {
        fake.attack(Attack::StaleOnce);
    }
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::BAD_ANSWER)));
    assert_eq!(fake.revision_of(EMAIL, &sid(&fake, PASSWORD_ID)), Some(1), "nothing was half written");
    fake.clear_attacks();
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(fake.revision_of(EMAIL, &sid(&fake, PASSWORD_ID)), Some(2));
}

#[test]
fn a_cursor_the_server_forgot_is_read_again_from_nothing_once() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    fake.forget_cursors(EMAIL);
    let before = fake.seen.len();
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    let reads: Vec<&str> = fake.seen[before..].iter().filter(|seen| seen.path().ends_with("/sync")).map(|seen| seen.url.as_str()).collect();
    assert_eq!(reads.iter().filter(|url| !url.contains("since=")).count(), 1, "the 410, then everything from nothing, once: {reads:?}");
    assert!(reads.iter().any(|url| url.contains("since=")));
    assert_eq!(client.links.len(), 9);
    // The cursor is stored again from the second read
    assert!(client.connection.kemlock.as_ref().unwrap().cursor.is_some());
    assert_clean(&client.sync(&mut fake).problem);
}

#[test]
fn a_sync_longer_than_a_page_is_read_page_by_page() {
    let mut fake = server();
    for n in 0..120 {
        let id = format!("00000000-0000-4000-8000-{n:012}");
        fake.plant_item(EMAIL, "login", &json!({"id": id, "name": format!("Site {n}"), "username": "u", "password": "p", "websites": [format!("site{n}.example")], "addedAt": 1}));
    }
    fake.sign_manifest(EMAIL);
    let mut client = Client::connect(&mut fake, EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(client.of_kind("password").len(), 120);
    assert_eq!(fake.requests_to("/sync"), 2, "a hundred and then the rest");
    assert_eq!(outcome.report.created_here, 120);
}

// --- Two devices -------------------------------------------------------------------------------------------------------------------

#[test]
fn a_second_device_reads_back_every_kind_a_first_wrote_and_what_it_edits_comes_back() {
    let mut fake = server();
    let mut a = Client::connect(&mut fake, EMAIL);
    every_kind(&mut a);
    assert_clean(&a.sync(&mut fake).problem);
    // B holds the certificate and the files already (they are only ever paired, never made from the server's), and nothing else
    let mut b = Client::connect(&mut fake, EMAIL);
    b.add(cert_local(CERT_ID, "Document signing"));
    b.add(a.locals[&("protected".to_string(), FILE_ID.to_string())].clone());
    b.add(a.locals[&("protected".to_string(), FOLDER_ID.to_string())].clone());
    b.add(a.locals[&("certificate".to_string(), CERT_ID.to_string())].clone());
    let outcome = b.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.sent, 0, "{:?}", outcome.report.refused);
    for (kind, id) in [("password", PASSWORD_ID), ("authenticator", ACCOUNT_ID), ("backup-codes", CODES_ID), ("key", SSH_ID), ("key", EXCHANGE_ID), ("key", AES_ID)] {
        assert!(b.has(kind, id), "{kind} {id} was not read");
    }
    assert_eq!(b.value("password", PASSWORD_ID), a.value("password", PASSWORD_ID));
    assert_eq!(b.value("authenticator", ACCOUNT_ID)["secret"], "JBSWY3DPEHPK3PXP");
    for id in [SSH_ID, EXCHANGE_ID, AES_ID] {
        assert_eq!(b.value("key", id)["key"], a.value("key", id)["key"], "{id}");
        assert_eq!(b.value("key", id)["type"], a.value("key", id)["type"]);
    }
    // The pairing cost nothing: nothing written, no manifest signed over the first
    assert_eq!(verified_manifest(&fake).counter, 1);
    // B edits the password; A takes it
    edit(&mut b, "password", PASSWORD_ID, |value| {
        value["password"] = json!("cobalt-otter-99");
        value["updatedAt"] = json!(1_765_000_000_000i64);
    });
    assert_clean(&b.sync(&mut fake).problem);
    let outcome = a.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.received, 1);
    assert_eq!(a.value("password", PASSWORD_ID)["password"], "cobalt-otter-99");
    assert_eq!(verified_manifest(&fake).counter, 2);
}

#[test]
fn changed_on_both_sides_the_later_change_wins_and_the_password_it_replaced_is_kept() {
    let mut fake = server();
    let mut a = Client::connect(&mut fake, EMAIL);
    a.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    edit(&mut a, "password", PASSWORD_ID, |value| value["updatedAt"] = json!(2000));
    assert_clean(&a.sync(&mut fake).problem);
    let mut b = Client::connect(&mut fake, EMAIL);
    assert_clean(&b.sync(&mut fake).problem);
    edit(&mut a, "password", PASSWORD_ID, |value| {
        value["password"] = json!("pA");
        value["updatedAt"] = json!(3000);
    });
    edit(&mut b, "password", PASSWORD_ID, |value| {
        value["password"] = json!("pB");
        value["updatedAt"] = json!(4000);
    });
    assert_clean(&a.sync(&mut fake).problem);
    let outcome = b.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.conflicts, 1);
    let id = sid(&fake, PASSWORD_ID);
    let on_server = fake.plain_of(EMAIL, &id).unwrap();
    assert_eq!(fake.revision_of(EMAIL, &id), Some(3));
    assert_eq!(on_server["password"], "pB", "the later change wins as a whole");
    assert!(on_server["previousPasswords"].as_array().unwrap().iter().any(|old| old["password"] == "pA"), "the password it replaced is kept: {on_server}");
    // B has it too, and A takes it
    assert!(b.value("password", PASSWORD_ID)["history"].as_array().unwrap().iter().any(|old| old["password"] == "pA"));
    assert_clean(&a.sync(&mut fake).problem);
    assert_eq!(a.value("password", PASSWORD_ID)["password"], "pB");
    assert!(a.value("password", PASSWORD_ID)["history"].as_array().unwrap().iter().any(|old| old["password"] == "pA"));
}

#[test]
fn a_spent_backup_code_stays_spent_and_a_counter_never_goes_back() {
    let mut fake = server();
    let mut a = Client::connect(&mut fake, EMAIL);
    a.put("backup-codes", CODES_ID, with_id(backup_codes("GitHub"), CODES_ID));
    let mut hotp = totp_account("Bank", "card");
    hotp["type"] = json!("hotp");
    hotp["counter"] = json!(3);
    a.put("authenticator", ACCOUNT_ID, with_id(hotp, ACCOUNT_ID));
    assert_clean(&a.sync(&mut fake).problem);
    let mut b = Client::connect(&mut fake, EMAIL);
    assert_clean(&b.sync(&mut fake).problem);
    // A spends a code (earlier), B changes the note (later): both hold, and the code stays spent whichever wins
    edit(&mut a, "backup-codes", CODES_ID, |value| {
        value["codes"][0]["used"] = json!(true);
        value["codes"][0]["usedAt"] = json!(3000);
        value["updatedAt"] = json!(3000);
    });
    edit(&mut b, "backup-codes", CODES_ID, |value| {
        value["note"] = json!("in the drawer");
        value["updatedAt"] = json!(4000);
    });
    // The counter: B moved it far, A (later) moved it less
    edit(&mut b, "authenticator", ACCOUNT_ID, |value| {
        value["counter"] = json!(9);
        value["updatedAt"] = json!(3000);
    });
    edit(&mut a, "authenticator", ACCOUNT_ID, |value| {
        value["counter"] = json!(5);
        value["updatedAt"] = json!(4000);
    });
    assert_clean(&a.sync(&mut fake).problem);
    assert_clean(&b.sync(&mut fake).problem);
    assert_clean(&a.sync(&mut fake).problem);
    for client in [&a, &b] {
        let codes = client.value("backup-codes", CODES_ID);
        assert_eq!(codes["codes"][0]["used"], true, "the spent code is spent on both");
        assert_eq!(codes["codes"][1]["used"], false);
        assert_eq!(codes["note"], "in the drawer");
    }
    let plain = fake.plain_of(EMAIL, &sid(&fake, CODES_ID)).unwrap();
    assert_eq!((plain["codes"][0]["used"].as_bool(), plain["note"].as_str()), (Some(true), Some("in the drawer")));
    assert_clean(&b.sync(&mut fake).problem);
    for client in [&a, &b] {
        assert_eq!(client.value("authenticator", ACCOUNT_ID)["counter"], 9, "the larger counter wins whichever side changed last");
    }
    assert_eq!(fake.plain_of(EMAIL, &sid(&fake, ACCOUNT_ID)).unwrap()["counter"], 9);
}

// --- Deleting ---------------------------------------------------------------------------------------------------------------------

#[test]
fn a_tombstone_trashes_a_password_here_and_a_key_is_never_destroyed_by_one() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    // The Kemlock app deletes the login
    let login = sid(&fake, PASSWORD_ID);
    fake.plant_tombstone(EMAIL, &login);
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.trashed_here, 1);
    assert!(crate::sync::map::deleted(&client.locals[&("password".to_string(), PASSWORD_ID.to_string())]), "it is in the vault's own trash, not gone");
    assert!(client.links[&login].deleted);
    // And then the key: it stays, and goes back to the server over the tombstone, as the next revision, with the manifest saying so
    let key = sid(&fake, SSH_ID);
    fake.plant_tombstone(EMAIL, &key);
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(client.has("key", SSH_ID));
    assert!(!crate::sync::map::deleted(&client.locals[&("key".to_string(), SSH_ID.to_string())]));
    assert_eq!(fake.revision_of(EMAIL, &key), Some(3));
    assert!(!fake.wire_of(EMAIL, &key).unwrap().deleted);
    assert!(verified_manifest(&fake).entries.iter().any(|entry| entry.item_id.to_string() == key && entry.revision == 3 && !entry.deleted));
    // A password trashed here is a tombstone there, and the server has no trash of its own
    edit(&mut client, "authenticator", ACCOUNT_ID, |value| value["deletedAt"] = json!(1_765_000_000_000i64));
    assert_clean(&client.sync(&mut fake).problem);
    assert!(fake.wire_of(EMAIL, &sid(&fake, ACCOUNT_ID)).unwrap().deleted);
}

#[test]
fn an_item_turned_off_leaves_the_server_and_stays_in_the_vault() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    // The service hands a run only the items that may sync: this one is no longer among them
    client.locals.remove(&("password".to_string(), PASSWORD_ID.to_string()));
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.trashed_there, 1);
    assert!(fake.wire_of(EMAIL, &sid(&fake, PASSWORD_ID)).unwrap().deleted);
}

#[test]
fn many_items_gone_at_once_stop_the_run_until_a_person_says_so() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    for n in 0..8 {
        let id = format!("00000000-0000-4000-8000-{n:012}");
        client.put("password", &id, with_id(password(&format!("Site {n}"), "u", "p", &format!("site{n}.example")), &id));
    }
    assert_clean(&client.sync(&mut fake).problem);
    for n in 0..6 {
        fake.plant_tombstone(EMAIL, &format!("00000000-0000-4000-8000-{n:012}"));
    }
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::ManyGone(6)));
    assert!(client.locals.values().all(|local| !crate::sync::map::deleted(local)), "nothing was taken");
    let outcome = client.accept(&mut fake);
    assert_clean(&outcome.problem);
    assert!(outcome.accepted);
    assert_eq!(client.locals.values().filter(|local| crate::sync::map::deleted(local)).count(), 6);
    // And many arriving at once, after the first pull, stop it too
    for n in 100..107 {
        fake.plant_item(EMAIL, "login", &json!({"id": format!("00000000-0000-4000-8000-{n:012}"), "name": format!("New {n}"), "username": "u", "password": "p", "websites": [format!("new{n}.example")], "addedAt": 1}));
    }
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::ManyNew(7)));
    assert!(client.locals.len() == 8);
}

// --- The signed manifest -----------------------------------------------------------------------------------------------------------

#[test]
fn the_manifest_lists_what_the_vault_does_not_read_and_what_is_not_the_persons_own() {
    let mut fake = server();
    // What other apps keep: a Bitwarden copy, an item of a kind this client does not read, a note of the app's, and a space's item
    let cipher = json!({"id": "11111111-2222-4333-8444-555555555555", "type": 1, "name": "2.abc|def|ghi"});
    fake.plant_bw(EMAIL, "login", &cipher);
    let future = fake.plant_item(EMAIL, "future-kind", &json!({"id": "99999999-8888-4777-8666-555555555555", "anything": [1]}));
    let note = fake.plant_item(EMAIL, "note", &json!({"id": "2f6b8d0e-4a1c-4e3f-a5b7-c9d1e3f5a7b9", "title": "Wi-Fi", "text": "Network: Larkspur", "addedAt": 1}));
    let foreign = fake.plant_foreign(EMAIL, &json!({"id": "x", "name": "a space's"}));
    fake.sign_manifest(EMAIL);
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    // None of it was written, deleted or taken
    for id in ["11111111-2222-4333-8444-555555555555", &future, &note] {
        assert_eq!(fake.revision_of(EMAIL, id), Some(1), "{id}");
        assert!(!fake.wire_of(EMAIL, id).unwrap().deleted);
    }
    assert_eq!(client.locals.len(), 1);
    // The manifest the client signed lists them all as they were, bw's by the hash of its cipher's bytes, and not the space's
    let manifest = verified_manifest(&fake);
    assert_eq!(manifest.counter, 2);
    let listed: Vec<String> = manifest.entries.iter().map(|entry| entry.item_id.to_string()).collect();
    for id in ["11111111-2222-4333-8444-555555555555", &future, &note, &sid(&fake, PASSWORD_ID)] {
        assert!(listed.contains(&id.to_string()), "{id} in {listed:?}");
    }
    assert!(!listed.contains(&foreign));
    let bw = manifest.entries.iter().find(|entry| entry.item_id.to_string() == "11111111-2222-4333-8444-555555555555").unwrap();
    assert_eq!(bw.ciphertext_hash, sha(cipher.to_string().as_bytes()));
    assert_eq!(client.links.len(), 4);
}

#[test]
fn items_no_manifest_lists_are_held_out_of_the_merge_until_one_does_and_a_day_stops_the_run() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    assert_clean(&client.sync(&mut fake).problem);
    // Another app writes an item and signs no manifest
    let unlisted = "00000000-0000-4000-8000-0000000000aa";
    fake.plant_item(EMAIL, "login", &json!({"id": unlisted, "name": "Unlisted", "username": "u", "password": "p", "websites": ["unlisted.example"], "addedAt": 1}));
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(!client.has("password", unlisted), "held out of the merge");
    assert!(client.connection.kemlock.as_ref().unwrap().held.contains_key(unlisted));
    // What this client writes meanwhile does not vouch for it
    client.put("backup-codes", CODES_ID, with_id(backup_codes("GitHub"), CODES_ID));
    assert_clean(&client.sync(&mut fake).problem);
    assert!(!verified_manifest(&fake).entries.iter().any(|entry| entry.item_id.to_string() == unlisted));
    assert!(!client.has("password", unlisted));
    // The app signs one that lists it: it is taken
    fake.sign_manifest(EMAIL);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert!(client.has("password", unlisted));
    assert!(client.connection.kemlock.as_ref().unwrap().held.is_empty());
    // One that stays unlisted for a day stops the run: the server handed back something no device vouches for
    let unlisted2 = "00000000-0000-4000-8000-0000000000bb";
    fake.plant_item(EMAIL, "login", &json!({"id": unlisted2, "name": "Unlisted too", "username": "u", "password": "p", "websites": ["unlisted2.example"], "addedAt": 1}));
    assert_clean(&client.sync(&mut fake).problem);
    client.now_ms += 25 * 3600 * 1000;
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::ITEMS_UNLISTED)));
    // A person who says so vouches for what is there
    let outcome = client.accept(&mut fake);
    assert_clean(&outcome.problem);
    assert!(client.has("password", unlisted2));
}

// --- Files -----------------------------------------------------------------------------------------------------------------------

#[test]
fn a_file_goes_before_the_note_that_names_it_and_a_second_device_opens_it() {
    let mut fake = server();
    let mut a = Client::connect(&mut fake, EMAIL);
    a.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
    let outcome = a.sync(&mut fake);
    assert_clean(&outcome.problem);
    // In this order: the slot, the bytes, the note
    let paths: Vec<String> = fake.seen.iter().map(|seen| format!("{} {}", seen.method, seen.path())).filter(|p| p.contains("/files") || p.contains("items:batch")).collect();
    assert!(paths[0].starts_with("POST ") && paths[0].ends_with("/files"), "{paths:?}");
    assert!(paths[1].starts_with("PUT ") && paths[1].contains("/files/"), "{paths:?}");
    assert!(paths[2].ends_with("items:batch"), "{paths:?}");
    let id = sid(&fake, FILE_ID);
    let plain = fake.plain_of(EMAIL, &id).unwrap();
    let attachment = &plain["attachments"][0];
    let file_id = attachment["kemlockFile"].as_str().expect("the note names the server's file");
    assert_eq!(plain["amethystora"]["attachment"], attachment["id"]);
    let stored = fake.account(EMAIL).files[file_id].bytes.clone().expect("the file is there");
    assert_eq!(stored.len(), kma1::sealed_len(22));
    assert!(stored.starts_with(b"KMA1"));
    // It opens with the key in the note, and with nothing else
    let key = crate::kemlock::Key::from_slice(&base64::Engine::decode(&base64::engine::general_purpose::STANDARD, attachment["key"].as_str().unwrap()).unwrap()).unwrap();
    assert_eq!(&kma1::decrypt(&key, &stored, 1 << 20).unwrap()[..], b"a file of the person's");
    assert!(kma1::decrypt(&crate::kemlock::Key::random(), &stored, 1 << 20).is_err());
    assert_eq!(fake.revision_of(EMAIL, &id), Some(1));
    let sent = everything_sent(&fake);
    assert!(!sent.contains("a file of the person's"));
    // A second device with the same item pairs with it, and when the first changes the file, takes the new one
    let mut b = Client::connect(&mut fake, EMAIL);
    b.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
    assert_clean(&b.sync(&mut fake).problem);
    edit_file(&mut a, b"the file, changed");
    let outcome = a.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(fake.revision_of(EMAIL, &id), Some(2));
    assert!(!fake.account(EMAIL).files.contains_key(file_id), "the old file was dropped once the new was named");
    assert_eq!(fake.account(EMAIL).files.len(), 1);
    let outcome = b.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(outcome.report.received, 1);
    assert_eq!(b.value("protected", FILE_ID)["files"][0]["data"], base64::Engine::encode(&base64::engine::general_purpose::STANDARD, b"the file, changed"));
    // A file that did not change is not sent again
    let uploads = fake.requests_to("/files");
    assert_clean(&a.sync(&mut fake).problem);
    assert_eq!(fake.requests_to("/files"), uploads);
}

fn edit_file(client: &mut Client, bytes: &[u8]) {
    let local = client.locals.get_mut(&("protected".to_string(), FILE_ID.to_string())).unwrap();
    local.value["files"][0]["data"] = json!(base64::Engine::encode(&base64::engine::general_purpose::STANDARD, bytes));
}

#[test]
fn a_file_the_server_cannot_keep_is_said_and_the_vaults_copy_stays() {
    for (why, setup) in [("file-too-large", 0), ("files-refused", 1), (word::FILES_BUCKET, 2)] {
        let mut fake = server();
        match setup {
            0 => fake.max_file = 10,
            1 => fake.files_disabled = true,
            _ => fake.attack(Attack::Presigned),
        }
        let mut client = Client::connect(&mut fake, EMAIL);
        client.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
        client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
        let outcome = client.sync(&mut fake);
        assert_clean(&outcome.problem);
        assert_eq!(outcome.report.refused_total, 1, "{why}");
        assert_eq!(outcome.report.refused[0]["why"], why);
        assert!(client.has("protected", FILE_ID), "the vault's copy stays");
        // The rest of the run went on
        assert_eq!(fake.live_ids(EMAIL).len(), 1);
        assert!(fake.account(EMAIL).files.values().all(|file| file.bytes.is_none()));
    }
}

// --- More of the run ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_manifest_another_device_signed_first_is_read_and_signed_above() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("Mail", "sam", "p1", "mail.example"), PASSWORD_ID));
    fake.attack(Attack::StaleManifest);
    assert_clean(&client.sync(&mut fake).problem);
    // The other device signed counter 1 (and listed what the server holds); this one signed above it
    let manifest = verified_manifest(&fake);
    assert_eq!((manifest.counter, manifest.entries.len()), (2, 1));
    assert_eq!(client.connection.kemlock.as_ref().unwrap().manifest_counter, 2);
    assert_eq!(fake.requests_to("/manifests/"), 4, "a read, two writes, and the read between them");
}

#[test]
fn the_first_write_of_an_item_names_no_revision_it_replaces() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    let batch = fake.seen.iter().find(|seen| seen.path().ends_with("items:batch")).unwrap();
    let body: Value = serde_json::from_str(&batch.body).unwrap();
    let writes = body["writes"].as_array().unwrap();
    assert_eq!(writes.len(), 9);
    for write in writes {
        assert!(write["expectedRevision"].is_null(), "{write}");
        assert_eq!(write["item"]["revision"], 1);
        assert_eq!(write["item"]["deleted"], false, "`deleted` is always there");
        assert_eq!(write["item"]["format"], "kem1");
        assert_eq!(write["item"]["owner"], owner_of(&fake).to_string());
        assert!(write["item"].get("deletedAt").is_none() && write["item"].get("held").is_none(), "nothing but the members a server takes");
    }
}

#[test]
fn every_kind_is_on_by_default_here_and_a_kind_turned_off_is_not_written() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    for kind in ["password", "authenticator", "backup-codes", "key", "certificate", "protected"] {
        assert_eq!(client.connection.kind_choice(kind), "on", "{kind}");
    }
    client.connection.kinds.insert("key".into(), "off".into());
    every_kind(&mut client);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(fake.live_ids(EMAIL).len(), 6, "the three keys stayed home");
    assert_eq!(client.of_kind("key").len(), 3);
    // A kind a sealed note was kept for reads as on
    client.connection.kinds.insert("key".into(), "sealed".into());
    assert_eq!(client.connection.kind_choice("key"), "on");
}

#[test]
fn an_item_turned_off_and_on_again_goes_back_over_its_tombstone() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    every_kind(&mut client);
    assert_clean(&client.sync(&mut fake).problem);
    let local = client.locals.remove(&("key".to_string(), SSH_ID.to_string())).unwrap();
    assert_clean(&client.sync(&mut fake).problem);
    let id = sid(&fake, SSH_ID);
    assert!(fake.wire_of(EMAIL, &id).unwrap().deleted);
    assert_eq!(fake.revision_of(EMAIL, &id), Some(2));
    client.add(local);
    let outcome = client.sync(&mut fake);
    assert_clean(&outcome.problem);
    assert_eq!(fake.revision_of(EMAIL, &id), Some(3));
    assert!(!fake.wire_of(EMAIL, &id).unwrap().deleted);
    assert_eq!(fake.wire_of(EMAIL, &id).unwrap().kind, "ssh-key", "an item's kind never changes");
    assert!(verified_manifest(&fake).entries.iter().any(|entry| entry.item_id.to_string() == id && entry.revision == 3 && !entry.deleted));
}

#[test]
fn a_run_that_cannot_read_what_it_needs_asks_nothing_of_the_server() {
    use crate::kemlock::sync::engine::{self, Input};
    let mut fake = server();
    let client = Client::connect(&mut fake, EMAIL);
    let before = fake.seen.len();
    let input = |connection, local_unreadable, links_unreadable| Input { connection, access: None, links: Vec::new(), locals: Vec::new(), accept: false, full: false, now_ms: now_ms(), local_unreadable, links_unreadable };
    let persist = |_: &str| true;
    assert_eq!(engine::run(&mut fake, &crate::sync::convert::Direct, input(client.connection.clone(), 2, false), &persist).problem, Some(Problem::LocalUnreadable(2)));
    assert_eq!(engine::run(&mut fake, &crate::sync::convert::Direct, input(client.connection.clone(), 0, true), &persist).problem, Some(Problem::LinksUnreadable));
    // A connection that is not a Kemlock one has no business here
    let mut other = client.connection.clone();
    other.kemlock = None;
    assert_eq!(engine::run(&mut fake, &crate::sync::convert::Direct, input(other, 0, false), &persist).problem, Some(Problem::CannotOpen));
    // A root key that is not the account's does not open its keys, and nothing is sent
    let mut wrong = client.connection.clone();
    wrong.user_key = crate::seal::hex(&[7u8; 64]);
    assert_eq!(engine::run(&mut fake, &crate::sync::convert::Direct, input(wrong, 0, false), &persist).problem, Some(Problem::Kemlock(word::KEYS_INVALID)));
    assert_eq!(fake.seen.len(), before);
}
