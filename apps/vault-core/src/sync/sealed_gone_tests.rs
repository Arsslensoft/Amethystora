//! Sealed sync is gone (plans/vault-kemlock, decision 3): what an earlier version wrote as a sealed note is read, and replaced by the
//! item's plain form, the plain cipher first and the note to the server's trash after it, never deleted. A `sealed` stored for a kind or an
//! item is `on`. Nothing here makes a note by the vault's own code: `plant_sealed` writes one the way the last version that did it did.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use super::cipher::{self, Content};
use super::fake::{Fake, USER_ID};
use super::kinds_tests::cert_local;
use super::map::{self, Local};
use super::merge::{Held, Link, PartRef};
use super::tests::{backup_codes, bump, connect, password, Vault};
use crate::protocol::Approval;
use crate::seal::{self, Key};

/// The name an earlier version gave every sealed note
const SEALED_NAME: &str = "Amethystora sealed item";

fn vault_with_key() -> Vault {
    Vault { sealing: Some((Key::random(), "vault-1".into())), ..Vault::default() }
}

fn copy_of(vault: &Vault) -> Vault {
    Vault { sealing: vault.sealing.as_ref().map(|(k, v)| (k.copy(), v.clone())), ..Vault::default() }
}

fn live(fake: &Fake) -> Vec<String> {
    fake.ciphers.iter().filter(|raw| raw["deletedDate"].is_null()).map(|raw| raw["id"].as_str().unwrap().to_string()).collect()
}

fn in_trash(fake: &Fake, id: &str) -> bool {
    !fake.find(id).unwrap()["deletedDate"].is_null()
}

fn opened(fake: &Fake, id: &str) -> cipher::Opened {
    cipher::open(fake.find(id).unwrap(), &fake.user).unwrap()
}

fn local_of(vault: &Vault, kind: &str, id: &str) -> Local {
    vault.locals.get(&(kind.to_string(), id.to_string())).cloned().unwrap()
}

/// What the last version that sealed wrote for `local` (the vault's own, with its sealing key): the note on the server, and the link the
/// vault kept for it. A blob that does not fit a note is the note's file, as it was.
pub(super) fn plant_sealed(fake: &mut Fake, vault: &mut Vault, local: &Local, counter: u64) -> String {
    let (key, id) = vault.sealing.as_ref().expect("a sealing key");
    let (notes, blob) = match map::sealed_text(local, key, id, counter) {
        Ok(text) => (text.to_string(), None),
        Err(_) => (map::SEALED_ATTACHED.to_string(), Some(map::sealed_bytes(local, key, id, counter))),
    };
    let content = Content { kind: cipher::NOTE, name: SEALED_NAME.into(), notes: Some(notes), marker: Some(cipher::MARKER_SEALED.into()), ..Content::default() };
    let cipher_id = fake.store(cipher::create_body(&content, USER_ID, &fake.user).unwrap());
    let file = blob.map(|bytes| Held { id: fake.attach(&cipher_id, "amethystora-sealed.bin", &bytes), hash: seal::hex(&Sha256::digest(&bytes)) });
    let raw = fake.find(&cipher_id).unwrap().clone();
    let part = PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: map::hash(local) };
    let link = Link { cipher: cipher_id.clone(), revision: raw["revisionDate"].as_str().unwrap().into(), atts: cipher::attachments(&raw), raw, deleted: false, sealed: true, seal: counter, file, made: true, parts: vec![part] };
    vault.locals.insert((local.kind.clone(), local.id.clone()), local.clone());
    vault.links.insert(cipher_id.clone(), link);
    cipher_id
}

/// A vault whose one password was sealed by the last version, and the connection it kept (`sealed`, for that kind)
fn sealed_password() -> (Fake, super::merge::Connection, Vault, String) {
    let mut fake = Fake::default();
    let mut connection = connect(&mut fake).unwrap();
    connection.kinds.insert("password".into(), "sealed".into());
    let mut vault = vault_with_key();
    vault.put("password", "p1", password("Site", "person", "pw-secret", "https://a.test"));
    let local = local_of(&vault, "password", "p1");
    let note = plant_sealed(&mut fake, &mut vault, &local, 1);
    (fake, connection, vault, note)
}

#[test]
fn a_sealed_choice_reads_as_on_everywhere() {
    let mut connection = connect(&mut Fake::default()).unwrap();
    connection.kinds.insert("key".into(), "sealed".into());
    connection.kinds.insert("password".into(), "off".into());
    connection.choices.insert("password.p1".into(), "sealed".into());
    connection.choices.insert("backup-codes.b1".into(), "sealed".into());
    assert_eq!(connection.kind_choice("key"), "on");
    assert_eq!((connection.choice("key", "k1"), connection.choice("password", "p1"), connection.choice("password", "p2")), ("on", "on", "off"));
    // Where the kind says off, an item's old `sealed` is its own word, and wins as `on`
    assert_eq!(connection.choice("backup-codes", "b1"), "on");
    // A stored connection that says so is read the same, and says nothing of it on its way back
    let stored = serde_json::to_value(&connection).unwrap();
    assert_eq!(stored["kinds"]["key"], json!("sealed"));
    let back: super::merge::Connection = serde_json::from_value(stored).unwrap();
    assert_eq!(back.kind_choice("key"), "on");
}

#[test]
fn an_item_stored_as_sealed_goes_as_the_plain_cipher_of_an_item_set_to_on() {
    let mut fake = Fake::default();
    let mut connection = connect(&mut fake).unwrap();
    connection.kinds.insert("password".into(), "sealed".into());
    connection.choices.insert("backup-codes.b1".into(), "sealed".into());
    let mut vault = vault_with_key();
    vault.put("password", "p1", password("Site", "person", "pw-secret", "https://a.test"));
    vault.put("backup-codes", "b1", backup_codes("Bank"));
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none() && outcome.report.refused_total == 0, "{:?}", outcome.report.refused);
    assert_eq!(live(&fake).len(), 2);
    for id in live(&fake) {
        let content = opened(&fake, &id).content;
        assert!(!map::is_sealed_note(&content), "a note the vault never writes again");
        assert!(content.name != SEALED_NAME);
    }
    assert!(vault.links.values().all(|link| !link.sealed));
}

#[test]
fn an_old_sealed_note_is_replaced_by_its_plain_form_and_the_note_goes_to_the_trash_after_it() {
    let (mut fake, connection, mut vault, note) = sealed_password();
    assert_eq!(live(&fake), vec![note.clone()]);
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none() && outcome.report.refused_total == 0, "{:?} {:?}", outcome.problem, outcome.report.refused);
    // One plain cipher stands, the note is in the server's trash, and nothing was deleted (the fake refuses a permanent delete)
    assert_eq!(fake.ciphers.len(), 2);
    assert!(in_trash(&fake, &note));
    let plain = live(&fake);
    assert_eq!(plain.len(), 1);
    let content = opened(&fake, &plain[0]).content;
    assert_eq!((content.kind, content.password.as_deref(), content.username.as_deref()), (cipher::LOGIN, Some("pw-secret"), Some("person")));
    // The plain one was written first
    let writes: Vec<(&str, &str)> = fake.seen.iter().filter(|seen| seen.method != "GET" && seen.url.contains("/api/ciphers")).map(|seen| (seen.method.as_str(), seen.url.rsplit('/').next().unwrap())).collect();
    assert_eq!(writes.len(), 2, "{writes:?}");
    assert_eq!(writes[0], ("POST", "ciphers"));
    assert_eq!(writes[1], ("PUT", "delete"));
    assert!(fake.seen.iter().all(|seen| seen.method != "DELETE"));
    // The vault keeps one link, the plain one, and its item as it was
    assert_eq!(vault.links.len(), 1);
    let link = vault.links.get(&plain[0]).unwrap();
    assert!(!link.sealed && link.made && link.parts.len() == 1);
    assert_eq!(vault.value("password", "p1")["password"], json!("pw-secret"));
    assert_eq!((outcome.report.sent, outcome.report.trashed_there), (1, 1));
    // Nothing more to do next time, and nothing more is made
    let again = vault.sync(&mut fake, &connection);
    assert!(again.problem.is_none() && again.report.sent == 0 && again.report.refused_total == 0, "{:?}", again.report.refused);
    assert_eq!((fake.ciphers.len(), live(&fake).len()), (2, 1));
}

#[test]
fn a_failed_plain_write_leaves_the_sealed_note_where_it_is() {
    let (mut fake, connection, mut vault, note) = sealed_password();
    fake.status.insert("write", 500);
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_some() || outcome.report.refused_total > 0, "the write failed and nothing said so");
    assert_eq!(fake.ciphers.len(), 1, "no second cipher");
    assert!(!in_trash(&fake, &note), "the note went to the trash with nothing to take its place");
    assert!(vault.links.get(&note).is_some_and(|link| link.sealed), "the vault still knows it as the sealed note");
    assert!(fake.seen.iter().all(|seen| !seen.url.ends_with("/delete")));
    // A server that refuses it with a word the same
    fake.status.insert("write", 400);
    vault.sync(&mut fake, &connection);
    assert!(!in_trash(&fake, &note) && fake.ciphers.len() == 1);
    // Whole again: the next run does it
    fake.status.remove("write");
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(in_trash(&fake, &note));
    assert_eq!(live(&fake).len(), 1);
    assert!(vault.links.values().all(|link| !link.sealed));
}

#[test]
fn a_note_that_cannot_reach_the_trash_after_the_plain_cipher_stands_is_trashed_by_the_next_run() {
    let (mut fake, connection, mut vault, note) = sealed_password();
    fake.status.insert("trash", 500);
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_some());
    // The plain cipher stands and is linked, so that no third copy is made; the note is listed for the next run
    assert_eq!(live(&fake).len(), 2);
    assert!(vault.links.values().any(|link| !link.sealed));
    fake.status.remove("trash");
    let connection = {
        let mut kept = connection.clone();
        kept.pending = outcome.pending.clone();
        kept
    };
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(in_trash(&fake, &note));
    assert_eq!(fake.ciphers.len(), 2);
    assert_eq!(live(&fake).len(), 1);
}

#[test]
fn an_old_sealed_note_whose_blob_is_a_file_goes_plain_too() {
    let mut fake = Fake::default();
    let mut connection = connect(&mut fake).unwrap();
    connection.kinds.insert("certificate".into(), "sealed".into());
    let mut vault = vault_with_key();
    let mut big = cert_local("c1", "Big", 0);
    big.value["fields"] = json!({"pad": "x".repeat(6000)});
    let note = plant_sealed(&mut fake, &mut vault, &big, 4);
    assert_eq!(opened(&fake, &note).content.notes.as_deref(), Some(map::SEALED_ATTACHED));
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none() && outcome.report.refused_total == 0, "{:?} {:?}", outcome.problem, outcome.report.refused);
    assert!(in_trash(&fake, &note));
    let plain = live(&fake);
    assert_eq!(plain.len(), 1);
    let content = opened(&fake, &plain[0]).content;
    assert!(!map::is_sealed_note(&content) && content.name != SEALED_NAME);
    assert!(vault.links.values().all(|link| !link.sealed));
    assert_eq!(vault.value("certificate", "c1"), big.value);
}

#[test]
fn an_old_sealed_note_of_an_item_the_vault_no_longer_holds_is_only_trashed() {
    let (mut fake, connection, mut vault, note) = sealed_password();
    vault.locals.clear();
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(in_trash(&fake, &note));
    assert_eq!(fake.ciphers.len(), 1, "nothing was made in its place");
    assert!(vault.links.is_empty());
}

#[test]
fn an_old_sealed_note_of_an_item_set_to_off_is_trashed_and_the_item_stays() {
    let (mut fake, mut connection, mut vault, note) = sealed_password();
    connection.choices.insert("password.p1".into(), "off".into());
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(in_trash(&fake, &note));
    assert_eq!((fake.ciphers.len(), vault.of_kind("password").len()), (1, 1));
}

#[test]
fn an_old_sealed_note_changed_on_the_server_is_kept_beside_the_vaults_item_and_both_go_plain() {
    let (mut fake, connection, mut vault, note) = sealed_password();
    // Another vault of the same key sealed another value into it
    let key = vault.sealing.as_ref().unwrap().0.copy();
    let theirs = Local { kind: "password".into(), id: "p1".into(), name: "Site".into(), meta: Value::Null, approval: Approval::WhileOpen, value: password("Site", "person", "THEIR-SECRET", "https://a.test") };
    let text = map::sealed_text(&theirs, &key, "vault-1", 3).unwrap();
    let raw = fake.find(&note).unwrap().clone();
    let body = cipher::update_body(&raw, &opened(&fake, &note).content, &Content { notes: Some(text.to_string()), ..opened(&fake, &note).content }, USER_ID, &fake.user).unwrap();
    bump(&mut fake, &note, |stored| stored["notes"] = body["notes"].clone());
    let outcome = vault.sync(&mut fake, &connection);
    assert_eq!(outcome.report.conflicts, 1, "{:?} {:?}", outcome.problem, outcome.report.refused);
    // Nothing lost: the vault's own and the other's are both items now
    let secrets: Vec<Value> = vault.of_kind("password").iter().map(|local| local.value["password"].clone()).collect();
    assert!(secrets.contains(&json!("pw-secret")) && secrets.contains(&json!("THEIR-SECRET")), "{secrets:?}");
    // And two runs later both are plain ciphers and no sealed note is live
    vault.sync(&mut fake, &connection);
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(vault.links.values().all(|link| !link.sealed), "{:?}", vault.links.values().map(|link| link.sealed).collect::<Vec<_>>());
    assert!(in_trash(&fake, &note));
    let plain: Vec<String> = live(&fake).iter().map(|id| opened(&fake, id).content.password.unwrap_or_default()).collect();
    assert_eq!(plain.len(), 2, "{plain:?}");
    assert!(plain.contains(&"pw-secret".to_string()) && plain.contains(&"THEIR-SECRET".to_string()));
}

#[test]
fn a_note_of_this_vault_that_it_has_not_seen_comes_in_and_goes_plain_the_next_run() {
    let (mut fake, connection, vault, note) = sealed_password();
    // This vault restored from a backup that has the key but not the item or its link
    let mut restored = copy_of(&vault);
    restored.sync(&mut fake, &connection);
    assert_eq!(restored.value("password", "p1")["password"], json!("pw-secret"));
    assert!(restored.links.get(&note).is_some_and(|link| link.sealed));
    assert!(!in_trash(&fake, &note));
    let outcome = restored.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none(), "{:?}", outcome.problem);
    assert!(in_trash(&fake, &note));
    assert_eq!(live(&fake).len(), 1);
    assert_eq!(opened(&fake, &live(&fake)[0]).content.password.as_deref(), Some("pw-secret"));
}

#[test]
fn a_sealed_note_of_another_vault_is_counted_and_left_alone() {
    let (mut fake, connection, vault, note) = sealed_password();
    let mut other = Vault { sealing: Some((Key::random(), "vault-2".into())), ..Vault::default() };
    let outcome = other.sync(&mut fake, &connection);
    assert!(outcome.problem.is_none());
    assert_eq!(outcome.report.sealed_elsewhere, 1);
    assert!(other.locals.is_empty() && other.links.is_empty());
    assert!(!in_trash(&fake, &note));
    drop(vault);
}

#[test]
fn an_older_copy_of_an_old_sealed_note_that_a_server_kept_is_never_taken() {
    let mut fake = Fake::default();
    let mut connection = connect(&mut fake).unwrap();
    connection.kinds.insert("password".into(), "sealed".into());
    let mut vault = vault_with_key();
    vault.put("password", "p1", password("Site", "person", "NEW-SECRET", "https://a.test"));
    let local = local_of(&vault, "password", "p1");
    let note = plant_sealed(&mut fake, &mut vault, &local, 5);
    // The server serves the note as it was at the vault's first send, dated later
    let key = vault.sealing.as_ref().unwrap().0.copy();
    let older = Local { value: password("Site", "person", "OLD-SECRET", "https://a.test"), ..local };
    let text = map::sealed_text(&older, &key, "vault-1", 2).unwrap();
    let raw = fake.find(&note).unwrap().clone();
    let body = cipher::update_body(&raw, &opened(&fake, &note).content, &Content { notes: Some(text.to_string()), ..opened(&fake, &note).content }, USER_ID, &fake.user).unwrap();
    bump(&mut fake, &note, |stored| stored["notes"] = body["notes"].clone());
    let outcome = vault.sync(&mut fake, &connection);
    assert!(outcome.report.refused.iter().any(|r| r["why"] == "rolled-back"), "{:?} {:?}", outcome.problem, outcome.report.refused);
    assert_eq!(vault.value("password", "p1")["password"], json!("NEW-SECRET"));
    assert!(vault.of_kind("password").len() == 1 && !in_trash(&fake, &note));
    assert!(vault.links.get(&note).is_some_and(|link| link.sealed));
}
