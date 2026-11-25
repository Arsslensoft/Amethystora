//! A sync run on the Kemlock API (`spec-protocol.md` 5, 6, 7, 10; `spec-items.md`): read what changed since the cursor, check it
//! against the signed manifest, decide for each item what moved where, write to the server (batches, files, the manifest), and say
//! what the vault should write, as `sync::merge`'s run does for Bitwarden: the same `Outcome`, which the service puts in place a
//! slice at a time, each group only if the items it was decided from are still as they were.
//!
//! A link is one item of the server (`Link.cipher` is its id) and, when it is one of this client's, the vault item it pairs with.
//! What the link keeps in `raw` is what the cache needs: the item's kind, revision, hash and, for an item this client reads, the
//! last plaintext the server had, which a write starts from. Items this client does not read are links too, with no part: the
//! manifest lists every item the server holds.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::kemlock::conv::{Owner, Uuid, b64_decode, item_uuid};
use crate::kemlock::item::{Kem1Item, WireItem};
use crate::kemlock::manifest::{Entry, Manifest};
use crate::kemlock::{Key, kma1};
use crate::protocol::Approval;
use crate::seal;
use crate::sync::address::Server;
use crate::sync::api::{Expired, Http, Problem};
use crate::sync::convert::Convert;
use crate::sync::map::{self, Local};
use crate::sync::merge::{Access, Basis, Connection, Group, Link, Outcome, PartRef, Report, Write};

use super::account::{self, Account};
use super::api::{FileRefusal, FullSync, KemApi, Page, Refused};
use super::dpop::DpopKey;
use super::items::{self, Mapped, Taken};
use super::state::{MoveRecord, News};
use super::word;

/// The most items one batch holds, and the most JSON: the server's limits are 500 and 2 MiB
const BATCH_ITEMS: usize = 500;
const BATCH_BYTES: usize = 1_500_000;
/// The server's ciphertext limit by default, 1 MiB
const MOST_CIPHERTEXT: usize = 1024 * 1024;
/// A file this client sends: the network service's line is 24 MiB, which a 16 MiB file fits
pub const MOST_FILE: usize = 16 * 1024 * 1024;
const FEW: usize = 5;
const DAY_MS: i64 = 24 * 3600 * 1000;
/// Attempts of one run when the server says another device wrote first
const ATTEMPTS: u32 = 3;

pub struct Input {
    pub connection: Connection,
    pub access: Option<Access>,
    pub links: Vec<Link>,
    /// Every item that may sync and is not off
    pub locals: Vec<Local>,
    /// A person said so: what went from the server, or arrived, may go on, and what the manifest does not list is vouched for
    pub accept: bool,
    /// Read everything again, whatever the cursor says
    pub full: bool,
    pub now_ms: i64,
    pub local_unreadable: usize,
    pub links_unreadable: bool,
}

/// The new refresh token, kept by whoever can write the connection before this run uses it: false stops the run
pub type Persist<'a> = dyn Fn(&str) -> bool + 'a;

fn sha256(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn hex32(hash: &[u8; 32]) -> String {
    seal::hex(hash)
}

fn unhex32(text: &str) -> Option<[u8; 32]> {
    seal::unhex(text)?.try_into().ok()
}

// --- What the run knows of each item of the server ---------------------------------------------------------------------------

/// An item of the server as the run knows it: from a link, and changed by what this run reads and writes
#[derive(Clone)]
struct Cached {
    kind: String,
    format: String,
    revision: u64,
    hash: [u8; 32],
    deleted: bool,
    key_version: u32,
    /// What the item opened to, for an item this client reads: the base of the next write
    plain: Option<Value>,
    /// The vault item it pairs with
    part: Option<PartRef>,
    /// The attachment this client sent for it: the SHA-256 of the file and the server's file id
    file: Option<(String, String)>,
    /// No signed manifest lists it: kept out of the merge
    held: bool,
    /// It was read but could not be taken yet (its file was not there, or did not open): decided again at the next run, whatever the cursor says
    retry: bool,
    /// This client made the item on the server: only such an item is deleted there when it stops syncing here
    made: bool,
}

impl Cached {
    fn from_link(link: &Link) -> Option<Cached> {
        let raw = &link.raw;
        Some(Cached {
            kind: raw.get("kind")?.as_str()?.to_string(),
            format: raw.get("format")?.as_str()?.to_string(),
            revision: link.revision.parse().ok()?,
            hash: unhex32(raw.get("hash")?.as_str()?)?,
            deleted: link.deleted,
            key_version: raw.get("key_version").and_then(Value::as_u64).unwrap_or(0) as u32,
            plain: raw.get("plain").filter(|plain| !plain.is_null()).cloned(),
            part: link.parts.first().cloned(),
            file: raw.get("file").and_then(|file| Some((file.get("sha256")?.as_str()?.to_string(), file.get("server")?.as_str()?.to_string()))),
            held: raw.get("held").and_then(Value::as_bool).unwrap_or(false),
            retry: raw.get("retry").and_then(Value::as_bool).unwrap_or(false),
            made: link.made,
        })
    }

    fn to_link(&self, id: &str) -> Link {
        let mut raw = json!({"kind": self.kind, "format": self.format, "hash": hex32(&self.hash), "key_version": self.key_version});
        if let Some(plain) = &self.plain {
            raw["plain"] = plain.clone();
        }
        if let Some((sha, server)) = &self.file {
            raw["file"] = json!({"sha256": sha, "server": server});
        }
        if self.held {
            raw["held"] = json!(true);
        }
        if self.retry {
            raw["retry"] = json!(true);
        }
        Link { cipher: id.to_string(), revision: self.revision.to_string(), raw, deleted: self.deleted, sealed: false, seal: 0, atts: Vec::new(), file: None, made: self.made, parts: self.part.iter().cloned().collect() }
    }

    fn entry(&self, id: &str) -> Option<Entry> {
        let id = Uuid::parse(id).ok()?;
        Some(if self.deleted { Entry::tombstone(id, self.revision) } else { Entry { item_id: id, revision: self.revision, ciphertext_hash: self.hash, deleted: false } })
    }
}

/// A write to the server that is planned, with what it will do to the cache when the server takes it
struct Planned {
    id: String,
    item: Kem1Item,
    expected: Option<u64>,
    cached: Cached,
    /// A file to send first, and the note's attachment it is
    file: Option<items::FileOut>,
    /// Server files this write leaves unnamed: deleted after it
    drop_files: Vec<String>,
}

struct Session<'a> {
    api: KemApi<'a>,
    connection: &'a Connection,
    refresh: Option<Zeroizing<String>>,
    until_ms: i64,
    now_ms: i64,
    renewed: bool,
    persist: &'a Persist<'a>,
}

impl Session<'_> {
    fn login(&mut self) -> Result<(), Problem> {
        let refresh = self.refresh.clone().ok_or(Problem::LoginExpired)?;
        let tokens = self.api.refresh(&refresh)?;
        // The old token is spent: the new one is what the run hands back, whatever happens next, and is kept before anything uses it, or a
        // crash would leave the old one to be used twice
        self.refresh = Some(tokens.refresh.clone());
        if !(self.persist)(&tokens.refresh) {
            return Err(Problem::Net(crate::sync::api::NetFailure::Cancelled));
        }
        if !tokens.user_id.eq_ignore_ascii_case(&self.connection.user_id) {
            return Err(Problem::IdentityChanged);
        }
        self.until_ms = self.now_ms + (tokens.expires_in.min(600) - 30) * 1000;
        self.api.access = Some(tokens.access);
        Ok(())
    }

    /// A call, signing in first if need be, and once more if the token ran out on the way
    fn call<T>(&mut self, mut what: impl FnMut(&mut KemApi<'_>) -> Result<T, Expired>) -> Result<T, Problem> {
        loop {
            if self.api.access.is_none() || self.until_ms <= self.now_ms {
                self.login()?;
            }
            match what(&mut self.api) {
                Ok(value) => return Ok(value),
                Err(Expired::Problem(problem)) => return Err(problem),
                Err(Expired::Token) if !self.renewed => {
                    self.renewed = true;
                    self.api.access = None;
                }
                Err(Expired::Token) => return Err(Problem::LoginExpired),
            }
        }
    }
}

struct Run<'a> {
    account: Account,
    owner: Owner,
    owner_text: String,
    state_cursor: Option<String>,
    convert: &'a dyn Convert,
    now_ms: i64,
    accept: bool,
    cache: BTreeMap<String, Cached>,
    /// Items this run read, or made: their links are written again
    touched: BTreeSet<String>,
    locals: HashMap<(String, String), &'a Local>,
    by_part: HashMap<(String, String), String>,
    groups: BTreeMap<String, Group>,
    planned: Vec<Planned>,
    report: Report,
    sent_hashes: BTreeMap<String, String>,
    /// The revision each of them was written at
    sent_revisions: BTreeMap<String, u64>,
    first_pull: bool,
    /// The vault items the links paired at the start of the run, with their items: only those can leave (an item this run paired is not a leaver)
    linked: Vec<((String, String), String)>,
    /// Vault items this run decided to trash because the server deleted them: not sent again as new
    trashed_now: BTreeSet<(String, String)>,
}

fn key_of(local: &Local) -> (String, String) {
    (local.kind.clone(), local.id.clone())
}

fn write_of(kind: &str, id: &str, name: String, meta: Value, approval: Approval, value: Value) -> Write {
    Write { kind: kind.to_string(), id: id.to_string(), name, meta, approval, value }
}

fn hash_of_write(write: &Write) -> String {
    map::hash(&Local { kind: write.kind.clone(), id: write.id.clone(), name: write.name.clone(), meta: write.meta.clone(), approval: write.approval, value: write.value.clone() })
}

fn tombstone(local: &Local, now_ms: i64) -> Write {
    let mut value = local.value.clone();
    if let Some(object) = value.as_object_mut() {
        object.insert("deletedAt".into(), json!(now_ms));
        object.insert("updatedAt".into(), json!(now_ms));
    }
    write_of(&local.kind, &local.id, map::name_of(&local.kind, &value), map::meta_of(&local.kind, &value), local.approval, value)
}

fn trashable(kind: &str) -> bool {
    crate::sync::kinds::ON_BY_DEFAULT.contains(&kind)
}

fn changed_at(plain: &Value) -> i64 {
    plain.get("updatedAt").and_then(Value::as_i64).or_else(|| plain.get("addedAt").and_then(Value::as_i64)).unwrap_or(0)
}

fn local_changed_at(local: &Local) -> i64 {
    local.value.get("updatedAt").and_then(Value::as_i64).or_else(|| local.value.get("addedAt").and_then(Value::as_i64)).unwrap_or(0)
}

impl<'a> Run<'a> {
    fn local_of(&self, part: &PartRef) -> Option<&'a Local> {
        self.locals.get(&(part.kind.clone(), part.id.clone())).copied()
    }

    fn basis_of(&self, kind: &str, id: &str) -> Basis {
        Basis { kind: kind.to_string(), id: id.to_string(), hash: self.locals.get(&(kind.to_string(), id.to_string())).map(|local| map::hash(local)) }
    }

    fn group(&mut self, id: &str) -> &mut Group {
        self.groups.entry(id.to_string()).or_insert_with(|| Group { cipher: id.to_string(), link: None, writes: Vec::new(), basis: Vec::new() })
    }

    fn refuse(&mut self, what: &str, why: &str) {
        self.report.refused_total += 1;
        if self.report.refused.len() < 20 {
            self.report.refused.push(json!({"item": what, "why": why}));
        }
    }

    /// What a vault item is, as a kind of the Kemlock API, and the plaintext the server would hold for it over `base`
    fn compose(&self, local: &Local, base: Option<&Value>, file_held: Option<&str>) -> Result<Mapped, map::Unmapped> {
        items::compose(local, base, self.now_ms, file_held, self.convert)
    }

    fn seal(&self, id: &str, revision: u64, mapped: &Mapped) -> Result<Kem1Item, ()> {
        let uuid = Uuid::parse(id).map_err(|_| ())?;
        let json = Zeroizing::new(serde_json::to_vec(&mapped.plain).map_err(|_| ())?);
        if json.len() + 64 > MOST_CIPHERTEXT {
            return Err(());
        }
        Kem1Item::seal(&self.account.item_wrap, self.account.key_version, uuid, self.owner, mapped.kind, revision, &json).map_err(|_| ())
    }

    /// Plans the write of a vault item: new, or over the server's copy
    fn plan_write(&mut self, local: &Local, id: &str) -> Result<(), &'static str> {
        let cached = self.cache.get(id).cloned();
        let live = cached.as_ref().filter(|c| !c.deleted);
        let file_held = live.and_then(|c| c.file.as_ref()).map(|(sha, _)| sha.clone());
        let mapped = self.compose(local, live.and_then(|c| c.plain.as_ref()), file_held.as_deref()).map_err(|_| "unreadable")?;
        // An item's kind never changes: the server's wins over what the vault's item would be now
        if let Some(c) = &cached
            && c.kind != mapped.kind
        {
            return Err("kind-changed");
        }
        if mapped.file.as_ref().is_some_and(|file| file.bytes.len() > MOST_FILE) {
            return Err("file-too-large");
        }
        let revision = cached.as_ref().map_or(1, |c| c.revision + 1);
        let item = self.seal(id, revision, &mapped).map_err(|()| "too-large")?;
        let hash = sha256(item.ciphertext().unwrap_or(&[]));
        let (file_rec, drop) = match (&mapped.file, live.and_then(|c| c.file.clone())) {
            (Some(file), old) => (Some((file.sha256.clone(), String::new())), old.map(|(_, server)| server).into_iter().collect()),
            (None, old) => (old, Vec::new()),
        };
        let part = PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: map::hash(local) };
        // An item written over one the server holds keeps who made it; one written new, or over a deletion, is this client's own
        let made = live.is_none_or(|c| c.made);
        let new = Cached { kind: mapped.kind.to_string(), format: "kem1".into(), revision, hash, deleted: false, key_version: self.account.key_version, plain: Some(mapped.plain.clone()), part: Some(part), file: file_rec, held: false, retry: false, made };
        self.planned.push(Planned { id: id.to_string(), item, expected: cached.map(|c| c.revision), cached: new, file: mapped.file, drop_files: drop });
        Ok(())
    }

    fn plan_tombstone(&mut self, id: &str) {
        let Some(c) = self.cache.get(id).cloned().filter(|c| !c.deleted) else { return };
        let Ok(uuid) = Uuid::parse(id) else { return };
        let Ok(item) = Kem1Item::tombstone(uuid, self.owner, &c.kind, c.revision + 1, self.account.key_version) else { return };
        let new = Cached { revision: c.revision + 1, hash: [0; 32], deleted: true, plain: None, part: None, file: None, held: false, retry: false, made: false, ..c.clone() };
        let drop = c.file.map(|(_, server)| server).into_iter().collect();
        self.planned.push(Planned { id: id.to_string(), item, expected: Some(c.revision), cached: new, file: None, drop_files: drop });
    }
}

// --- Reading the server ---------------------------------------------------------------------------------------------------------

/// An item of a page, opened as far as it can be
enum Seen {
    /// Not the account's own vault: no part of this run
    Foreign,
    Item { id: String, cached: Box<Cached> },
}

fn classify(run: &Run<'_>, wire: &WireItem) -> Result<Seen, Problem> {
    let bad = || Problem::Kemlock(word::BAD_ANSWER);
    let Ok(owner) = Owner::parse(&wire.owner) else { return Err(bad()) };
    if owner != run.owner || wire.collection_id.is_some() {
        return Ok(Seen::Foreign);
    }
    let id = wire.id.clone();
    if Uuid::parse(&id).is_err() {
        return Err(bad());
    }
    // A Bitwarden copy: opaque, listed by the hash of its bytes
    if wire.format != "kem1" {
        let bytes = if wire.deleted { None } else { Some(wire.ciphertext.as_deref().and_then(|c| b64_decode(c).ok()).ok_or_else(bad)?) };
        let hash = bytes.as_deref().map_or([0; 32], sha256);
        return Ok(Seen::Item { id, cached: Box::new(Cached { kind: wire.kind.clone(), format: wire.format.clone(), revision: wire.revision, hash, deleted: wire.deleted, key_version: wire.key_version, plain: None, part: None, file: None, held: false, retry: false, made: false }) });
    }
    // A tombstone with ciphertext, a live item without, a bad length: the server is not honest
    let kem = wire.kem1().map_err(|_| bad())?;
    let hash = kem.ciphertext().map_or([0; 32], sha256);
    let mut cached = Cached { kind: kem.kind.clone(), format: "kem1".into(), revision: kem.revision, hash, deleted: kem.deleted(), key_version: kem.key_version, plain: None, part: None, file: None, held: false, retry: false, made: false };
    if !kem.deleted() && kem.key_version == run.account.key_version {
        // Opened and checked: the plaintext's own id has to be this item's, or it is not an item of this client's
        if let Ok((_, json)) = kem.open(&run.account.item_wrap)
            && let Ok(plain) = serde_json::from_slice::<Value>(&json)
            && plain.get("id").and_then(Value::as_str).is_some_and(|plain_id| item_uuid(&run.owner, plain_id).to_string() == id)
            && plain.is_object()
        {
            cached.plain = Some(plain);
        }
    }
    Ok(Seen::Item { id, cached: Box::new(cached) })
}

/// Reads every page since the cursor. `full` is a 410, or a person's ask: from nothing.
fn read_pages(session: &mut Session<'_>, run: &mut Run<'_>, since: Option<String>, fresh: &mut BTreeSet<String>, cursor: &mut Option<String>, siblings: &mut usize) -> Result<bool, Problem> {
    let mut since = since;
    loop {
        let page = match session.call(|api| api.sync(since.as_deref()))? {
            Ok(None) => return Ok(true),
            Ok(Some(page)) => page,
            Err(FullSync) => return Ok(false),
        };
        let Page { items, cursor: next, more, siblings: held } = page;
        *siblings += held;
        for wire in &items {
            let Seen::Item { id, cached } = classify(run, wire)? else { continue };
            let cached = *cached;
            if let Some(old) = run.cache.get(&id) {
                if cached.revision < old.revision {
                    return Err(Problem::Kemlock(word::ITEM_ROLLED_BACK));
                }
                if cached.revision == old.revision {
                    // The same revision with other bytes is a server that changed an item without saying so
                    if cached.hash != old.hash || cached.deleted != old.deleted {
                        return Err(Problem::Kemlock(word::ITEM_ROLLED_BACK));
                    }
                    continue;
                }
                // A live item seen deleted before and back: the manifest has to list it (checked with the manifest)
            }
            let part = run.cache.get(&id).and_then(|old| old.part.clone());
            let file = run.cache.get(&id).and_then(|old| old.file.clone());
            let made = run.cache.get(&id).is_some_and(|old| old.made);
            let mut cached = cached;
            cached.part = part;
            cached.file = file;
            cached.made = made;
            run.cache.insert(id.clone(), cached);
            run.touched.insert(id.clone());
            fresh.insert(id);
        }
        *cursor = Some(next.clone());
        if !more {
            return Ok(true);
        }
        since = Some(next);
    }
}

// --- The signed manifest ----------------------------------------------------------------------------------------------------

struct Checked {
    /// What the server holds now, verified: its counter and the SHA-256 of its bytes
    counter: u64,
    sha: Option<String>,
    listed: BTreeMap<String, Entry>,
    none: bool,
}

/// The manifest the server holds, verified under the account's own `sig1` key and held to the highest counter seen
fn fetch_manifest(session: &mut Session<'_>, run: &Run<'_>, seen_counter: u64, seen_sha: Option<&str>) -> Result<Checked, Problem> {
    let invalid = || Problem::Kemlock(word::MANIFEST_INVALID);
    let answer = session.call(|api| api.manifest(&run.owner_text))?;
    let Some(answer) = answer else {
        if seen_counter > 0 {
            // One the server had and no longer has
            return Err(Problem::Kemlock(word::MANIFEST_ROLLED_BACK));
        }
        return Ok(Checked { counter: 0, sha: None, listed: BTreeMap::new(), none: true });
    };
    let text = |name: &str| answer.get(name).and_then(Value::as_str).and_then(|text| b64_decode(text).ok()).ok_or_else(invalid);
    let (bytes, signature) = (text("manifest")?, text("signature")?);
    let manifest = Manifest::parse_signed(&bytes, &signature, &run.account.sig_public).map_err(|_| invalid())?;
    if manifest.owner != run.owner {
        return Err(invalid());
    }
    if manifest.counter < seen_counter {
        return Err(Problem::Kemlock(word::MANIFEST_ROLLED_BACK));
    }
    let sha = hex32(&sha256(&bytes));
    let _ = seen_sha;
    let listed = manifest.entries.iter().map(|entry| (entry.item_id.to_string(), entry.clone())).collect();
    Ok(Checked { counter: manifest.counter, sha: Some(sha), listed, none: false })
}

/// What the manifest says of the items, as the Kemlock app holds it to: an item the server no longer serves, one at a lower
/// revision, or one that came back from deletion with no manifest listing it, stops the run; one no manifest lists is held out of
/// the merge
fn compare(run: &mut Run<'_>, checked: &Checked, fresh: &mut BTreeSet<String>, held_since: &mut BTreeMap<String, i64>, deleted_before: &BTreeSet<String>) -> Result<(), Problem> {
    if checked.none {
        held_since.clear();
        for cached in run.cache.values_mut() {
            cached.held = false;
        }
        return Ok(());
    }
    for (id, entry) in &checked.listed {
        match run.cache.get(id) {
            None if entry.deleted => {}
            None => return Err(Problem::Kemlock(word::ITEM_MISSING)),
            Some(cached) if cached.revision < entry.revision => return Err(Problem::Kemlock(word::ITEM_ROLLED_BACK)),
            Some(cached) if cached.revision == entry.revision && (cached.hash != entry.ciphertext_hash || cached.deleted != entry.deleted) => return Err(Problem::Kemlock(word::ITEM_ROLLED_BACK)),
            Some(_) => {}
        }
    }
    let ids: Vec<String> = run.cache.keys().cloned().collect();
    for id in ids {
        let Some(cached) = run.cache.get(&id).cloned() else { continue };
        let listed_ok = checked.listed.get(&id).is_some_and(|entry| entry.revision == cached.revision);
        if listed_ok {
            if cached.held {
                if let Some(c) = run.cache.get_mut(&id) {
                c.held = false;
            }
                fresh.insert(id.clone());
                run.touched.insert(id.clone());
            }
            held_since.remove(&id);
            continue;
        }
        // Back from deletion with nothing listing it: a server putting an old item back
        if !cached.deleted && deleted_before.contains(&id) && fresh.contains(&id) && !run.accept {
            return Err(Problem::Kemlock(word::ITEM_RESURRECTED));
        }
        if run.accept {
            if let Some(c) = run.cache.get_mut(&id) {
                c.held = false;
            }
            held_since.remove(&id);
            if cached.held {
                fresh.insert(id.clone());
                run.touched.insert(id.clone());
            }
            continue;
        }
        if fresh.contains(&id) || cached.held {
            let since = *held_since.entry(id.clone()).or_insert(run.now_ms);
            if run.now_ms - since >= DAY_MS {
                return Err(Problem::Kemlock(word::ITEMS_UNLISTED));
            }
            if let Some(c) = run.cache.get_mut(&id) {
                c.held = true;
            }
            run.touched.insert(id.clone());
            fresh.remove(&id);
        }
    }
    Ok(())
}

// --- Deciding -----------------------------------------------------------------------------------------------------------------

/// A server item that reads as an item of the vault: its plaintext, and what the vault holds for it
fn paired<'a>(run: &Run<'a>, id: &str, cached: &Cached) -> Option<&'a Local> {
    if let Some(part) = &cached.part {
        return run.local_of(part);
    }
    // A vault item an adoption paired with this item (the move), or one with the plaintext's own id, not linked to anything yet
    if let Some(key) = run.by_part.iter().find(|(_, other)| other.as_str() == id).map(|(key, _)| key.clone()) {
        return run.locals.get(&key).copied();
    }
    let plain = cached.plain.as_ref()?;
    let vault_kind = items::reads(&cached.kind, plain)?;
    let plain_id = plain.get("id")?.as_str()?;
    let local = run.locals.get(&(vault_kind.to_string(), plain_id.to_string())).copied()?;
    (!run.by_part.contains_key(&key_of(local)) || run.by_part.get(&key_of(local)).is_some_and(|other| other == id)).then_some(local)
}

fn decide(session: &mut Session<'_>, run: &mut Run<'_>, fresh: &BTreeSet<String>, outcome_churn: &mut (usize, usize)) -> Result<(), Problem> {
    let ids: Vec<String> = fresh.iter().cloned().collect();
    for id in ids {
        let Some(cached) = run.cache.get(&id).cloned() else { continue };
        if cached.format != "kem1" || cached.part.is_none() && cached.plain.is_none() {
            // Not ours to read: left as the server has it, listed in the manifest
            if cached.plain.is_none() && cached.format == "kem1" && !cached.deleted {
                run.report.left_alone += 1;
            }
            continue;
        }
        if cached.deleted {
            gone_there(run, &id, &cached, outcome_churn);
            continue;
        }
        let Some(plain) = cached.plain.clone() else { continue };
        let Some(vault_kind) = items::reads(&cached.kind, &plain) else {
            run.report.left_alone += 1;
            if let Some(c) = run.cache.get_mut(&id) {
                c.part = None;
            }
            continue;
        };
        let local = paired(run, &id, &cached);
        // A protected note's file, when the item is one the vault holds
        let mut file: Option<Zeroizing<Vec<u8>>> = None;
        if vault_kind == "protected"
            && local.is_some()
            && let Some(attachment) = items::attachment_of(&plain)
            && let (Some(server), Some(key)) = (attachment.get("kemlockFile").and_then(Value::as_str).filter(|f| crate::sync::api::is_uuid(f)), items::attachment_key(&attachment))
        {
            let size = attachment.get("size").and_then(Value::as_u64).unwrap_or(0) as usize;
            if size <= MOST_FILE
                && let Some(bytes) = session.call(|api| api.file_download(&id, server, kma1::sealed_len(size)))?
                && let Ok(plain_bytes) = kma1::decrypt(&key, &bytes, size)
            {
                file = Some(plain_bytes);
            }
        }
        match local {
            None => new_from_server(run, &id, &cached, &plain, outcome_churn),
            Some(local) => both(run, &id, &cached, &plain, local, file.as_deref().map(|f| &f[..]))?,
        }
    }
    Ok(())
}

fn gone_there(run: &mut Run<'_>, id: &str, cached: &Cached, churn: &mut (usize, usize)) {
    let Some(part) = cached.part.clone() else { return };
    churn.0 += 1;
    let local = run.local_of(&part);
    let mut writes = Vec::new();
    let mut basis = Vec::new();
    if let Some(local) = local.filter(|local| !map::deleted(local) && trashable(&local.kind)) {
        // Taken to the vault's own trash only if it did not change here since: a change here wins and goes back over the tombstone
        if map::hash(local) == part.hash {
            writes.push(tombstone(local, run.now_ms));
            run.trashed_now.insert(key_of(local));
            basis.push(run.basis_of(&local.kind, &local.id));
            run.report.trashed_here += 1;
        } else {
            run.by_part.remove(&key_of(local));
            if let Some(c) = run.cache.get_mut(id) {
                c.part = None;
            }
            return;
        }
    }
    let kept = local.is_some_and(|local| writes.is_empty() && !map::deleted(local));
    if kept {
        // A key, a certificate or a file is never destroyed because a server said so: it stays, and is sent again
        run.report.left_alone += 1;
    }
    if let Some(local) = local {
        run.by_part.remove(&key_of(local));
    }
    if let Some(c) = run.cache.get_mut(id) {
        c.part = None;
        c.plain = None;
    }
    let group = run.group(id);
    group.writes.extend(writes);
    group.basis.extend(basis);
}

fn new_from_server(run: &mut Run<'_>, id: &str, cached: &Cached, plain: &Value, churn: &mut (usize, usize)) {
    match items::take(&cached.kind, plain, None, None, run.now_ms, run.convert) {
        Taken::Item(read) if !read.needs_file => {
            // An id that another item holds is not this one
            if run.locals.contains_key(&(read.kind.to_string(), read.id.clone())) || run.by_part.contains_key(&(read.kind.to_string(), read.id.clone())) {
                run.report.left_alone += 1;
                return;
            }
            churn.1 += 1;
            let write = write_of(read.kind, &read.id, read.name, read.meta, Approval::WhileOpen, read.value);
            let part = PartRef { kind: write.kind.clone(), id: write.id.clone(), hash: hash_of_write(&write) };
            run.by_part.insert((write.kind.clone(), write.id.clone()), id.to_string());
            if let Some(c) = run.cache.get_mut(id) {
                c.part = Some(part);
            }
            let basis = Basis { kind: write.kind.clone(), id: write.id.clone(), hash: None };
            let group = run.group(id);
            group.writes.push(write);
            group.basis.push(basis);
            run.report.created_here += 1;
            run.report.received += 1;
        }
        _ => run.report.left_alone += 1,
    }
}

/// The vault item and the server's both exist
fn both(run: &mut Run<'_>, id: &str, cached: &Cached, plain: &Value, local: &Local, file: Option<&[u8]>) -> Result<(), Problem> {
    if let Some(c) = run.cache.get_mut(id) {
        c.retry = false;
    }
    let part = cached.part.clone();
    let linked_hash = part.as_ref().map(|part| part.hash.clone());
    let changed_here = linked_hash.as_ref().is_none_or(|hash| *hash != map::hash(local));
    let server_changed = true;
    let _ = server_changed;
    let taken = items::take(&cached.kind, plain, Some(local), file, run.now_ms, run.convert);
    let read = match taken {
        Taken::Item(read) if !read.needs_file => read,
        Taken::Item(_) => {
            // The file is not there or did not open: nothing of this note is taken now, and it is looked at again at the next run
            run.by_part.insert(key_of(local), id.to_string());
            if let Some(c) = run.cache.get_mut(id) {
                c.retry = true;
            }
            run.touched.insert(id.to_string());
            return Ok(());
        }
        Taken::Untouched => {
            run.report.left_alone += 1;
            return Ok(());
        }
        Taken::Conflict => {
            // It no longer reads as the item it was: the vault's stays, nothing is deleted on either side
            run.report.conflicts += 1;
            run.by_part.insert(key_of(local), id.to_string());
            if let Some(c) = run.cache.get_mut(id) {
                c.part = Some(PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: map::hash(local) });
            }
            return Ok(());
        }
    };
    run.by_part.insert(key_of(local), id.to_string());
    let theirs = Local { kind: read.kind.to_string(), id: read.id.clone(), name: read.name.clone(), meta: read.meta.clone(), approval: local.approval, value: read.value.clone() };
    if map::deleted(local) {
        // In the vault's trash and still live on the server. If the server's copy is what the vault held, the trash goes there (the tombstone is planned
        // with the rest of what is here); if it was changed over there, that change is not deleted: it stays, and so does the vault's trashed copy
        if map::hash(&theirs) != map::hash(local) {
            run.by_part.remove(&key_of(local));
            if let Some(c) = run.cache.get_mut(id) {
                c.part = None;
            }
        }
        return Ok(());
    }
    // A counter never goes back and a code spent here stays spent: what is read over the vault's item is held to that, so the server's own copy
    // is read apart, to tell when the server is the one behind and has to be told
    let clamped_kind = matches!(local.kind.as_str(), crate::items::KIND_ACCOUNT | crate::items::KIND_BACKUP_CODES);
    let server_side = match clamped_kind.then(|| items::take(&cached.kind, plain, None, None, run.now_ms, run.convert)) {
        Some(Taken::Item(bare)) => Local { value: bare.value.clone(), ..theirs.clone() },
        _ => theirs.clone(),
    };
    let behind = server_side.value != theirs.value;
    let same = map::hash(&theirs) == map::hash(local);
    if same {
        // Nothing differs: only the link moves on
        if let Some(c) = run.cache.get_mut(id) {
            c.part = Some(PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: map::hash(local) });
        }
        if behind {
            send_behind(run, id, local);
        }
        return Ok(());
    }
    if !changed_here || linked_hash.is_none() && !both_differ(local, &theirs) {
        take_theirs(run, id, local, theirs.clone());
        if behind {
            send_behind(run, id, &theirs);
        }
        return Ok(());
    }
    // Changed on both sides: the later change wins as a whole, and what must never be lost is kept
    run.report.conflicts += 1;
    let server_wins = changed_at(plain) > local_changed_at(local);
    let mut merged = if server_wins { theirs.clone() } else { local.clone() };
    merge_losing(&mut merged, if server_wins { local } else { &theirs });
    // The same by what is compared and by everything: a history kept or a spent code marked is a change the other side has not seen
    let merged_is_server = map::hash(&merged) == map::hash(&server_side) && merged.value == server_side.value;
    let merged_is_local = map::hash(&merged) == map::hash(local) && merged.value == local.value;
    if !merged_is_local {
        take_theirs(run, id, local, merged.clone());
    } else if let Some(c) = run.cache.get_mut(id) {
        c.part = Some(PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: map::hash(local) });
    }
    if !merged_is_server {
        // The server's copy is replaced by the merge, over the revision it holds
        if run.plan_write(&merged, id).is_err() {
            run.refuse(&format!("{}.{}", local.kind, local.id), "unreadable");
        }
        run.report.sent += 1;
    }
    Ok(())
}

/// The server holds less than the vault keeps (a counter that is higher here, a code spent here): it is sent the vault's
fn send_behind(run: &mut Run<'_>, id: &str, local: &Local) {
    match run.plan_write(local, id) {
        Ok(()) => run.report.sent += 1,
        Err(why) => run.refuse(&format!("{}.{}", local.kind, local.id), why),
    }
}

fn both_differ(local: &Local, theirs: &Local) -> bool {
    map::hash(local) != map::hash(theirs)
}

/// Keeps what the losing copy had that the winner must not lose: a password that was in use, a code that was spent, a counter
fn merge_losing(winner: &mut Local, loser: &Local) {
    match winner.kind.as_str() {
        crate::items::KIND_PASSWORD => {
            let (Some(mut won), Some(lost)) = (map::password(winner), map::password(loser)) else { return };
            if lost.password.as_str() != won.password.as_str() && !lost.password.is_empty() && !won.history.iter().any(|old| old.password.as_str() == lost.password.as_str()) {
                won.history.push(crate::items::OldPassword { password: lost.password.clone(), changed_at: lost.updated_at.unwrap_or(0) });
                won.history.truncate(5);
            }
            if let Ok(value) = serde_json::to_value(&won) {
                winner.value = value;
            }
        }
        crate::items::KIND_ACCOUNT => {
            let (ours, theirs) = (winner.value.get("counter").and_then(Value::as_i64), loser.value.get("counter").and_then(Value::as_i64));
            if theirs > ours {
                winner.value["counter"] = json!(theirs);
            }
        }
        crate::items::KIND_BACKUP_CODES => {
            let spent: Vec<Value> = loser.value.get("codes").and_then(Value::as_array).into_iter().flatten().filter(|c| c.get("used") == Some(&json!(true))).map(|c| c["code"].clone()).collect();
            if let Some(codes) = winner.value.get_mut("codes").and_then(Value::as_array_mut) {
                for code in codes.iter_mut() {
                    if spent.contains(&code["code"]) {
                        code["used"] = json!(true);
                    }
                }
            }
        }
        _ => {}
    }
}

fn take_theirs(run: &mut Run<'_>, id: &str, local: &Local, theirs: Local) {
    let write = write_of(&local.kind, &local.id, theirs.name.clone(), theirs.meta.clone(), local.approval, theirs.value.clone());
    let part = PartRef { kind: local.kind.clone(), id: local.id.clone(), hash: hash_of_write(&write) };
    if let Some(c) = run.cache.get_mut(id) {
        c.part = Some(part);
    }
    let basis = run.basis_of(&local.kind, &local.id);
    let group = run.group(id);
    group.writes.push(write);
    group.basis.push(basis);
    run.report.received += 1;
}

// --- Sending ------------------------------------------------------------------------------------------------------------------

/// Plans what the vault has that the server lacks or has differently
fn plan_local(run: &mut Run<'_>, connection: &Connection, fresh: &BTreeSet<String>, redo: &BTreeSet<String>, churn: &mut (usize, usize)) {
    let mut locals: Vec<&Local> = run.locals.values().copied().collect();
    locals.sort_by(|a, b| (&a.kind, &a.id).cmp(&(&b.kind, &b.id)));
    for local in locals {
        let key = key_of(local);
        let linked = run.by_part.get(&key).cloned();
        match (linked, map::deleted(local)) {
            (Some(id), true) => {
                // In the vault's trash: gone from the server, which has no trash of its own
                if run.cache.get(&id).is_some_and(|c| !c.deleted) {
                    run.plan_tombstone(&id);
                    churn.0 += 1;
                    run.report.trashed_there += 1;
                }
                run.by_part.remove(&key);
            }
            (Some(id), false) => {
                let Some(c) = run.cache.get(&id).cloned() else { continue };
                if c.deleted || c.held {
                    continue;
                }
                // What was read this run was decided with the vault's item in front of it: a merge that had to be sent is planned already
                // (an item the move's check found different is sent again whatever was read: the server's copy is not what was sent)
                let again = redo.contains(&id);
                if (fresh.contains(&id) && !again) || run.planned.iter().any(|planned| planned.id == id) {
                    continue;
                }
                let moved = again || c.part.as_ref().is_none_or(|part| part.hash != map::hash(local));
                if moved {
                    match run.plan_write(local, &id) {
                        Ok(()) => run.report.sent += 1,
                        Err(why) => run.refuse(&format!("{}.{}", local.kind, local.id), why),
                    }
                }
            }
            (None, true) => {}
            (None, false) if run.trashed_now.contains(&key) => {}
            (None, false) => {
                if connection.choice_for_new(&local.kind, &local.id, local.approval) == "off" {
                    continue;
                }
                let Some(kem_kind) = items::kem_kind_for(local) else { continue };
                let _ = kem_kind;
                let id = item_uuid(&run.owner, &local.id).to_string();
                // An item the server already holds under this id that is not paired: paired above, or a clash
                if let Some(c) = run.cache.get(&id)
                    && !c.deleted
                {
                    continue;
                }
                match run.plan_write(local, &id) {
                    Ok(()) => {
                        run.by_part.insert(key, id.clone());
                        run.touched.insert(id);
                        run.report.created_there += 1;
                    }
                    Err(why) => run.refuse(&format!("{}.{}", local.kind, local.id), why),
                }
            }
        }
    }
    // Links whose vault item is no longer one that syncs (turned off, removed): a copy this client made leaves the server, the vault's stays.
    // An item another app made, and the vault took in, is only let go: it stays on the server as it is, unlinked from the vault's item.
    let leaving: Vec<(String, String)> = run.linked.iter().filter(|(key, cipher)| !run.locals.contains_key(key) && run.by_part.get(key) == Some(cipher)).map(|(key, cipher)| (key.0.clone(), cipher.clone())).collect();
    for (_, id) in leaving {
        let Some(c) = run.cache.get(&id).filter(|c| !c.deleted && c.format == "kem1") else { continue };
        if c.made {
            run.plan_tombstone(&id);
            churn.0 += 1;
            run.report.trashed_there += 1;
        } else {
            run.by_part.retain(|_, other| *other != id);
            if let Some(c) = run.cache.get_mut(&id) {
                c.part = None;
                c.plain = None;
            }
            run.touched.insert(id);
        }
    }
}

/// Sends the plan: files first, then batches of puts and then of deletions. `Ok(false)` is a stale revision: read again and start over.
fn send(session: &mut Session<'_>, run: &mut Run<'_>) -> Result<bool, Problem> {
    let mut planned = std::mem::take(&mut run.planned);
    // Files before the item that names them, so that no note names a file the server lacks
    for plan in planned.iter_mut() {
        let Some(file) = plan.file.take() else { continue };
        let attachment = items::attachment_of(plan.cached.plain.as_ref().unwrap_or(&Value::Null));
        let Some(key) = attachment.as_ref().and_then(items::attachment_key) else { continue };
        let Ok(sealed) = kma1::encrypt(&key, &file.bytes, MOST_FILE) else { continue };
        let uploaded = session.call(|api| match api.file_start(&plan.id, sealed.len() as u64)? {
            Err(refusal) => Ok(Err(refusal)),
            Ok(slot) if slot.presigned => Ok(Err(FileRefusal::Bucket)),
            Ok(slot) => api.file_upload(&plan.id, &slot.file, sealed.clone()).map(|done| done.map(|()| slot.file)),
        })?;
        match uploaded {
            Ok(server) => {
                if let Some(plain) = plan.cached.plain.as_mut() {
                    items::name_file(plain, &server);
                }
                plan.cached.file = Some((file.sha256.clone(), server));
                // Sealed again with the file named: the item's revision is the same, its ciphertext the one that goes
                let mapped = Mapped { kind: "note", plain: plan.cached.plain.clone().unwrap_or(Value::Null), file: None };
                if let Ok(item) = run.seal(&plan.id, plan.cached.revision, &mapped) {
                    plan.cached.hash = sha256(item.ciphertext().unwrap_or(&[]));
                    plan.item = item;
                }
            }
            Err(refusal) => {
                let why = match refusal {
                    FileRefusal::TooBig(_) => "file-too-large",
                    FileRefusal::Bucket => word::FILES_BUCKET,
                    FileRefusal::NotAllowed => "files-refused",
                    FileRefusal::Refused => "files-refused",
                };
                run.refuse(&plan.id, why);
                // The item goes without its file this time: the vault's copy stays, and the file goes when the server takes it
                plan.cached.plain = None;
                plan.id.clear();
            }
        }
    }
    planned.retain(|plan| !plan.id.is_empty());
    // Puts before deletions: a run cut short never leaves less than it found
    planned.sort_by_key(|plan| plan.cached.deleted);
    let mut at = 0;
    while at < planned.len() {
        let (mut count, mut bytes) = (0, 0);
        let mut wires = Vec::new();
        while at + count < planned.len() && count < BATCH_ITEMS {
            let wire = planned[at + count].item.to_wire();
            let size = wire.to_json().len();
            if count > 0 && bytes + size > BATCH_BYTES {
                break;
            }
            bytes += size;
            wires.push(wire);
            count += 1;
        }
        let writes: Vec<(Option<u64>, &WireItem)> = planned[at..at + count].iter().zip(&wires).map(|(plan, wire)| (plan.expected, wire)).collect();
        let answered = session.call(|api| api.batch(&writes))?;
        match answered {
            Ok(stored) => {
                if stored.len() != count || stored.iter().zip(&planned[at..at + count]).any(|(item, plan)| item.get("revision").and_then(Value::as_u64) != Some(plan.cached.revision)) {
                    return Err(Problem::Kemlock(word::BAD_ANSWER));
                }
            }
            Err(Refused::Stale { .. }) => return Ok(false),
            Err(Refused::TooLarge) | Err(Refused::Invalid(_)) => {
                // One item the server will not take stops the whole batch: left out, and the rest tried again by the next run
                run.report.left_alone += 0;
                return Err(Problem::Kemlock(word::BAD_ANSWER));
            }
        }
        at += count;
    }
    for plan in planned {
        for server in &plan.drop_files {
            if !server.is_empty() {
                let _ = session.call(|api| api.file_delete(&plan.id, server));
            }
        }
        if let Some(hash) = plan.cached.plain.as_ref().map(items::canonical) {
            run.sent_hashes.insert(plan.id.clone(), hex32(&sha256(&hash)));
            run.sent_revisions.insert(plan.id.clone(), plan.cached.revision);
        }
        run.cache.insert(plan.id.clone(), plan.cached);
        run.touched.insert(plan.id);
    }
    Ok(true)
}

/// Signs and sends a manifest of everything the cache holds that is not held (`spec-protocol.md` 6.4)
fn sign_manifest(session: &mut Session<'_>, run: &Run<'_>, counter: &mut u64, sha: &mut Option<String>) -> Result<(), Problem> {
    // What another device's manifest lists that this run's cache does not hold, or holds at an older revision: written after this run read, and
    // kept in the one signed over it, or the app that wrote it would find its item unlisted
    let mut theirs: BTreeMap<String, Entry> = BTreeMap::new();
    for _ in 0..ATTEMPTS {
        let mut entries: BTreeMap<String, Entry> = run.cache.iter().filter(|(_, cached)| !cached.held).filter_map(|(id, cached)| cached.entry(id).map(|entry| (id.clone(), entry))).collect();
        for (id, entry) in &theirs {
            if run.cache.get(id).is_none_or(|cached| cached.revision < entry.revision) {
                entries.insert(id.clone(), entry.clone());
            }
        }
        let manifest = Manifest::new(run.owner, *counter + 1, entries.into_values().collect()).map_err(|_| Problem::Kemlock(word::MANIFEST_INVALID))?;
        let bytes = manifest.to_bytes();
        let signature = manifest.sign(&run.account.sig_private).map_err(|_| Problem::Kemlock(word::MANIFEST_INVALID))?;
        match session.call(|api| api.put_manifest(&run.owner_text, &bytes, &signature))? {
            Ok(()) => {
                *counter += 1;
                *sha = Some(hex32(&sha256(&bytes)));
                return Ok(());
            }
            Err(held) => {
                // Another device signed first: its counter is the one to go above, once its manifest checks out
                let checked = fetch_manifest(session, run, *counter, None)?;
                *counter = checked.counter.max(held.unwrap_or(0));
                theirs = checked.listed;
            }
        }
    }
    Err(Problem::Kemlock(word::MANIFEST_INVALID))
}

// --- The move's check ------------------------------------------------------------------------------------------------------

/// Reads everything again from nothing and holds it to what the move sent (`spec-protocol.md` 10.2, step 4)
fn check_move(session: &mut Session<'_>, run: &Run<'_>, record: &mut MoveRecord) -> Result<Vec<String>, Problem> {
    // Per item: its revision, and what it opens to unless it is deleted
    let mut found: BTreeMap<String, (u64, Option<Value>)> = BTreeMap::new();
    let mut since: Option<String> = None;
    while let Ok(Some(page)) = session.call(|api| api.sync(since.as_deref()))? {
        for wire in &page.items {
            let Ok(kem) = wire.kem1() else { continue };
            if kem.owner != run.owner {
                continue;
            }
            if kem.deleted() {
                found.insert(wire.id.clone(), (kem.revision, None));
            } else if let Ok((_, json)) = kem.open(&run.account.item_wrap)
                && let Ok(plain) = serde_json::from_slice::<Value>(&json)
            {
                found.insert(wire.id.clone(), (kem.revision, Some(plain)));
            }
        }
        if !page.more {
            break;
        }
        since = Some(page.cursor);
    }
    let mut differs = Vec::new();
    let mut edited = Vec::new();
    for (id, hash) in &record.sent {
        match found.get(id) {
            Some((_, Some(plain))) if hex32(&sha256(&items::canonical(plain))) == *hash => {}
            // Written at a later revision than the move's, or deleted since: someone changed it after the copy, which is no mismatch
            Some((revision, _)) if record.revisions.get(id).is_some_and(|sent| revision > sent) => edited.push(id.clone()),
            _ => differs.push(id.clone()),
        }
    }
    for id in edited {
        record.sent.remove(&id);
        record.revisions.remove(&id);
    }
    Ok(differs)
}

// --- A run --------------------------------------------------------------------------------------------------------------------

pub fn run(http: &mut dyn Http, convert: &dyn Convert, input: Input, persist: &Persist<'_>) -> Outcome {
    let Input { connection, access, links, mut locals, accept, full, now_ms, local_unreadable, links_unreadable } = input;
    let mut outcome = Outcome { problem: None, access: None, refresh: None, revision: None, groups: Vec::new(), report: Report::default(), churn: 0, accepted: accept, purge: Vec::new(), no_files: None, files_read: connection.files_read, pending: connection.pending.clone(), kemlock: None };
    if links_unreadable {
        outcome.problem = Some(Problem::LinksUnreadable);
    } else if local_unreadable > 0 {
        outcome.problem = Some(Problem::LocalUnreadable(local_unreadable));
    } else if connection.kemlock.is_none() {
        outcome.problem = Some(Problem::CannotOpen);
    }
    if outcome.problem.is_none()
        && let Some(state) = &connection.kemlock
    {
        let server: Server = connection.server();
        match (account::open_state(&connection.user_key, &connection.user_id, state), DpopKey::from_hex(&state.dpop_key)) {
            (Ok(account), Some(key)) => {
                let mut session = Session {
                    api: KemApi::new(http, &server, &key),
                    connection: &connection,
                    refresh: connection.refresh.clone().map(Zeroizing::new),
                    until_ms: access.as_ref().map_or(0, |a| a.until_ms),
                    now_ms,
                    renewed: false,
                    persist,
                };
                session.api.access = access.map(|a| a.token);
                let owner = Owner::user(account.id);
                let mut news = News::default();
                let result = attempts(&mut session, convert, &connection, account, owner, &links, &locals, accept, full, now_ms, &mut outcome, &mut news);
                outcome.problem = result.err();
                outcome.access = session.api.access.clone().map(|token| Access { token, until_ms: session.until_ms });
                outcome.refresh = session.refresh.clone();
                outcome.kemlock = Some(news);
            }
            (Err(problem), _) => outcome.problem = Some(problem),
            (_, None) => outcome.problem = Some(Problem::CannotOpen),
        }
    }
    for local in &mut locals {
        map::wipe(local);
    }
    outcome
}

#[allow(clippy::too_many_arguments)]
fn attempts(session: &mut Session<'_>, convert: &dyn Convert, connection: &Connection, account: Account, owner: Owner, links: &[Link], locals: &[Local], accept: bool, full: bool, now_ms: i64, outcome: &mut Outcome, news: &mut News) -> Result<(), Problem> {
    let state = connection.kemlock.clone().unwrap_or_default();
    let mut account = Some(account);
    for _ in 1..=ATTEMPTS {
        let keys = match account.take() {
            Some(keys) => keys,
            None => account::open_state(&connection.user_key, &connection.user_id, &state)?,
        };
        let mut run = Run {
            account: keys,
            owner,
            owner_text: owner.to_string(),
            state_cursor: state.cursor.clone(),
            convert,
            now_ms,
            accept,
            cache: links.iter().filter_map(|link| Cached::from_link(link).map(|cached| (link.cipher.clone(), cached))).collect(),
            touched: BTreeSet::new(),
            locals: locals.iter().filter(|local| items::kem_kind_for(local).is_some() && local.meta.get("exportable") != Some(&Value::Bool(false))).map(|local| (key_of(local), local)).collect(),
            by_part: HashMap::new(),
            groups: BTreeMap::new(),
            planned: Vec::new(),
            report: Report::default(),
            sent_hashes: BTreeMap::new(),
            sent_revisions: BTreeMap::new(),
            first_pull: links.is_empty(),
            linked: Vec::new(),
            trashed_now: BTreeSet::new(),
        };
        for link in links {
            for part in &link.parts {
                run.by_part.insert((part.kind.clone(), part.id.clone()), link.cipher.clone());
                run.linked.push(((part.kind.clone(), part.id.clone()), link.cipher.clone()));
            }
        }
        // Items this client was told to adopt (the move: Kemlock's own item for a login both hold) are paired before anything is read
        for adoption in &state.adopt {
            let id = item_uuid(&owner, &adoption.entry).to_string();
            if !run.by_part.contains_key(&(adoption.kind.clone(), adoption.id.clone())) && !run.cache.contains_key(&id) {
                run.by_part.insert((adoption.kind.clone(), adoption.id.clone()), id);
            }
        }
        match steps(session, &mut run, connection, &state, accept, full, now_ms, outcome, news)? {
            Step::Done(report) => {
                outcome.report = report;
                return Ok(());
            }
            Step::Again => {}
        }
    }
    Err(Problem::Kemlock(word::BAD_ANSWER))
}

enum Step {
    Done(Report),
    /// Another device wrote first: read again from the stored cursor
    Again,
}

#[allow(clippy::too_many_arguments)]
fn steps(session: &mut Session<'_>, run: &mut Run<'_>, connection: &Connection, state: &super::state::KemlockState, accept: bool, full: bool, now_ms: i64, outcome: &mut Outcome, news: &mut News) -> Result<Step, Problem> {
    let mut fresh: BTreeSet<String> = BTreeSet::new();
    let deleted_before: BTreeSet<String> = run.cache.iter().filter(|(_, c)| c.deleted).map(|(id, _)| id.clone()).collect();
    let mut cursor: Option<String> = None;
    let mut siblings = 0;
    // Read, from the stored cursor; from nothing when a person asked for it or the server says so, once
    let from = if accept || (full && run.cache.is_empty()) { None } else { run.state_cursor.clone() };
    let ok = read_pages(session, run, from.clone(), &mut fresh, &mut cursor, &mut siblings)?;
    if !ok {
        let mut again = None;
        fresh.clear();
        let ok = read_pages(session, run, None, &mut fresh, &mut again, &mut siblings)?;
        if !ok {
            return Err(Problem::Kemlock(word::BAD_ANSWER));
        }
        cursor = again;
    }
    if siblings > 0 {
        run.report.refuse("siblings", word::SIBLINGS);
    }
    // Items the cache holds as held, and ones not yet decided, are looked at again with the manifest
    for (id, cached) in &run.cache {
        if cached.held || cached.retry {
            fresh.insert(id.clone());
        }
    }
    let mut checked = fetch_manifest(session, run, state.manifest_counter, state.manifest_sha256.as_deref())?;
    let mut held_since = state.held.clone();
    if let Err(Problem::Kemlock(why)) = compare(run, &checked, &mut fresh, &mut held_since, &deleted_before) {
        // The manifest lists something this run's pages lack, or at a revision it did not read: another device may have written and signed between
        // the two reads. Reading from where the pages left off settles it; only a manifest still ahead of the server's items is the server's doing.
        if why != word::ITEM_ROLLED_BACK && why != word::ITEM_MISSING {
            return Err(Problem::Kemlock(why));
        }
        if !read_pages(session, run, cursor.clone().or(from.clone()), &mut fresh, &mut cursor, &mut siblings)? {
            return Err(Problem::Kemlock(word::BAD_ANSWER));
        }
        checked = fetch_manifest(session, run, state.manifest_counter, state.manifest_sha256.as_deref())?;
        compare(run, &checked, &mut fresh, &mut held_since, &deleted_before)?;
    }
    let mut counter = checked.counter.max(state.manifest_counter);
    let mut sha = checked.sha.clone().or_else(|| state.manifest_sha256.clone());

    // The guard: many items gone, or arriving, at once or over the days
    let mut churn = (0usize, 0usize);
    decide(session, run, &fresh, &mut churn)?;
    let links_total = run.cache.values().filter(|c| c.part.is_some()).count();
    let redo: BTreeSet<String> = state.moved.as_ref().filter(|record| record.finished_ms.is_none()).map(|record| record.redo.iter().cloned().collect()).unwrap_or_default();
    plan_local(run, connection, &fresh, &redo, &mut churn);
    if !accept && !run.first_pull {
        let (removed, arriving) = churn;
        let total = removed + arriving;
        let direction = |total: usize| if removed >= arriving { Problem::ManyGone(total) } else { Problem::ManyNew(total) };
        if removed > FEW || (removed > 1 && removed * 10 > links_total) || arriving > FEW {
            return Err(direction(total));
        }
        if total > 0 && connection.recent_total(now_ms) + total > (4 * FEW).max(links_total / 10) {
            return Err(direction(connection.recent_total(now_ms) + total));
        }
    }
    outcome.churn = if run.first_pull { 0 } else { u32::try_from(churn.0 + churn.1).unwrap_or(u32::MAX) };

    let wrote = !run.planned.is_empty();
    let moving = state.moved.as_ref().filter(|record| record.finished_ms.is_none()).cloned();
    if !send(session, run)? {
        return Ok(Step::Again);
    }
    if wrote || accept && checked.listed.len() != run.cache.len() {
        sign_manifest(session, run, &mut counter, &mut sha)?;
    }
    if let Some(mut record) = moving {
        record.sent.extend(std::mem::take(&mut run.sent_hashes));
        record.revisions.extend(std::mem::take(&mut run.sent_revisions));
        let differs = check_move(session, run, &mut record)?;
        if differs.is_empty() {
            record.finished_ms = Some(now_ms);
            record.redo.clear();
        } else {
            record.redone += 1;
            record.redo = differs;
            news.moved = Some(record);
            return Err(Problem::Kemlock(word::MOVE_CHECK));
        }
        news.moved = Some(record);
    }
    // Links: every item this run read or wrote, and the parts that went
    let touched: Vec<String> = run.touched.iter().cloned().collect();
    for id in touched {
        let Some(cached) = run.cache.get(&id) else { continue };
        let link = cached.to_link(&id);
        let group = run.groups.entry(id.clone()).or_insert_with(|| Group { cipher: id.clone(), link: None, writes: Vec::new(), basis: Vec::new() });
        group.link = Some(link);
    }
    // A written group whose link says the item is gone (a tombstone) keeps its writes: the vault's trash is the vault's
    outcome.groups = std::mem::take(&mut run.groups).into_values().collect();
    news.cursor = cursor.or_else(|| run.state_cursor.clone());
    news.manifest_counter = Some(counter);
    news.manifest_sha256 = sha;
    news.held = Some(held_since.into_iter().filter(|(id, _)| run.cache.get(id).is_some_and(|c| c.held)).collect());
    if !state.adopt.is_empty() {
        news.adopted = true;
    }
    Ok(Step::Done(std::mem::take(&mut run.report)))
}

/// Keys for tests and the interop: the item wrap of an account
#[allow(dead_code)]
pub fn item_wrap_of(account: &Account) -> &Key {
    &account.item_wrap
}
