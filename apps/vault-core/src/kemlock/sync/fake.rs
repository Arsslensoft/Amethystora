//! A Kemlock Server of our own, in memory, that answers `/kem/v1` as `spec-protocol.md` describes it, for tests: honest by
//! default, and hostile when told (`Attack`). It really verifies what the real server verifies: DPoP proofs (three parts, `typ`,
//! a `jwk` with no private member, the EdDSA signature, `htm`, `htu` against its own `DOMAIN` plus the path, `iat` within 60 s, a
//! `jti` it has not seen, `ath` on a call with a token, the nonce), tokens bound to the proof key's thumbprint, refresh tokens that
//! rotate and end the session when one is used twice, OPAQUE (the server half, with the client's suite and context), `items:batch`
//! (all or none, `expectedRevision`, revision = stored + 1, kind and format never change), the manifest (signature under the
//! account's own `sig1` key, a counter that only rises) and files (`KMA1`, the announced length).
//!
//! It keeps every request (`seen`), so a test can say what left the machine, and it never opens a socket: it is an `Http`.
//!
//! # Using it from another crate (`feature = "fake-server"`)
//!
//! ```ignore
//! let mut server = FakeKemlock::new("http://127.0.0.1:18299");        // its DOMAIN, which is also the address it answers at
//! let id = server.make_account("sam@example.test", "a password");     // a Kemlock-only account (OPAQUE + keys, as a client makes one)
//! let id = server.make_compatible_account("bw@example.test", "pw");   // an account the Bitwarden API made: no Kemlock keys yet
//! let address = server.server();                                      // `sync::address::Server` for it
//! sign_in(&mut server, &attempt, &fake::derive, &fake::bitwarden_derive)   // the stand-in Argon2id / PBKDF2 the accounts were made with
//! server.plant_item(email, "login", &plain);  server.plant_bw(email, "login", &cipher);  server.plant_tombstone(email, &id);
//! server.sign_manifest(email);                // as the Kemlock app does after it writes: lists every item the server holds
//! server.attack(Attack::StaleOnce);           // one of the hostile behaviours; `clear_attacks()` ends them
//! server.plain_of(email, &item_id);           // what an item opens to, from the test side
//! server.seen                                 // every request, with its headers (names in lower case)
//! ```
//!
//! `FakeKemlock` is an `Http` (`call`). Its Argon2id and Bitwarden PBKDF2 are stand-ins (`derive`, `bitwarden_derive`): the tests give the
//! client the same closures, so no test pays for a 64 MiB hash (one test runs the real one). `require_totp`, `require_email_code`,
//! `change_security_stamp`, `expire_access_tokens`, `rotate_nonce` and `clock_offset` set up the second steps, a dead session, a token
//! that ran out, a new nonce and a clock that is off.

use std::collections::{BTreeMap, HashMap, HashSet};

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::kemlock::bundle::Bundle;
use crate::kemlock::conv::{Owner, OwnerKind, Uuid, b64_decode, b64_encode, item_uuid};
use crate::kemlock::item::{Kem1Item, WireItem};
use crate::kemlock::keys::{PrivateKeys, password_wrap_key, user_key, wrap_root_key};
use crate::kemlock::manifest::{Entry, Manifest};
use crate::kemlock::master::{DEFAULT_PARAMS, KdfParams};
use crate::kemlock::opaque::{self, Kernel, Suite};
use crate::kemlock::{Key, RootKey};
use crate::sync::address::Server;
use crate::sync::api::{Http, NetFailure, Problem, Request, Response};
use crate::sync::crypto::{self, EncString, Kdf, KdfProblem, SymKey};

use super::account::{self, Account};
use super::dpop;

pub const BASE: &str = "https://kemlock.example.test";
pub const TOTP_CODE: &str = "123456";
pub const EMAIL_CODE: &str = "246810";
pub const RECOVERY_CODE: &str = "RECOVERY-CODE-0001";

/// A stand-in for Argon2id that costs nothing: the password, the salt and the settings, hashed
pub fn derive(password: &str, salt: &[u8], params: &KdfParams) -> Result<Key, Problem> {
    let mut hash = Sha256::new();
    hash.update(b"fake-argon2id");
    hash.update(password.as_bytes());
    hash.update(salt);
    hash.update(params.memory_kib.to_be_bytes());
    hash.update(params.iterations.to_be_bytes());
    hash.update(params.parallelism.to_be_bytes());
    Ok(Key::new(hash.finalize().into()))
}

/// A stand-in for Bitwarden's PBKDF2 master key
pub fn bitwarden_derive(password: &[u8], email: &str, _kdf: &Kdf) -> Result<Zeroizing<[u8; 32]>, KdfProblem> {
    let mut hash = Sha256::new();
    hash.update(b"fake-pbkdf2");
    hash.update(password);
    hash.update(crypto::normalize_email(email).as_bytes());
    Ok(Zeroizing::new(hash.finalize().into()))
}

/// What Bitwarden's prelogin says for every Compatible account here
pub const BW_KDF: Kdf = Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None };

/// One request as it reached the server
#[derive(Clone, Debug)]
pub struct Seen {
    pub method: String,
    pub url: String,
    /// Names in lower case
    pub headers: Vec<(String, String)>,
    pub body: String,
}

impl Seen {
    /// The path after the server's address, without the query
    pub fn path(&self) -> String {
        let rest = self.url.split_once("://").map_or(self.url.as_str(), |(_, rest)| rest);
        let path = rest.find('/').map_or("", |at| &rest[at..]);
        path.split('?').next().unwrap_or("").to_string()
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }
}

/// How the server misbehaves, when a test says so. Each is a thing a hostile or broken server can do and the client must not be fooled
/// by; the ones that happen once say so.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Attack {
    /// Prelogin answers these settings whatever the account holds (a server lowering the cost of guessing the password)
    PreloginKdf { memory_kib: u32, iterations: u32, parallelism: u32 },
    /// The next `n` proofs that would have been accepted are answered with `use-dpop-nonce` and a new nonce
    StaleNonce(u32),
    /// Every proof is answered with `use-dpop-nonce`, whatever nonce it carries
    NonceNeverAccepted,
    /// The next request to `auth/token` ends the account's sessions with this reason (`refresh-token-reuse`, `security-stamp-changed`)
    SessionEnds(&'static str),
    /// The manifest is served as the oldest one the server ever held: a counter lower than one already seen
    ManifestRolledBack,
    /// The manifest is served as if there never was one (404)
    ManifestMissing,
    /// The manifest is served with a signature that is not the signer's
    ManifestBadSignature,
    /// An item is served under another kind
    Relabel { item: String, kind: String },
    /// An item is served as a tombstone that still carries its ciphertext
    TombstoneWithCiphertext { item: String },
    /// An item is served at the revision before the current one
    RollBack { item: String },
    /// An item is not served at all
    Hide { item: String },
    /// An item is served at its own revision with another content, sealed under the account's keys: what it was when it was written is not what is read back
    Tamper { item: String },
    /// The next batch is refused as if another device wrote first (409 `stale-revision`), once
    StaleOnce,
    /// A sync page says a federated server holds two versions of an item
    Siblings,
    /// The next manifest written is refused as another device's signed first (409 `stale-manifest`), which it did, once, listing what the server holds
    StaleManifest,
    /// A file is served with one byte changed
    FileTampered,
    /// Files are offered pre-signed, to a bucket
    Presigned,
}

struct LoginState {
    state: ServerLogin<Suite>,
    email: String,
    jkt: String,
    born: i64,
}

struct Challenge {
    account: usize,
    jkt: String,
    born: i64,
    device: String,
}

struct Ticket {
    account: usize,
    jkt: String,
    born: i64,
    two_factor: bool,
}

struct Sess {
    account: usize,
    device: String,
    jkt: String,
    /// Access tokens work while this holds
    alive: bool,
    /// The refresh token works while this holds
    refresh_ok: bool,
    reason: &'static str,
    current_refresh: String,
}

/// An item as the server keeps it
#[derive(Clone)]
pub struct Stored {
    pub wire: WireItem,
    pub seq: u64,
    /// What it was before each of its later revisions
    pub history: Vec<WireItem>,
    pub deleted_at: Option<String>,
}

#[derive(Clone)]
pub struct StoredManifest {
    pub counter: u64,
    pub bytes: Vec<u8>,
    pub signature: Vec<u8>,
    pub stored_at: String,
}

pub struct StoredFile {
    pub item: String,
    pub size: u64,
    pub bytes: Option<Vec<u8>>,
}

#[derive(Clone)]
pub struct Device {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub bitwarden: Option<String>,
}

pub struct BwSide {
    pub hash: String,
    pub protected_key: String,
    pub user: SymKey,
}

/// An account of the fake. Everything a client keeps is here too, so that a test can plant what another device would write.
pub struct FakeAccount {
    pub id: Uuid,
    pub email: String,
    pub password: String,
    /// The Argon2id settings and salt prelogin answers
    pub kdf: KdfParams,
    pub salt: Vec<u8>,
    record: Option<ServerRegistration<Suite>>,
    /// 0 until the account has Kemlock keys
    pub key_version: u32,
    pub root: Option<RootKey>,
    pub wrapped_root_key: Vec<u8>,
    pub public_bundle: Vec<u8>,
    pub bundle_signature: Vec<u8>,
    pub sealed_private_keys: Vec<u8>,
    /// A Compatible account: the Bitwarden master password hash and the user key as Bitwarden's API keeps it
    pub bw: Option<BwSide>,
    /// The code the authenticator shows now, and the codes already used
    pub totp: Option<String>,
    pub totp_used: HashSet<String>,
    pub email_code: Option<String>,
    pub email_sent: u32,
    pub recovery: Option<String>,
    /// What `bitwarden/start` says the account's second steps are, when a test wants other than `["totp"]`
    pub bw_two_factor: Option<Vec<String>>,
    pub password_failures: u32,
    pub second_failures: u32,
    /// How many times the Bitwarden hash reached `bitwarden/start`
    pub bitwarden_hash_received: u32,
    pub items: BTreeMap<String, Stored>,
    pub manifests: Vec<StoredManifest>,
    pub files: BTreeMap<String, StoredFile>,
    pub devices: Vec<Device>,
    seq: u64,
    horizon: u64,
}

impl FakeAccount {
    fn second_step(&self) -> bool {
        self.totp.is_some() || self.email_code.is_some()
    }

    fn methods(&self) -> Vec<&'static str> {
        let mut methods = Vec::new();
        if self.totp.is_some() {
            methods.push("totp");
        }
        if self.email_code.is_some() {
            methods.push("email");
        }
        methods
    }

    pub fn owner(&self) -> Owner {
        Owner::user(self.id)
    }

    /// The keys a client opens from this account's root key
    pub fn keys(&self) -> Account {
        let root = self.root.as_ref().expect("the account has a root key");
        account::open(root, &self.id, self.key_version, &self.public_bundle, &self.bundle_signature, &self.sealed_private_keys).expect("the account's keys open")
    }
}

struct Reply {
    status: u16,
    body: Vec<u8>,
    headers: Vec<(String, String)>,
}

type R<T> = Result<T, Reply>;

impl Reply {
    fn json(status: u16, value: Value) -> Reply {
        Reply { status, body: serde_json::to_vec(&value).unwrap_or_default(), headers: Vec::new() }
    }

    fn empty(status: u16) -> Reply {
        Reply { status, body: Vec::new(), headers: Vec::new() }
    }

    fn problem(status: u16, slug: &str, detail: &str) -> Reply {
        Reply::json(status, json!({"type": format!("urn:kemlock:problem:{slug}"), "title": slug, "status": status, "detail": detail}))
    }

    fn bad(detail: &str) -> Reply {
        Reply::problem(400, "invalid-request", detail)
    }

    /// Members added to a problem's body
    fn with(mut self, extra: Value) -> Reply {
        if let (Ok(Value::Object(mut body)), Value::Object(more)) = (serde_json::from_slice::<Value>(&self.body), extra) {
            body.extend(more);
            self.body = serde_json::to_vec(&Value::Object(body)).unwrap_or_default();
        }
        self
    }

    fn header(mut self, name: &str, value: &str) -> Reply {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
}

fn civil(days: i64) -> (i64, i64, i64) {
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    (yoe + era * 400 + i64::from(month <= 2), month, day)
}

fn rfc3339(at: i64) -> String {
    let (days, rest) = (at.div_euclid(86_400), at.rem_euclid(86_400));
    let (y, m, d) = civil(days);
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn http_date(at: i64) -> String {
    let days = at.div_euclid(86_400);
    let rest = at.rem_euclid(86_400);
    let (y, m, d) = civil(days);
    let weekday = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"][days.rem_euclid(7) as usize];
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][(m - 1) as usize];
    format!("{weekday}, {d:02} {month} {y:04} {:02}:{:02}:{:02} GMT", rest / 3600, rest % 3600 / 60, rest % 60)
}

fn decode_percent(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        if bytes[at] == b'%'
            && at + 2 < bytes.len()
            && let Ok(byte) = u8::from_str_radix(std::str::from_utf8(&bytes[at + 1..at + 3]).unwrap_or(""), 16)
        {
            out.push(byte);
            at += 3;
            continue;
        }
        out.push(bytes[at]);
        at += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn query_of(query: &str, name: &str) -> Option<String> {
    query.split('&').filter_map(|pair| pair.split_once('=')).find(|(key, _)| *key == name).map(|(_, value)| decode_percent(value))
}

fn body_of(request: &Request, allowed: &[&str]) -> R<Map<String, Value>> {
    let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&request.body) else { return Err(Reply::bad("the body is not a JSON object")) };
    if let Some(key) = map.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(Reply::bad(&format!("unknown field `{key}`")));
    }
    Ok(map)
}

fn text<'a>(map: &'a Map<String, Value>, name: &str) -> R<&'a str> {
    map.get(name).and_then(Value::as_str).ok_or_else(|| Reply::bad(&format!("`{name}` is missing")))
}

fn bytes(map: &Map<String, Value>, name: &str) -> R<Vec<u8>> {
    b64_decode(text(map, name)?).map_err(|_| Reply::bad(&format!("`{name}` is not base64url without padding")))
}

fn sha(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn entry_of(id: &str, wire: &WireItem) -> Entry {
    let id = Uuid::parse(id).expect("an item id");
    if wire.deleted {
        return Entry::tombstone(id, wire.revision);
    }
    let bytes = wire.ciphertext.as_deref().and_then(|c| b64_decode(c).ok()).unwrap_or_default();
    Entry { item_id: id, revision: wire.revision, ciphertext_hash: sha(&bytes), deleted: false }
}

pub struct FakeKemlock {
    /// What the server says it is set up under: DPoP proofs are checked against it
    pub domain: String,
    /// The address requests may come to (the same as the domain, unless a test says otherwise)
    listen: String,
    pub features: Vec<String>,
    pub seen: Vec<Seen>,
    /// Seconds the server's clock is ahead of this machine's
    pub clock_offset: i64,
    pub access_ttl: i64,
    pub max_file: u64,
    pub files_disabled: bool,
    pub sso_only: bool,
    /// Accounts made from now on use the real Argon2id, not the stand-in
    pub real_argon2: bool,
    /// What `GET /kem/v1/config` says instead, for a server that is not one
    pub config_override: Option<(u16, Value)>,
    attacks: Vec<Attack>,
    setup: ServerSetup<Suite>,
    pub accounts: Vec<FakeAccount>,
    nonce_epoch: u64,
    seen_jti: HashSet<(String, String)>,
    logins: HashMap<String, LoginState>,
    challenges: HashMap<String, Challenge>,
    tickets: HashMap<String, Ticket>,
    sessions: Vec<Sess>,
    access: HashMap<String, (usize, i64)>,
    refresh: HashMap<String, usize>,
}

impl FakeKemlock {
    pub fn new(domain: &str) -> FakeKemlock {
        FakeKemlock {
            domain: domain.trim_end_matches('/').to_string(),
            listen: domain.trim_end_matches('/').to_string(),
            features: ["opaque", "dpop", "totp", "sync", "live", "manifest", "device-list", "bitwarden-enrol", "account-keys", "sends"].iter().map(|f| f.to_string()).collect(),
            seen: Vec::new(),
            clock_offset: 0,
            access_ttl: 600,
            max_file: 100 * 1024 * 1024,
            files_disabled: false,
            sso_only: false,
            real_argon2: false,
            config_override: None,
            attacks: Vec::new(),
            setup: ServerSetup::<Suite>::new(&mut Kernel),
            accounts: Vec::new(),
            nonce_epoch: 1,
            seen_jti: HashSet::new(),
            logins: HashMap::new(),
            challenges: HashMap::new(),
            tickets: HashMap::new(),
            sessions: Vec::new(),
            access: HashMap::new(),
            refresh: HashMap::new(),
        }
    }

    /// The address a client reaches it at, in the form a connection keeps
    pub fn server(&self) -> Server {
        Server { address: self.listen.clone(), identity: format!("{}/identity", self.listen), api: format!("{}/api", self.listen) }
    }

    /// Requests are answered at this address while proofs are still checked against `domain`: the case of a server set up under another
    /// address than the one the person typed
    pub fn reachable_at(&mut self, address: &str) {
        self.listen = address.trim_end_matches('/').to_string();
    }

    pub fn attack(&mut self, attack: Attack) {
        self.attacks.push(attack);
    }

    pub fn clear_attacks(&mut self) {
        self.attacks.clear();
    }

    pub fn now(&self) -> i64 {
        super::api::unix_now() + self.clock_offset
    }

    fn nonce(&self) -> String {
        b64_encode(&sha(format!("fake-nonce-{}", self.nonce_epoch).as_bytes())[..12])
    }

    fn previous_nonce(&self) -> String {
        b64_encode(&sha(format!("fake-nonce-{}", self.nonce_epoch.saturating_sub(1)).as_bytes())[..12])
    }

    /// The nonce changes (every five minutes on the real server; the previous one is still accepted)
    pub fn rotate_nonce(&mut self) {
        self.nonce_epoch += 1;
    }

    // --- Accounts -------------------------------------------------------------------------------------------------------------

    fn index(&self, email: &str) -> usize {
        let email = opaque::credential_identifier(email);
        self.accounts.iter().position(|a| a.email == email).unwrap_or_else(|| panic!("no account {email}"))
    }

    fn find(&self, email: &str) -> Option<usize> {
        let email = opaque::credential_identifier(email);
        self.accounts.iter().position(|a| a.email == email)
    }

    pub fn account(&self, email: &str) -> &FakeAccount {
        &self.accounts[self.index(email)]
    }

    pub fn account_mut(&mut self, email: &str) -> &mut FakeAccount {
        let at = self.index(email);
        &mut self.accounts[at]
    }

    fn blank(&self, email: &str, password: &str) -> FakeAccount {
        let mut salt = vec![0u8; 16];
        crate::seal::random(&mut salt);
        FakeAccount {
            id: Uuid::random_v4(),
            email: opaque::credential_identifier(email),
            password: password.to_string(),
            kdf: DEFAULT_PARAMS,
            salt,
            record: None,
            key_version: 0,
            root: None,
            wrapped_root_key: Vec::new(),
            public_bundle: Vec::new(),
            bundle_signature: Vec::new(),
            sealed_private_keys: Vec::new(),
            bw: None,
            totp: None,
            totp_used: HashSet::new(),
            email_code: None,
            email_sent: 0,
            recovery: None,
            bw_two_factor: None,
            password_failures: 0,
            second_failures: 0,
            bitwarden_hash_received: 0,
            items: BTreeMap::new(),
            manifests: Vec::new(),
            files: BTreeMap::new(),
            devices: Vec::new(),
            seq: 0,
            horizon: 0,
        }
    }

    /// Makes a Kemlock-only account the way a client registers one (`spec-protocol.md` 2.9): OPAQUE, a root key under the password wrap,
    /// a bundle, its signature and the sealed private keys. Returns the account's id.
    pub fn make_account(&mut self, email: &str, password: &str) -> String {
        self.make_account_with(email, password, DEFAULT_PARAMS)
    }

    /// The same under Argon2id settings of the test's choosing (below the defaults, or above), which prelogin then answers
    pub fn make_account_with(&mut self, email: &str, password: &str, params: KdfParams) -> String {
        let mut account = self.blank(email, password);
        account.kdf = params;
        let master = if self.real_argon2 {
            crate::kemlock::master::master_key(password, &account.salt, &account.kdf).expect("Argon2id runs")
        } else {
            derive(password, &account.salt, &account.kdf).expect("the stand-in derives")
        };
        let (state, request) = opaque::registration_start(&master).expect("registration starts");
        let response = ServerRegistration::<Suite>::start(&self.setup, RegistrationRequest::deserialize(&request).expect("a request"), account.email.as_bytes()).expect("the server starts").message;
        let registered = opaque::registration_finish(state, &master, &response.serialize()).expect("registration finishes");
        account.record = Some(ServerRegistration::<Suite>::finish(RegistrationUpload::deserialize(&registered.upload).expect("an upload")));
        let root = RootKey::random();
        let private = PrivateKeys::generate();
        let bundle = Bundle { account_id: account.id, key_version: 1, kx1: private.kx1.public_key(), sig1: private.sig1.public_key() };
        account.public_bundle = bundle.to_bytes();
        account.bundle_signature = bundle.sign(&private.sig1).expect("the bundle signs");
        account.sealed_private_keys = private.seal(&user_key(&root), &account.id, 1);
        account.wrapped_root_key = wrap_root_key(&root, &password_wrap_key(&master, registered.export_key.as_bytes()), &account.id, 1);
        account.root = Some(root);
        account.key_version = 1;
        let id = account.id.to_string();
        self.accounts.push(account);
        id
    }

    /// An account made through the Bitwarden API: it holds the Bitwarden master password hash and the user key, no OPAQUE record and no
    /// Kemlock keys until its owner signs in on this API once (`spec-protocol.md` 2.4)
    pub fn make_compatible_account(&mut self, email: &str, password: &str) -> String {
        let mut account = self.blank(email, password);
        let master = bitwarden_derive(password.as_bytes(), email, &BW_KDF).expect("the stand-in derives");
        let user = SymKey::random();
        let protected_key = EncString::seal(&crypto::stretch(&master), user.bytes()).text();
        let hash = crypto::master_hash(&master, password.as_bytes()).to_string();
        account.root = RootKey::from_slice(user.bytes());
        account.bw = Some(BwSide { hash, protected_key, user });
        let id = account.id.to_string();
        self.accounts.push(account);
        id
    }

    /// The account's second step is an authenticator that shows `code` now (`TOTP_CODE`): a code is accepted once
    pub fn require_totp(&mut self, email: &str, code: &str) {
        let account = self.account_mut(email);
        account.totp = Some(code.to_string());
        account.recovery = Some(RECOVERY_CODE.to_string());
    }

    pub fn require_email_code(&mut self, email: &str, code: &str) {
        let account = self.account_mut(email);
        account.email_code = Some(code.to_string());
        account.recovery = Some(RECOVERY_CODE.to_string());
    }

    /// Ends every session of the account at its next refresh: its password or security stamp changed
    pub fn change_security_stamp(&mut self, email: &str) {
        let at = self.index(email);
        for session in self.sessions.iter_mut().filter(|s| s.account == at) {
            session.alive = false;
            session.refresh_ok = false;
            session.reason = "security-stamp-changed";
        }
    }

    /// Every access token stops being good (they run out)
    pub fn expire_access_tokens(&mut self) {
        self.access.clear();
    }

    pub fn session_count(&self, email: &str) -> usize {
        let at = self.index(email);
        self.sessions.iter().filter(|s| s.account == at && s.alive).count()
    }

    // --- Items, from the test's side -----------------------------------------------------------------------------------------

    fn store(&mut self, at: usize, wire: WireItem) -> String {
        let now = self.now();
        let account = &mut self.accounts[at];
        account.seq += 1;
        let id = wire.id.clone();
        let deleted_at = wire.deleted.then(|| rfc3339(now));
        let history = account.items.get(&id).map(|old| old.history.iter().cloned().chain([old.wire.clone()]).collect()).unwrap_or_default();
        account.items.insert(id.clone(), Stored { wire, seq: account.seq, history, deleted_at });
        id
    }

    /// What another Kemlock app does: a `kem1` item of `kind` whose id is the plaintext's own `id` (a UUID itself, else its legacy
    /// mapping), at the next revision. The manifest is not touched. Returns the item's id on the server.
    pub fn plant_item(&mut self, email: &str, kind: &str, plain: &Value) -> String {
        let at = self.index(email);
        let owner = self.accounts[at].owner();
        let id = item_uuid(&owner, plain["id"].as_str().expect("a plaintext with an id"));
        self.plant_item_as(email, &id.to_string(), kind, plain)
    }

    /// The same under an id of the test's choosing, which is how an item whose plaintext `id` does not match is made
    pub fn plant_item_as(&mut self, email: &str, item: &str, kind: &str, plain: &Value) -> String {
        let at = self.index(email);
        let keys = self.accounts[at].keys();
        let revision = self.accounts[at].items.get(item).map_or(1, |stored| stored.wire.revision + 1);
        let id = Uuid::parse(item).expect("an item id");
        let json = serde_json::to_vec(plain).expect("JSON");
        let sealed = Kem1Item::seal(&keys.item_wrap, keys.key_version, id, self.accounts[at].owner(), kind, revision, &json).expect("the item seals");
        self.store(at, sealed.to_wire())
    }

    /// A tombstone at the next revision, in the item's own kind
    pub fn plant_tombstone(&mut self, email: &str, item: &str) {
        let at = self.index(email);
        let stored = self.accounts[at].items.get(item).expect("an item to delete").wire.clone();
        let tomb = Kem1Item::tombstone(Uuid::parse(item).expect("an id"), self.accounts[at].owner(), &stored.kind, stored.revision + 1, stored.key_version).expect("a tombstone");
        self.store(at, tomb.to_wire());
    }

    /// A Bitwarden API cipher as the Kemlock sync lists it: format `bw`, key version 0, no item key, the cipher's own JSON as the ciphertext
    pub fn plant_bw(&mut self, email: &str, kind: &str, cipher: &Value) -> String {
        let at = self.index(email);
        let id = cipher["id"].as_str().expect("a cipher id").to_string();
        let revision = self.accounts[at].items.get(&id).map_or(1, |stored| stored.wire.revision + 1);
        let wire = WireItem {
            id,
            owner: self.accounts[at].owner().to_string(),
            kind: kind.to_string(),
            format: "bw".into(),
            revision,
            key_version: 0,
            ciphertext: Some(b64_encode(cipher.to_string().as_bytes())),
            item_key: None,
            deleted: false,
            collection_id: None,
            deleted_at: None,
            held: None,
        };
        self.store(at, wire)
    }

    /// An item as the server stores it, whatever it is: for a shape no honest client writes
    pub fn plant_wire(&mut self, email: &str, wire: WireItem) -> String {
        let at = self.index(email);
        self.store(at, wire)
    }

    /// An item of a space the person belongs to: another owner, its own key
    pub fn plant_foreign(&mut self, email: &str, plain: &Value) -> String {
        let at = self.index(email);
        let id = Uuid::random_v4();
        let space = Owner { kind: OwnerKind::Space, id: Uuid::random_v4() };
        let sealed = Kem1Item::seal(&Key::random(), 1, id, space, "login", 1, &serde_json::to_vec(plain).expect("JSON")).expect("seals");
        self.store(at, sealed.to_wire())
    }

    /// What an item opens to under the account's keys
    pub fn plain_of(&self, email: &str, item: &str) -> Option<Value> {
        let account = self.account(email);
        let stored = account.items.get(item)?;
        let keys = account.keys();
        let (_, json) = stored.wire.kem1().ok()?.open(&keys.item_wrap).ok()?;
        serde_json::from_slice(&json).ok()
    }

    pub fn wire_of(&self, email: &str, item: &str) -> Option<WireItem> {
        self.account(email).items.get(item).map(|stored| stored.wire.clone())
    }

    /// The ids of the items the server holds live
    pub fn live_ids(&self, email: &str) -> Vec<String> {
        self.account(email).items.iter().filter(|(_, stored)| !stored.wire.deleted).map(|(id, _)| id.clone()).collect()
    }

    pub fn revision_of(&self, email: &str, item: &str) -> Option<u64> {
        self.account(email).items.get(item).map(|stored| stored.wire.revision)
    }

    /// Every cursor handed out so far can no longer be synced from: a 410 for each
    pub fn forget_cursors(&mut self, email: &str) {
        let account = self.account_mut(email);
        account.horizon = account.seq + 1;
        account.seq += 1;
    }

    /// Signs a manifest of everything the server holds, above the stored counter, as the Kemlock app does after it writes
    pub fn sign_manifest(&mut self, email: &str) -> u64 {
        let at = self.index(email);
        self.sign_manifest_at(at)
    }

    fn sign_manifest_at(&mut self, at: usize) -> u64 {
        let keys = self.accounts[at].keys();
        let account = &self.accounts[at];
        let owner = account.owner().to_string();
        let entries: Vec<Entry> = account.items.iter().filter(|(_, stored)| stored.wire.owner == owner).map(|(id, stored)| entry_of(id, &stored.wire)).collect();
        let counter = account.manifests.last().map_or(0, |m| m.counter) + 1;
        let manifest = Manifest::new(account.owner(), counter, entries).expect("a manifest");
        let (bytes, signature) = (manifest.to_bytes(), manifest.sign(&keys.sig_private).expect("signs"));
        let now = self.now();
        self.accounts[at].manifests.push(StoredManifest { counter, bytes, signature, stored_at: rfc3339(now) });
        counter
    }

    /// The manifest the server holds, parsed
    pub fn manifest(&self, email: &str) -> Option<Manifest> {
        let stored = self.account(email).manifests.last()?;
        Manifest::parse(&stored.bytes).ok()
    }

    pub fn requests_to(&self, path_part: &str) -> usize {
        self.seen.iter().filter(|seen| seen.path().contains(path_part)).count()
    }

    // --- The wire -------------------------------------------------------------------------------------------------------------

    fn take_attack(&mut self, wanted: impl Fn(&Attack) -> bool) -> Option<Attack> {
        let at = self.attacks.iter().position(wanted)?;
        Some(self.attacks.remove(at))
    }

    /// Checks the request's DPoP proof as the server does and returns the key's thumbprint
    fn proof(&mut self, request: &Request, path: &str, token: Option<&str>) -> R<String> {
        let bad = |why: &str| Reply::problem(401, "invalid-dpop-proof", why).header("www-authenticate", "DPoP error=\"invalid_dpop_proof\", algs=\"ES256 EdDSA\"");
        let proofs: Vec<&String> = request.headers.iter().filter(|(name, _)| name.eq_ignore_ascii_case("dpop")).map(|(_, value)| value).collect();
        if proofs.len() != 1 {
            return Err(bad("exactly one DPoP header is required"));
        }
        let parts: Vec<&str> = proofs[0].split('.').collect();
        let [header, claims, signature] = parts.as_slice() else { return Err(bad("a proof has three parts")) };
        let decode = |part: &str| b64_decode(part).ok().and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());
        let (Some(header_json), Some(claims_json)) = (decode(header), decode(claims)) else { return Err(bad("the proof is not JSON")) };
        if header_json["typ"] != json!("dpop+jwt") {
            return Err(bad("typ must be dpop+jwt"));
        }
        let jwk = &header_json["jwk"];
        if jwk.get("d").is_some() || jwk["kty"] != json!("OKP") || jwk["crv"] != json!("Ed25519") || header_json["alg"] != json!("EdDSA") {
            return Err(bad("the key is not a public Ed25519 JWK"));
        }
        let x: [u8; 32] = jwk["x"].as_str().and_then(|x| b64_decode(x).ok()).and_then(|x| x.try_into().ok()).ok_or_else(|| bad("the key's x is 32 bytes"))?;
        let key = VerifyingKey::from_bytes(&x).map_err(|_| bad("the key is not a point"))?;
        let signature = b64_decode(signature).ok().and_then(|s| Signature::from_slice(&s).ok()).ok_or_else(|| bad("the signature is 64 bytes"))?;
        if key.verify(format!("{header}.{claims}").as_bytes(), &signature).is_err() {
            return Err(bad("the signature does not verify"));
        }
        if claims_json["htm"] != json!(request.method) {
            return Err(bad("htm doesn't match the method"));
        }
        let expected = dpop::htu(&format!("{}{}", self.domain, path));
        if claims_json["htu"].as_str().map(dpop::htu) != Some(expected) {
            return Err(bad("htu doesn't match the request URL"));
        }
        let iat = claims_json["iat"].as_i64().ok_or_else(|| bad("iat is a number"))?;
        if (iat - self.now()).abs() > 60 {
            return Err(bad("iat is too far from the server's clock"));
        }
        let jti = claims_json["jti"].as_str().filter(|jti| (1..=256).contains(&jti.len())).ok_or_else(|| bad("jti is 1 to 256 characters"))?.to_string();
        if let Some(token) = token
            && claims_json["ath"].as_str() != Some(dpop::ath(token).as_str())
        {
            return Err(bad("ath doesn't match the access token"));
        }
        let never = self.attacks.contains(&Attack::NonceNeverAccepted);
        let nonce_ok = !never && claims_json["nonce"].as_str().is_some_and(|nonce| nonce == self.nonce() || nonce == self.previous_nonce());
        let mut stale = false;
        if nonce_ok && let Some(Attack::StaleNonce(n)) = self.attacks.iter_mut().find(|a| matches!(a, Attack::StaleNonce(n) if *n > 0)) {
            *n -= 1;
            stale = true;
        }
        if !nonce_ok || stale {
            self.nonce_epoch += 1;
            return Err(Reply::problem(401, "use-dpop-nonce", "the nonce is missing or old").with(json!({"error": "use_dpop_nonce"})).header("www-authenticate", "DPoP error=\"use_dpop_nonce\""));
        }
        let jkt = b64_encode(&sha(format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", jwk["x"].as_str().unwrap_or("")).as_bytes()));
        if !self.seen_jti.insert((jkt.clone(), jti)) {
            return Err(bad("the proof was already used"));
        }
        Ok(jkt)
    }

    /// The account and session a request's token is for, after the proof and the token are checked
    fn authenticate(&mut self, request: &Request, path: &str) -> R<(usize, usize)> {
        let unauthorized = |detail: &str| Reply::problem(401, "unauthorized", detail).header("www-authenticate", "DPoP error=\"invalid_token\"");
        let header = request.headers.iter().find(|(name, _)| name.eq_ignore_ascii_case("authorization")).map(|(_, value)| value.clone());
        let Some(token) = header.as_deref().and_then(|value| value.strip_prefix("DPoP ")).map(str::to_string) else {
            return Err(Reply::problem(401, "unauthorized", "send Authorization: DPoP <access token>").header("www-authenticate", "DPoP algs=\"ES256 EdDSA\""));
        };
        let jkt = self.proof(request, path, Some(&token))?;
        let Some(&(session, expires)) = self.access.get(&token) else { return Err(unauthorized("the access token is not good")) };
        let live = self.sessions.get(session).is_some_and(|s| s.alive && s.jkt == jkt);
        if !live || expires < self.now() {
            return Err(unauthorized("the access token is not good"));
        }
        Ok((self.sessions[session].account, session))
    }

    fn issue(&mut self, account: usize, jkt: &str, device: &str) -> Value {
        let mut random = [0u8; 24];
        crate::seal::random(&mut random);
        let (access, refresh) = (format!("at.{}", b64_encode(&random)), format!("rt.{}", b64_encode(&sha(&random))));
        let session = self.sessions.len();
        self.sessions.push(Sess { account, device: device.to_string(), jkt: jkt.to_string(), alive: true, refresh_ok: true, reason: "", current_refresh: refresh.clone() });
        self.access.insert(access.clone(), (session, self.now() + self.access_ttl));
        self.refresh.insert(refresh.clone(), session);
        self.token_object(account, device, &access, &refresh)
    }

    fn token_object(&self, account: usize, device: &str, access: &str, refresh: &str) -> Value {
        json!({"tokenType": "DPoP", "accessToken": access, "expiresIn": self.access_ttl, "refreshToken": refresh, "refreshExpiresIn": 30 * 86_400,
               "userId": self.accounts[account].id.to_string(), "deviceId": device, "admin": false})
    }

    fn route(&mut self, request: &Request, rest: &str) -> R<Reply> {
        let (path, query) = rest.split_once('?').unwrap_or((rest, ""));
        if request.body.len() > 2 * 1024 * 1024 && !path.contains("/files/") {
            return Err(Reply::problem(413, "payload-too-large", "the body is over 2 MiB"));
        }
        if let Some(bitwarden) = path.strip_prefix("/identity") {
            return self.bitwarden(request, bitwarden);
        }
        let Some(kem) = path.strip_prefix("/kem/v1/") else { return Err(Reply::problem(404, "not-found", "no such route")) };
        let segments: Vec<&str> = kem.split('/').collect();
        match (request.method, segments.as_slice()) {
            ("GET", ["config"]) => Ok(self.config()),
            ("POST", ["auth", "prelogin"]) => self.prelogin(request),
            ("POST", ["auth", "methods"]) => self.methods(request),
            ("POST", ["auth", "opaque", "start"]) => self.opaque_start(request, path),
            ("POST", ["auth", "opaque", "finish"]) => self.opaque_finish(request, path),
            ("POST", ["auth", "two-factor"]) => self.two_factor(request, path, "totp"),
            ("POST", ["auth", "two-factor", "email", "send"]) => self.email_send(request, path),
            ("POST", ["auth", "two-factor", "email"]) => self.two_factor(request, path, "email"),
            ("POST", ["auth", "two-factor", "recovery"]) => self.two_factor(request, path, "recovery"),
            ("POST", ["auth", "bitwarden", "start"]) => self.bitwarden_start(request, path),
            ("POST", ["auth", "bitwarden", "finish"]) => self.bitwarden_finish(request, path),
            ("POST", ["auth", "token"]) => self.token(request, path),
            ("GET", ["account", "keys"]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.account_keys(account)
            }
            ("GET", ["devices"]) => {
                let (account, session) = self.authenticate(request, path)?;
                let current = self.sessions[session].device.clone();
                let now = rfc3339(self.now());
                let list: Vec<Value> = self.accounts[account].devices.iter().map(|d| json!({"id": d.id, "name": d.name, "kind": d.kind, "createdAt": now, "lastSeenAt": now, "current": d.id == current, "trusted": false})).collect();
                Ok(Reply::json(200, json!({"devices": list})))
            }
            ("POST", ["devices", "sign-out"]) => {
                let (account, _) = self.authenticate(request, path)?;
                let body = body_of(request, &["deviceId"])?;
                let device = text(&body, "deviceId")?.to_string();
                if !self.accounts[account].devices.iter().any(|d| d.id == device) {
                    return Err(Reply::problem(404, "not-found", "no such device"));
                }
                self.accounts[account].devices.retain(|d| d.id != device);
                // Access tokens keep working until they run out, as on the real server: only the refresh token is refused
                for session in self.sessions.iter_mut().filter(|s| s.account == account && s.device == device) {
                    session.refresh_ok = false;
                }
                Ok(Reply::empty(204))
            }
            ("GET", ["sync"]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.sync(account, query_of(query, "since"), query_of(query, "limit").and_then(|l| l.parse().ok()))
            }
            ("POST", ["sync"]) => {
                let (account, _) = self.authenticate(request, path)?;
                let body = body_of(request, &["since", "limit"])?;
                self.sync(account, body.get("since").and_then(Value::as_str).map(str::to_string), body.get("limit").and_then(Value::as_u64).map(|l| l as usize))
            }
            ("POST", ["items:batch"]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.batch(request, account)
            }
            ("GET", ["manifests", owner]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.get_manifest(account, &decode_percent(owner))
            }
            ("PUT", ["manifests", owner]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.put_manifest(request, account, &decode_percent(owner))
            }
            ("POST", ["items", item, "files"]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.file_start(request, account, item)
            }
            ("PUT", ["items", item, "files", file]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.file_put(request, account, item, file)
            }
            ("GET", ["items", item, "files", file]) => {
                let (account, _) = self.authenticate(request, path)?;
                self.file_get(account, item, file)
            }
            ("DELETE", ["items", item, "files", file]) => {
                let (account, _) = self.authenticate(request, path)?;
                if !self.accounts[account].files.get(*file).is_some_and(|f| f.item == *item) {
                    return Err(Reply::problem(404, "not-found", "no such file"));
                }
                self.accounts[account].files.remove(*file);
                Ok(Reply::empty(204))
            }
            _ => Err(Reply::problem(404, "not-found", "no such route")),
        }
    }

    fn config(&self) -> Reply {
        if let Some((status, body)) = &self.config_override {
            return Reply::json(*status, body.clone());
        }
        Reply::json(
            200,
            json!({"server": "kemlock-server", "apiVersions": ["v1"], "version": "0.1.2", "commit": null, "license": "AGPL-3.0-only", "sourceUrl": "https://example.test/source",
                   "serverId": "0b1c2d3e-4f50-4172-8394-a5b6c7d8e9f0", "domain": self.domain, "setup": "complete", "signupsAllowed": true, "features": self.features, "vaults": []}),
        )
    }

    /// Bitwarden's own prelogin on the same server, which the enrolment of a Compatible account asks
    fn bitwarden(&mut self, request: &Request, path: &str) -> R<Reply> {
        match (request.method, path) {
            ("POST", "/accounts/prelogin/password" | "/accounts/prelogin") => {
                let _ = body_of(request, &["email"])?;
                Ok(Reply::json(
                    200,
                    json!({"kdf": 0, "kdfIterations": BW_KDF.iterations, "kdfMemory": null, "kdfParallelism": null,
                           "kdfSettings": {"kdfType": 0, "iterations": BW_KDF.iterations, "memory": null, "parallelism": null}, "salt": null}),
                ))
            }
            _ => Err(Reply::problem(404, "not-found", "no such route")),
        }
    }

    fn prelogin(&mut self, request: &Request) -> R<Reply> {
        let body = body_of(request, &["email"])?;
        let email = text(&body, "email")?;
        let (params, salt) = match self.find(email) {
            Some(at) => (self.accounts[at].kdf, self.accounts[at].salt.clone()),
            None => (DEFAULT_PARAMS, sha(format!("unknown-salt{email}").as_bytes())[..16].to_vec()),
        };
        let lowered = self.attacks.iter().find_map(|a| match a {
            Attack::PreloginKdf { memory_kib, iterations, parallelism } => Some(KdfParams { memory_kib: *memory_kib, iterations: *iterations, parallelism: *parallelism }),
            _ => None,
        });
        let params = lowered.unwrap_or(params);
        Ok(Reply::json(200, json!({"kdf": {"memoryKib": params.memory_kib, "iterations": params.iterations, "parallelism": params.parallelism, "salt": b64_encode(&salt)}})))
    }

    fn methods(&mut self, request: &Request) -> R<Reply> {
        let _ = body_of(request, &["email"])?;
        if self.sso_only {
            return Ok(Reply::json(200, json!({"methods": ["sso"], "sso": {"providerName": "Example"}})));
        }
        Ok(Reply::json(200, json!({"methods": ["password"]})))
    }

    fn rate_limited() -> Reply {
        Reply::problem(429, "rate-limited", "too many tries").with(json!({"retryAfter": 60})).header("retry-after", "60")
    }

    fn opaque_start(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["email", "request"])?;
        let email = text(&body, "email")?;
        if email.len() > 254 {
            return Err(Reply::bad("the email is too long"));
        }
        let ke1 = CredentialRequest::deserialize(&bytes(&body, "request")?).map_err(|_| Reply::bad("not an OPAQUE request"))?;
        let id = opaque::credential_identifier(email);
        let record = self.find(&id).and_then(|at| self.accounts[at].record.clone());
        let params = ServerLoginParameters { context: Some(opaque::CONTEXT), identifiers: Default::default() };
        let started = ServerLogin::start(&mut Kernel, &self.setup, record, ke1, id.as_bytes(), params).map_err(|_| Reply::bad("OPAQUE did not start"))?;
        let mut random = [0u8; 18];
        crate::seal::random(&mut random);
        let token = b64_encode(&random);
        let born = self.now();
        self.logins.insert(token.clone(), LoginState { state: started.state, email: id, jkt, born });
        Ok(Reply::json(200, json!({"response": b64_encode(&started.message.serialize()), "loginState": token})))
    }

    fn device_of(&mut self, account: usize, device: &Value) -> R<String> {
        let Value::Object(map) = device else { return Err(Reply::bad("device is an object")) };
        if let Some(key) = map.keys().find(|key| !["name", "kind", "id", "bitwardenDeviceIdentifier", "deviceType"].contains(&key.as_str())) {
            return Err(Reply::bad(&format!("unknown device field `{key}`")));
        }
        let kind = text(map, "kind")?;
        if !["kemlock-android", "kemlock-ios", "kemlock-web", "kemlock-browser", "kemlock-cli", "amethystora", "bitwarden", "other"].contains(&kind) {
            return Err(Reply::bad("an unknown device kind"));
        }
        if map.contains_key("deviceType") && kind != "kemlock-browser" {
            return Err(Reply::bad("deviceType only goes with kemlock-browser"));
        }
        let name: String = text(map, "name")?.chars().filter(|c| !c.is_control()).take(64).collect();
        let bitwarden = map.get("bitwardenDeviceIdentifier").and_then(Value::as_str).filter(|id| (1..=256).contains(&id.len())).map(str::to_string);
        let wanted = map.get("id").and_then(Value::as_str);
        let known = self.accounts[account].devices.iter().position(|d| if bitwarden.is_some() { d.bitwarden == bitwarden } else { Some(d.id.as_str()) == wanted });
        if let Some(at) = known {
            let device = &mut self.accounts[account].devices[at];
            device.name = name;
            return Ok(device.id.clone());
        }
        let id = Uuid::random_v4().to_string();
        self.accounts[account].devices.push(Device { id: id.clone(), name, kind: kind.to_string(), bitwarden });
        Ok(id)
    }

    fn opaque_finish(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["email", "loginState", "finalization", "device"])?;
        let state = text(&body, "loginState")?;
        let Some(login) = self.logins.remove(state) else { return Err(Reply::bad("the login state was already used")) };
        if login.jkt != jkt || self.now() - login.born > 300 {
            return Err(Reply::bad("the login state is not good"));
        }
        let Some(at) = self.find(&login.email) else { return Err(Reply::problem(401, "unauthorized", "wrong password")) };
        if self.accounts[at].password_failures >= 10 {
            return Err(Self::rate_limited());
        }
        let ke3 = CredentialFinalization::deserialize(&bytes(&body, "finalization")?).map_err(|_| Reply::bad("not an OPAQUE finalization"))?;
        let params = ServerLoginParameters { context: Some(opaque::CONTEXT), identifiers: Default::default() };
        if login.state.finish(ke3, params).is_err() {
            self.accounts[at].password_failures += 1;
            return Err(Reply::problem(401, "unauthorized", "wrong password"));
        }
        self.accounts[at].password_failures = 0;
        let device = self.device_of(at, body.get("device").unwrap_or(&Value::Null))?;
        if self.accounts[at].second_step() {
            let mut random = [0u8; 18];
            crate::seal::random(&mut random);
            let challenge = b64_encode(&random);
            let born = self.now();
            self.challenges.insert(challenge.clone(), Challenge { account: at, jkt, born, device });
            let methods = self.accounts[at].methods();
            return Ok(Reply::json(200, json!({"status": "two_factor_required", "tokens": null, "challenge": challenge, "methods": methods})));
        }
        let tokens = self.issue(at, &jkt, &device);
        Ok(Reply::json(200, json!({"status": "signed_in", "tokens": tokens, "challenge": null, "methods": null})))
    }

    fn challenge_of(&mut self, body: &Map<String, Value>, jkt: &str) -> R<usize> {
        let challenge = text(body, "challenge")?;
        let Some(held) = self.challenges.get(challenge) else { return Err(Reply::problem(401, "unauthorized", "the challenge is not good")) };
        if held.jkt != jkt || self.now() - held.born > 300 {
            return Err(Reply::problem(401, "unauthorized", "the challenge is not good"));
        }
        Ok(held.account)
    }

    fn email_send(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["challenge", "client"])?;
        let at = self.challenge_of(&body, &jkt)?;
        if self.accounts[at].email_code.is_none() {
            return Err(Reply::bad("the account has no email step"));
        }
        self.accounts[at].email_sent += 1;
        Ok(Reply::empty(204))
    }

    fn two_factor(&mut self, request: &Request, path: &str, method: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, if method == "totp" { &["challenge", "method", "code"][..] } else { &["challenge", "code", "client"][..] })?;
        if method == "totp" && body.get("method").and_then(Value::as_str) != Some("totp") {
            return Err(Reply::bad("only totp goes here"));
        }
        let at = self.challenge_of(&body, &jkt)?;
        if self.accounts[at].second_failures >= 5 {
            return Err(Self::rate_limited());
        }
        let code = text(&body, "code")?.to_string();
        let account = &mut self.accounts[at];
        let good = match method {
            "totp" => account.totp.as_deref() == Some(code.as_str()) && account.totp_used.insert(code.clone()),
            "email" => account.email_sent > 0 && account.email_code.as_deref() == Some(code.as_str()),
            _ => account.recovery.as_deref() == Some(code.as_str()),
        };
        if !good {
            account.second_failures += 1;
            return Err(Reply::problem(401, "unauthorized", "the code is not good"));
        }
        account.second_failures = 0;
        if method == "recovery" {
            account.totp = None;
            account.email_code = None;
            account.recovery = None;
        }
        let challenge = text(&body, "challenge")?.to_string();
        let device = self.challenges.remove(&challenge).map(|c| c.device).unwrap_or_default();
        Ok(Reply::json(200, self.issue(at, &jkt, &device)))
    }

    fn token(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["grantType", "refreshToken"])?;
        if text(&body, "grantType")? != "refresh_token" {
            return Err(Reply::bad("only refresh_token"));
        }
        let token = text(&body, "refreshToken")?.to_string();
        if let Some(Attack::SessionEnds(reason)) = self.take_attack(|a| matches!(a, Attack::SessionEnds(_))) {
            if let Some(&session) = self.refresh.get(&token) {
                let account = self.sessions[session].account;
                for s in self.sessions.iter_mut().filter(|s| s.account == account) {
                    s.alive = false;
                    s.refresh_ok = false;
                    s.reason = reason;
                }
            }
            return Err(Reply::problem(401, "session-ended", "the session ended").with(json!({"reason": reason})));
        }
        let Some(&session) = self.refresh.get(&token) else { return Err(Reply::problem(401, "unauthorized", "the refresh token is not good")) };
        if !self.sessions[session].refresh_ok {
            let reason = self.sessions[session].reason;
            if reason.is_empty() {
                return Err(Reply::problem(401, "unauthorized", "the device signed out"));
            }
            return Err(Reply::problem(401, "session-ended", "the session ended").with(json!({"reason": reason})));
        }
        if self.sessions[session].jkt != jkt {
            return Err(Reply::problem(401, "unauthorized", "the refresh token is bound to another key"));
        }
        if self.sessions[session].current_refresh != token {
            // A spent token used again: whoever holds it is not the device that was given the new one, and the device's sessions all end
            let (account, device) = (self.sessions[session].account, self.sessions[session].device.clone());
            for s in self.sessions.iter_mut().filter(|s| s.account == account && s.device == device) {
                s.alive = false;
                s.refresh_ok = false;
                s.reason = "refresh-token-reuse";
            }
            return Err(Reply::problem(401, "session-ended", "the refresh token was used twice").with(json!({"reason": "refresh-token-reuse"})));
        }
        let mut random = [0u8; 24];
        crate::seal::random(&mut random);
        let (access, refresh) = (format!("at.{}", b64_encode(&random)), format!("rt.{}", b64_encode(&sha(&random))));
        self.sessions[session].current_refresh = refresh.clone();
        self.access.insert(access.clone(), (session, self.now() + self.access_ttl));
        self.refresh.insert(refresh.clone(), session);
        let (account, device) = (self.sessions[session].account, self.sessions[session].device.clone());
        Ok(Reply::json(200, self.token_object(account, &device, &access, &refresh)))
    }

    fn account_keys(&self, at: usize) -> R<Reply> {
        let account = &self.accounts[at];
        if account.key_version == 0 {
            return Err(Reply::problem(404, "not-found", "the account has no keys"));
        }
        Ok(Reply::json(
            200,
            json!({"keyVersion": account.key_version,
                   "kdf": {"memoryKib": account.kdf.memory_kib, "iterations": account.kdf.iterations, "parallelism": account.kdf.parallelism, "salt": b64_encode(&account.salt)},
                   "wrappedRootKey": b64_encode(&account.wrapped_root_key), "publicBundle": b64_encode(&account.public_bundle),
                   "bundleSignature": b64_encode(&account.bundle_signature), "sealedPrivateKeys": b64_encode(&account.sealed_private_keys)}),
        ))
    }

    fn bitwarden_start(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["email", "masterPasswordHash", "request"])?;
        let hash = text(&body, "masterPasswordHash")?;
        if hash.len() > 256 {
            return Err(Reply::bad("the hash is too long"));
        }
        let ke = RegistrationRequest::deserialize(&bytes(&body, "request")?).map_err(|_| Reply::bad("not an OPAQUE registration request"))?;
        let unauthorized = || Reply::problem(401, "unauthorized", "unknown account or wrong hash");
        let Some(at) = self.find(text(&body, "email")?) else { return Err(unauthorized()) };
        if self.accounts[at].bw.is_none() {
            return Err(unauthorized());
        }
        self.accounts[at].bitwarden_hash_received += 1;
        let account = &self.accounts[at];
        let bw = account.bw.as_ref().expect("checked");
        if bw.hash != hash {
            return Err(unauthorized());
        }
        if account.record.is_some() {
            return Err(Reply::problem(409, "already-exists", "the account is enrolled already"));
        }
        let response = ServerRegistration::<Suite>::start(&self.setup, ke, account.email.as_bytes()).map_err(|_| Reply::bad("OPAQUE did not start"))?.message;
        let two_factor: Vec<String> = account.bw_two_factor.clone().unwrap_or_else(|| account.methods().iter().filter(|m| **m == "totp").map(|m| m.to_string()).collect());
        let mut random = [0u8; 18];
        crate::seal::random(&mut random);
        let ticket = b64_encode(&random);
        let (user_id, key) = (account.id.to_string(), bw.protected_key.clone());
        let born = self.now();
        self.tickets.insert(ticket.clone(), Ticket { account: at, jkt, born, two_factor: !two_factor.is_empty() });
        Ok(Reply::json(200, json!({"userId": user_id, "key": key, "response": b64_encode(&response.serialize()), "ticket": ticket, "twoFactor": two_factor})))
    }

    fn bitwarden_finish(&mut self, request: &Request, path: &str) -> R<Reply> {
        let jkt = self.proof(request, path, None)?;
        let body = body_of(request, &["ticket", "upload", "kdf", "publicBundle", "bundleSignature", "sealedPrivateKeys", "wrappedRootKey", "twoFactorCode"])?;
        let ticket = text(&body, "ticket")?.to_string();
        let Some(held) = self.tickets.get(&ticket) else { return Err(Reply::problem(401, "unauthorized", "the ticket is not good")) };
        if held.jkt != jkt || self.now() - held.born > 300 {
            return Err(Reply::problem(401, "unauthorized", "the ticket is not good"));
        }
        let (at, needs_code) = (held.account, held.two_factor);
        let kdf = body.get("kdf").and_then(Value::as_object).ok_or_else(|| Reply::bad("kdf is an object"))?;
        let salt = b64_decode(kdf.get("salt").and_then(Value::as_str).unwrap_or("")).unwrap_or_default();
        let number = |name: &str| kdf.get(name).and_then(Value::as_u64);
        let defaults = number("memoryKib") == Some(u64::from(DEFAULT_PARAMS.memory_kib)) && number("iterations") == Some(u64::from(DEFAULT_PARAMS.iterations)) && number("parallelism") == Some(u64::from(DEFAULT_PARAMS.parallelism));
        if !defaults || salt.len() != 16 {
            return Err(Reply::bad("the KDF settings must be the defaults with a 16-byte salt"));
        }
        if needs_code {
            if self.accounts[at].second_failures >= 5 {
                return Err(Self::rate_limited());
            }
            let code = body.get("twoFactorCode").and_then(Value::as_str).unwrap_or("").to_string();
            let account = &mut self.accounts[at];
            if account.totp.as_deref() != Some(code.as_str()) || !account.totp_used.insert(code) {
                account.second_failures += 1;
                return Err(Reply::problem(401, "unauthorized", "the code is not good"));
            }
        }
        let upload = RegistrationUpload::deserialize(&bytes(&body, "upload")?).map_err(|_| Reply::bad("not an OPAQUE upload"))?;
        let (bundle, signature, sealed, wrapped) = (bytes(&body, "publicBundle")?, bytes(&body, "bundleSignature")?, bytes(&body, "sealedPrivateKeys")?, bytes(&body, "wrappedRootKey")?);
        if bundle.len() != crate::kemlock::bundle::BUNDLE_LEN || signature.len() != crate::kemlock::sig1::SIGNATURE || sealed.len() != crate::kemlock::keys::SEALED_PRIVATE_KEYS || wrapped.len() != crate::kemlock::keys::WRAPPED_ROOT_KEY {
            return Err(Reply::bad("a blob is not the length of its format"));
        }
        self.tickets.remove(&ticket);
        let account = &mut self.accounts[at];
        account.record = Some(ServerRegistration::<Suite>::finish(upload));
        account.kdf = DEFAULT_PARAMS;
        account.salt = salt;
        account.key_version = 1;
        account.public_bundle = bundle;
        account.bundle_signature = signature;
        account.sealed_private_keys = sealed;
        account.wrapped_root_key = wrapped;
        Ok(Reply::empty(204))
    }

    // --- Items ----------------------------------------------------------------------------------------------------------------

    /// An item as it is served, with the attacks applied; none when it is hidden
    fn serve(&self, at: usize, stored: &Stored) -> Option<Value> {
        let id = &stored.wire.id;
        if self.attacks.iter().any(|a| matches!(a, Attack::Hide { item } if item == id)) {
            return None;
        }
        let mut wire = stored.wire.clone();
        if self.attacks.iter().any(|a| matches!(a, Attack::RollBack { item } if item == id))
            && let Some(old) = stored.history.last()
        {
            wire = old.clone();
        }
        if self.attacks.iter().any(|a| matches!(a, Attack::Tamper { item } if item == id)) && !wire.deleted {
            let account = &self.accounts[at];
            let keys = account.keys();
            let plain = json!({"id": id, "name": "tampered", "password": "tampered"});
            if let Ok(sealed) = Kem1Item::seal(&keys.item_wrap, wire.key_version, Uuid::parse(id).ok()?, account.owner(), &wire.kind, wire.revision, plain.to_string().as_bytes()) {
                wire = sealed.to_wire();
            }
        }
        for attack in &self.attacks {
            match attack {
                Attack::Relabel { item, kind } if item == id => wire.kind = kind.clone(),
                Attack::TombstoneWithCiphertext { item } if item == id => wire.deleted = true,
                _ => {}
            }
        }
        let mut value = serde_json::to_value(&wire).ok()?;
        if let Some(at) = &stored.deleted_at
            && wire.deleted
        {
            value["deletedAt"] = json!(at);
        }
        Some(value)
    }

    fn sync(&mut self, at: usize, since: Option<String>, limit: Option<usize>) -> R<Reply> {
        let account = &self.accounts[at];
        let since_seq = match since.as_deref() {
            None => 0,
            Some(cursor) => {
                let seq = b64_decode(cursor).ok().and_then(|bytes| String::from_utf8(bytes).ok()).and_then(|text| text.strip_prefix('s')?.parse::<u64>().ok());
                match seq {
                    Some(seq) if seq <= account.seq && seq >= account.horizon => seq,
                    _ => return Err(Reply::problem(410, "full-sync-required", "the cursor cannot be used")),
                }
            }
        };
        if let Some(cursor) = &since
            && since_seq == account.seq
        {
            return Ok(Reply { status: 304, body: Vec::new(), headers: vec![("etag".into(), format!("\"{cursor}\""))] });
        }
        let limit = limit.filter(|l| *l > 0).unwrap_or(500).min(500);
        let mut changed: Vec<&Stored> = account.items.values().filter(|stored| stored.seq > since_seq).collect();
        changed.sort_by_key(|stored| stored.seq);
        let more = changed.len() > limit;
        changed.truncate(limit);
        let cursor_seq = if more { changed.last().map_or(account.seq, |stored| stored.seq) } else { account.seq };
        let items: Vec<Value> = changed.iter().filter_map(|stored| self.serve(at, stored)).collect();
        let cursor = b64_encode(format!("s{cursor_seq}").as_bytes());
        let siblings: Vec<Value> = if self.attacks.contains(&Attack::Siblings) && !items.is_empty() { vec![json!({"id": items[0]["id"]})] } else { Vec::new() };
        let mut reply = Reply::json(200, json!({"items": items, "cursor": cursor, "more": more, "siblings": siblings}));
        if !more {
            reply = reply.header("etag", &format!("\"{cursor}\""));
        }
        Ok(reply)
    }

    fn batch(&mut self, request: &Request, at: usize) -> R<Reply> {
        let body = body_of(request, &["writes"])?;
        let writes = body.get("writes").and_then(Value::as_array).ok_or_else(|| Reply::bad("writes is a list"))?;
        if writes.is_empty() || writes.len() > 500 {
            return Err(Reply::bad("a batch holds 1 to 500 writes"));
        }
        if self.take_attack(|a| *a == Attack::StaleOnce).is_some() {
            let first = writes.first().and_then(|w| w["item"]["id"].as_str()).unwrap_or("").to_string();
            let current = self.accounts[at].items.get(&first).map(|s| s.wire.revision);
            return Err(Reply::problem(409, "stale-revision", "another device wrote first").with(json!({"itemId": first, "currentRevision": current})));
        }
        let mut parsed: Vec<(Option<u64>, WireItem)> = Vec::new();
        for write in writes {
            let Value::Object(write) = write else { return Err(Reply::bad("a write is an object")) };
            if let Some(key) = write.keys().find(|key| !["expectedRevision", "item", "tags", "tagVersion"].contains(&key.as_str())) {
                return Err(Reply::bad(&format!("unknown field `{key}`")));
            }
            let expected = match write.get("expectedRevision") {
                None | Some(Value::Null) => None,
                Some(n) => Some(n.as_u64().ok_or_else(|| Reply::bad("expectedRevision is a number"))?),
            };
            let wire: WireItem = serde_json::from_value(write.get("item").cloned().unwrap_or(Value::Null)).map_err(|e| Reply::bad(&format!("the item: {e}")))?;
            if parsed.iter().any(|(_, other)| other.id == wire.id) {
                return Err(Reply::bad("an item twice in a batch"));
            }
            parsed.push((expected, wire));
        }
        let account = &self.accounts[at];
        let owner = account.owner().to_string();
        let mut stale: Option<Reply> = None;
        for (expected, wire) in &parsed {
            let stored = account.items.get(&wire.id);
            if wire.owner != owner {
                return Err(Reply::problem(403, "forbidden", "not the account's vault"));
            }
            if wire.collection_id.is_some() {
                return Err(Reply::bad("an item of a vault has no collectionId"));
            }
            if Uuid::parse(&wire.id).is_err() || crate::kemlock::item::check_kind(&wire.kind).is_err() {
                return Err(Reply::problem(400, "invalid-item", "not an id or a kind"));
            }
            if self.accounts.iter().enumerate().any(|(other, a)| other != at && a.items.contains_key(&wire.id)) {
                return Err(Reply::problem(409, "already-exists", "the id is another account's"));
            }
            if *expected != stored.map(|s| s.wire.revision) {
                stale.get_or_insert_with(|| Reply::problem(409, "stale-revision", "the revision is not the stored one").with(json!({"itemId": wire.id, "currentRevision": stored.map(|s| s.wire.revision)})));
                continue;
            }
            let next = stored.map_or(1, |s| s.wire.revision + 1);
            if wire.revision != next || stored.is_some_and(|s| s.wire.kind != wire.kind || s.wire.format != wire.format) {
                return Err(Reply::problem(422, "invalid-revision", "an item can't change its kind or format, and its revision is the stored one plus one"));
            }
            if wire.format != "kem1" {
                return Err(Reply::problem(400, "invalid-item", "a client writes kem1 items"));
            }
            if wire.deleted {
                if wire.ciphertext.is_some() || wire.item_key.is_some() {
                    return Err(Reply::problem(400, "invalid-item", "a tombstone has no ciphertext"));
                }
            } else {
                let ciphertext = wire.ciphertext.as_deref().and_then(|c| b64_decode(c).ok());
                let item_key = wire.item_key.as_deref().and_then(|c| b64_decode(c).ok());
                match (ciphertext, item_key) {
                    (Some(c), Some(k)) if c.len() >= 28 && k.len() == 60 => {
                        if c.len() > 1024 * 1024 {
                            return Err(Reply::problem(413, "item-too-large", "the ciphertext is over 1 MiB"));
                        }
                    }
                    _ => return Err(Reply::problem(400, "invalid-item", "a live item has a ciphertext of 28 bytes or more and a 60-byte item key")),
                }
            }
        }
        if let Some(refusal) = stale {
            return Err(refusal);
        }
        let mut stored = Vec::new();
        for (_, wire) in parsed {
            let id = self.store(at, wire);
            let item = &self.accounts[at].items[&id];
            let mut value = serde_json::to_value(&item.wire).unwrap_or(Value::Null);
            if let Some(deleted_at) = &item.deleted_at {
                value["deletedAt"] = json!(deleted_at);
            }
            stored.push(value);
        }
        Ok(Reply::json(200, json!({"items": stored})))
    }

    fn get_manifest(&mut self, at: usize, owner: &str) -> R<Reply> {
        let account = &self.accounts[at];
        if owner != account.owner().to_string() {
            return Err(Reply::problem(403, "forbidden", "not the account's vault"));
        }
        if self.attacks.contains(&Attack::ManifestMissing) {
            return Err(Reply::problem(404, "not-found", "no manifest"));
        }
        let stored = if self.attacks.contains(&Attack::ManifestRolledBack) { account.manifests.first() } else { account.manifests.last() };
        let Some(stored) = stored else { return Err(Reply::problem(404, "not-found", "no manifest")) };
        let mut signature = stored.signature.clone();
        if self.attacks.contains(&Attack::ManifestBadSignature) {
            let len = signature.len();
            signature[len / 2] ^= 0x01;
        }
        Ok(Reply::json(
            200,
            json!({"owner": owner, "counter": stored.counter, "manifest": b64_encode(&stored.bytes), "signature": b64_encode(&signature),
                   "signer": account.id.to_string(), "storedAt": stored.stored_at}),
        ))
    }

    fn put_manifest(&mut self, request: &Request, at: usize, owner: &str) -> R<Reply> {
        let body = body_of(request, &["manifest", "signature"])?;
        if self.take_attack(|a| *a == Attack::StaleManifest).is_some() {
            let current = self.sign_manifest_at(at);
            return Err(Reply::problem(409, "stale-manifest", "another device signed first").with(json!({"currentCounter": current})));
        }
        let account = &self.accounts[at];
        if owner != account.owner().to_string() {
            return Err(Reply::problem(403, "forbidden", "not the account's vault"));
        }
        let (manifest, signature) = (bytes(&body, "manifest")?, bytes(&body, "signature")?);
        let parsed = Bundle::parse(&account.public_bundle)
            .map_err(|_| Reply::bad("the account has no bundle"))
            .and_then(|bundle| Manifest::parse_signed(&manifest, &signature, &bundle.sig1).map_err(|_| Reply::bad("the manifest or its signature is not good")))?;
        if parsed.owner != account.owner() {
            return Err(Reply::bad("the manifest is another owner's"));
        }
        let stored = account.manifests.last().map_or(0, |m| m.counter);
        if parsed.counter <= stored {
            return Err(Reply::problem(409, "stale-manifest", "the counter is not above the stored one").with(json!({"currentCounter": stored})));
        }
        let now = rfc3339(self.now());
        let id = self.accounts[at].id.to_string();
        let kept = StoredManifest { counter: parsed.counter, bytes: manifest, signature, stored_at: now };
        let answer = json!({"owner": owner, "counter": kept.counter, "manifest": b64_encode(&kept.bytes), "signature": b64_encode(&kept.signature), "signer": id, "storedAt": kept.stored_at});
        self.accounts[at].manifests.push(kept);
        Ok(Reply::json(200, answer))
    }

    // --- Files ----------------------------------------------------------------------------------------------------------------

    fn file_start(&mut self, request: &Request, at: usize, item: &str) -> R<Reply> {
        let body = body_of(request, &["size"])?;
        if Uuid::parse(item).is_err() {
            return Err(Reply::problem(404, "not-found", "no such item"));
        }
        if self.files_disabled {
            return Err(Reply::problem(403, "storage-disabled", "files are off"));
        }
        let size = body.get("size").and_then(Value::as_u64).ok_or_else(|| Reply::bad("size is a number"))?;
        if size > self.max_file {
            return Err(Reply::problem(413, "file-too-large", "the file is too large").with(json!({"maxSize": self.max_file})));
        }
        let file = Uuid::random_v4().to_string();
        self.accounts[at].files.insert(file.clone(), StoredFile { item: item.to_string(), size, bytes: None });
        let presigned = self.attacks.contains(&Attack::Presigned);
        Ok(Reply::json(
            201,
            json!({"fileId": file, "itemId": item, "size": size, "maxSize": self.max_file, "uploadUrl": format!("{}/kem/v1/items/{item}/files/{file}", self.domain), "presigned": presigned, "expiresIn": null}),
        ))
    }

    fn file_put(&mut self, request: &Request, at: usize, item: &str, file: &str) -> R<Reply> {
        let Some(held) = self.accounts[at].files.get_mut(file).filter(|f| f.item == item) else { return Err(Reply::problem(404, "not-found", "no such file")) };
        if held.bytes.is_some() {
            return Err(Reply::problem(409, "already-uploaded", "the file is there already"));
        }
        if !request.body.starts_with(crate::kemlock::kma1::MAGIC) {
            return Err(Reply::problem(415, "not-kma1", "the bytes are not a KMA1 file"));
        }
        if request.body.len() as u64 != held.size {
            return Err(Reply::problem(400, "length-mismatch", "the length is not the announced one"));
        }
        held.bytes = Some(request.body.to_vec());
        Ok(Reply::json(200, json!({"fileId": file, "itemId": item, "size": held.size, "status": "ready"})))
    }

    fn file_get(&mut self, at: usize, item: &str, file: &str) -> R<Reply> {
        let Some(held) = self.accounts[at].files.get(file).filter(|f| f.item == item) else { return Err(Reply::problem(404, "not-found", "no such file")) };
        let Some(bytes) = &held.bytes else { return Err(Reply::problem(404, "not-found", "the file is not ready")) };
        let mut bytes = bytes.clone();
        if self.attacks.contains(&Attack::FileTampered)
            && let Some(last) = bytes.last_mut()
        {
            *last ^= 1;
        }
        Ok(Reply { status: 200, body: bytes, headers: Vec::new() })
    }
}

impl Http for FakeKemlock {
    fn call(&mut self, request: Request) -> Result<Response, NetFailure> {
        let body = String::from_utf8_lossy(&request.body[..request.body.len().min(64 * 1024)]).to_string();
        self.seen.push(Seen { method: request.method.to_string(), url: request.url.clone(), headers: request.headers.iter().map(|(n, v)| (n.to_ascii_lowercase(), v.clone())).collect(), body });
        let Some(rest) = request.url.strip_prefix(self.listen.as_str()).filter(|rest| rest.starts_with('/')).map(str::to_string) else { return Err(NetFailure::NotAllowed) };
        let mut reply = match self.route(&request, &rest) {
            Ok(reply) | Err(reply) => reply,
        };
        reply.headers.push(("dpop-nonce".into(), self.nonce()));
        reply.headers.push(("date".into(), http_date(self.now())));
        Ok(Response { status: reply.status, body: Zeroizing::new(reply.body), headers: reply.headers })
    }
}
