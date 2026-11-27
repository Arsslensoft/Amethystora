//! Against the real Kemlock Server in a container (plans/vault-kemlock/spec-protocol.md section 11): the Vault's Kemlock back end
//! (`amethystora_vault_core::kemlock::sync`: sign-in, the run, the signed manifest, files), through this crate's own HTTP code,
//! to the published image, pinned by digest. Run by hand (`-- --ignored`). The accounts are made here, by test code only:
//! a Kemlock-only one through `/kem/v1/accounts/register`, a Compatible one through the Bitwarden API.
//!
//! The server's `DOMAIN` must be exactly the address the client uses, so the address is the one thing to agree on. Either start a
//! container on a user network and run cargo on the same network (nothing on the host is published):
//!
//! ```text
//! docker network create kemlock-interop
//! docker run -d --rm --name kemlock-test --network kemlock-interop -e DOMAIN=http://kemlock-test:8080 -e SIGNUPS_ALLOWED=true \
//!   -e KEMLOCK_RATE_SIGN_IN_PER_MINUTE=600 -e KEMLOCK_RATE_REGISTER_PER_HOUR=1000 \
//!   -e LOGIN_RATELIMIT_SECONDS=1 -e LOGIN_RATELIMIT_MAX_BURST=1000 -e UNAUTHENTICATED_RATELIMIT_SECONDS=1 -e UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000 \
//!   ghcr.io/arsslensoft/kemlock-server@sha256:efd2f339fd8b3844174e1d8f8c4b2c19af19a696296d58d5ec78e8ae362c6e6d
//! docker run --rm --network kemlock-interop -v amethystora-cargo:/root/.cargo/registry -v kemlock-engine-target:/target \
//!   -e CARGO_TARGET_DIR=/target -e KEMLOCK_TEST_ADDRESS=http://kemlock-test:8080 -v "$PWD/apps":/src -w /src \
//!   amethystora-rust-f45 cargo test --release --locked -p amethystora-vault-net --features plain-http-for-tests --test kemlock \
//!   -- --ignored --nocapture --test-threads=1
//! ```
//!
//! or, with `docker` on the PATH and no `KEMLOCK_TEST_ADDRESS`, let each test start its own container on a free loopback port
//! (`DOMAIN` set to that port) and remove it at the end. Plain http to a host that is not loopback is allowed by
//! `Session::plain_for_tests` only. Nothing here ever contacts a host that is not the one container.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use amethystora_vault_core::items::{Account, BackupCode, BackupService, OtpKind, Password, Secret};
use amethystora_vault_core::keys::{self, KeyType};
use amethystora_vault_core::kemlock::bundle::Bundle;
use amethystora_vault_core::kemlock::conv::{Owner, Uuid, b64_decode, b64_encode, item_uuid};
use amethystora_vault_core::kemlock::item::{Kem1Item, WireItem};
use amethystora_vault_core::kemlock::keys::{PrivateKeys, password_wrap_key, user_key, wrap_root_key};
use amethystora_vault_core::kemlock::manifest::{Entry, Manifest};
use amethystora_vault_core::kemlock::master::{self, DEFAULT_PARAMS, KdfParams};
use amethystora_vault_core::kemlock::opaque;
use amethystora_vault_core::kemlock::sync::account::{self, Account as KemAccount};
use amethystora_vault_core::kemlock::sync::api::{KemApi, Mode};
use amethystora_vault_core::kemlock::sync::dpop::DpopKey;
use amethystora_vault_core::kemlock::sync::engine::{self, Input};
use amethystora_vault_core::kemlock::sync::signin::{self, Attempt, Connected, Step};
use amethystora_vault_core::kemlock::sync::word;
use amethystora_vault_core::kemlock::{Key, RootKey};
use amethystora_vault_core::protocol::Approval;
use amethystora_vault_core::sync::address::Server;
use amethystora_vault_core::sync::api::{Extra, Http, NetFailure, Problem, Request, Response};
use amethystora_vault_core::sync::cipher::{self, Content, LOGIN};
use amethystora_vault_core::sync::convert::Direct;
use amethystora_vault_core::sync::crypto::{self, Kdf};
use amethystora_vault_core::sync::map::{self, Local};
use amethystora_vault_core::sync::merge::{self, Access, Connection, Link, Outcome};
use amethystora_vault_core::sync::register;
use amethystora_vault_net::http::Session;

const IMAGE: &str = "ghcr.io/arsslensoft/kemlock-server@sha256:efd2f339fd8b3844174e1d8f8c4b2c19af19a696296d58d5ec78e8ae362c6e6d";
const PASSWORD: &str = "a master password for the container";

// --- The server -------------------------------------------------------------------------------------------------------------

/// What the tests reach: an address, and the container this process started for it, if it did
struct Container {
    address: String,
    name: Option<String>,
}

impl Drop for Container {
    fn drop(&mut self) {
        if let Some(name) = &self.name {
            let _ = Command::new("docker").args(["rm", "-f", name]).stdout(Stdio::null()).stderr(Stdio::null()).status();
        }
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0").expect("a free port").local_addr().unwrap().port()
}

fn container() -> Container {
    let (address, name) = match std::env::var("KEMLOCK_TEST_ADDRESS") {
        Ok(address) if !address.is_empty() => (address.trim_end_matches('/').to_string(), None),
        _ => {
            let port = free_port();
            let name = format!("kemlock-interop-{}-{port}", std::process::id());
            let address = format!("http://127.0.0.1:{port}");
            let status = Command::new("docker")
                .args(["run", "-d", "--rm", "--name", &name, "-p", &format!("127.0.0.1:{port}:8080")])
                .args(["-e", &format!("DOMAIN={address}"), "-e", "SIGNUPS_ALLOWED=true", "-e", "KEMLOCK_RATE_SIGN_IN_PER_MINUTE=600", "-e", "KEMLOCK_RATE_REGISTER_PER_HOUR=1000"])
                .args(["-e", "LOGIN_RATELIMIT_SECONDS=1", "-e", "LOGIN_RATELIMIT_MAX_BURST=1000", "-e", "UNAUTHENTICATED_RATELIMIT_SECONDS=1", "-e", "UNAUTHENTICATED_RATELIMIT_MAX_BURST=1000", IMAGE])
                .stdout(Stdio::null())
                .status()
                .expect("docker is on the PATH, or KEMLOCK_TEST_ADDRESS names a running server");
            assert!(status.success(), "the server container did not start");
            (address, Some(name))
        }
    };
    let container = Container { address, name };
    // Ready when its own config answers
    let mut net = Net::new(&container.address);
    let started = Instant::now();
    loop {
        let ready = net.call(Request { method: "GET", url: format!("{}/kem/v1/config", container.address), headers: vec![("Accept", "application/json".into())], body: Zeroizing::new(Vec::new()) }).map(|r| r.status == 200).unwrap_or(false);
        if ready {
            return container;
        }
        assert!(started.elapsed() < Duration::from_secs(90), "the server did not answer in 90 s");
        std::thread::sleep(Duration::from_millis(500));
    }
}

/// Every request that left and how it was answered, for the checks that say what was and was not asked
static LOG: Mutex<Vec<(String, String, u16, String)>> = Mutex::new(Vec::new());

fn log_len() -> usize {
    LOG.lock().unwrap().len()
}

fn log_since(at: usize) -> Vec<(String, String, u16, String)> {
    LOG.lock().unwrap()[at..].to_vec()
}

fn path_of(url: &str) -> String {
    url.splitn(4, '/').nth(3).map(|rest| format!("/{rest}")).unwrap_or_default()
}

/// The crate's own HTTP, as the client's `Http`, headers and all
struct Net(Session);

impl Net {
    fn new(address: &str) -> Net {
        let origin = amethystora_vault_core::sync::address::origin_of(address).expect("an origin");
        Net(Session::plain_for_tests(vec![origin]))
    }
}

impl Http for Net {
    fn call(&mut self, request: Request) -> Result<Response, NetFailure> {
        let headers: Vec<(String, String)> = request.headers.iter().map(|(name, value)| (name.to_string(), value.clone())).collect();
        let reply = self.0.request_full(request.method, &request.url, &headers, &request.body).map_err(|failure| NetFailure::from_name(failure.name()))?;
        let slug = if reply.status >= 400 { serde_json::from_slice::<Value>(&reply.body).ok().and_then(|v| v["type"].as_str().map(|t| t.trim_start_matches("urn:kemlock:problem:").to_string())).unwrap_or_default() } else { String::new() };
        LOG.lock().unwrap().push((request.method.to_string(), path_of(&request.url), reply.status, slug));
        Ok(Response { status: reply.status, body: reply.body, headers: reply.headers })
    }
}

fn server_of(container: &Container) -> Server {
    Server::plain_for_tests(&container.address)
}

fn unique_email(name: &str) -> String {
    format!("{name}-{}@example.test", amethystora_vault_core::seal::random_hex(4))
}

// --- Making accounts --------------------------------------------------------------------------------------------------------

/// A Kemlock-only account, as the Kemlock app makes one (`spec-protocol.md` 2.9), with the real Argon2id
fn register_kemlock(net: &mut Net, server: &Server, email: &str, password: &str) -> String {
    let key = DpopKey::generate();
    let mut api = KemApi::new(net, server, &key);
    let mut salt = [0u8; 16];
    amethystora_vault_core::seal::random(&mut salt);
    let master = master::master_key(password, &salt, &DEFAULT_PARAMS).expect("Argon2id");
    let (state, request) = opaque::registration_start(&master).expect("registration starts");
    let start = api.send("POST", "/accounts/register/start", Some(serde_json::to_vec(&json!({"email": email, "request": b64_encode(&request)})).unwrap()), "application/json", Mode::Open, &[]).expect("an answer");
    assert_eq!(start.status, 200, "register/start: {}", String::from_utf8_lossy(&start.body));
    let response = b64_decode(start.json().unwrap()["response"].as_str().unwrap()).unwrap();
    let registered = opaque::registration_finish(state, &master, &response).expect("registration finishes");
    let id = Uuid::random_v4();
    let root = RootKey::random();
    let private = PrivateKeys::generate();
    let bundle = Bundle { account_id: id, key_version: 1, kx1: private.kx1.public_key(), sig1: private.sig1.public_key() };
    let signature = bundle.sign(&private.sig1).unwrap();
    let sealed = private.seal(&user_key(&root), &id, 1);
    let wrapped = wrap_root_key(&root, &password_wrap_key(&master, registered.export_key.as_bytes()), &id, 1);
    let body = json!({
        "email": email,
        "userId": id.to_string(),
        "upload": b64_encode(&registered.upload),
        "kdf": {"memoryKib": DEFAULT_PARAMS.memory_kib, "iterations": DEFAULT_PARAMS.iterations, "parallelism": DEFAULT_PARAMS.parallelism, "salt": b64_encode(&salt)},
        "publicBundle": b64_encode(&bundle.to_bytes()),
        "bundleSignature": b64_encode(&signature),
        "sealedPrivateKeys": b64_encode(&sealed),
        "wrappedRootKey": b64_encode(&wrapped),
    });
    let finish = api.send("POST", "/accounts/register/finish", Some(serde_json::to_vec(&body).unwrap()), "application/json", Mode::Open, &[]).expect("an answer");
    assert_eq!(finish.status, 201, "register/finish: {}", String::from_utf8_lossy(&finish.body));
    id.to_string()
}

fn bw_kdf() -> Kdf {
    Kdf { kind: 0, iterations: 600_000, memory: None, parallelism: None }
}

/// A raw call to the Bitwarden API, as a second client would make it
fn bw_raw(net: &mut Net, method: &'static str, url: &str, access: &str, body: Option<&Value>) -> (u16, Value) {
    let headers = vec![
        ("Accept", "application/json".to_string()),
        ("Content-Type", "application/json".to_string()),
        ("Device-Type", "8".to_string()),
        ("Authorization", format!("Bearer {access}")),
        ("Bitwarden-Client-Version", amethystora_vault_core::sync::CLIENT_VERSION.to_string()),
    ];
    let body = Zeroizing::new(body.map(|body| serde_json::to_vec(body).unwrap()).unwrap_or_default());
    let response = net.call(Request { method, url: url.to_string(), headers, body }).expect("an answer");
    (response.status, serde_json::from_slice(&response.body).unwrap_or(Value::Null))
}

/// A Compatible account: made through the Bitwarden API, no Kemlock keys. Returns the Bitwarden device identifier its login used
/// and the user key as the Bitwarden API keeps it, with one cipher made there.
fn register_compatible(net: &mut Net, server: &Server, email: &str) -> (String, Vec<u8>, String) {
    register::register(net, &server.identity, email, PASSWORD, &bw_kdf()).expect("registered through Bitwarden's API");
    let device = merge::new_device_id();
    let pending = merge::prepare(net, &crypto::master_key, server.clone(), email, PASSWORD.as_bytes(), None, None, None, device.clone()).expect("prelogin");
    let (connection, access) = merge::finish(net, &pending, &Extra::default()).expect("a Bitwarden login");
    let user = connection.key().expect("the user key");
    let content = Content { kind: LOGIN, name: "A Bitwarden login".into(), username: Some("person".into()), password: Some("bw-secret-1".into()), uri: Some("https://example.test/bw".into()), ..Content::default() };
    let body = cipher::create_body(&content, &connection.user_id, &user).unwrap();
    let (status, created) = bw_raw(net, "POST", &format!("{}/ciphers", server.api), &access.token, Some(&body));
    assert_eq!(status, 200, "{created}");
    (device, user.bytes().to_vec(), created["id"].as_str().unwrap().to_string())
}

// --- A device of the person's -----------------------------------------------------------------------------------------------

fn derive(password: &str, salt: &[u8], params: &KdfParams) -> Result<Key, Problem> {
    master::master_key(password, salt, params).map_err(|_| Problem::CannotOpen)
}

struct Settings<'a> {
    device_id: Option<&'a str>,
    bitwarden_device: Option<&'a str>,
    opaque_seen: bool,
    second: Option<(&'a str, &'a str)>,
}

fn sign_in(net: &mut Net, server: &Server, email: &str, password: &str, settings: &Settings<'_>) -> Result<Step, Problem> {
    let key = DpopKey::generate();
    let attempt = Attempt {
        server,
        email,
        password,
        confirmed: None,
        second: settings.second.map(|(method, code)| signin::Second { method, code }),
        send_email: false,
        pinned: None,
        device_id: settings.device_id,
        bitwarden_device: settings.bitwarden_device,
        opaque_seen: settings.opaque_seen,
        dpop: &key,
    };
    signin::sign_in(net, &attempt, &derive, &crypto::master_key)
}

fn connected(step: Result<Step, Problem>) -> Connected {
    match step {
        Ok(Step::Connected(connected)) => *connected,
        Ok(Step::EmailSent(_)) => panic!("an email's code was asked for"),
        Err(problem) => panic!("not connected: {problem:?}"),
    }
}

struct Client {
    connection: Connection,
    access: Option<Access>,
    locals: BTreeMap<(String, String), Local>,
    links: BTreeMap<String, Link>,
    /// Every refresh token handed to the service to keep, in order, with the number of requests that had left when it was
    persisted: Vec<(String, usize)>,
    now_ms: i64,
}

fn connection_of(done: &Connected, server: &Server, email: &str) -> Connection {
    Connection {
        address: server.address.clone(),
        identity: server.identity.clone(),
        api: server.api.clone(),
        email: email.to_string(),
        user_id: done.tokens.user_id.clone(),
        user_key: amethystora_vault_core::seal::hex(done.root.as_bytes()),
        protected_key: String::new(),
        kdf: Kdf { kind: 1, iterations: 3, memory: Some(64), parallelism: Some(4) },
        device: "dev-1".into(),
        api_key: None,
        refresh: Some(done.tokens.refresh.to_string()),
        remember: None,
        ca: None,
        pin: None,
        choices: BTreeMap::new(),
        kinds: BTreeMap::new(),
        no_files: None,
        files_read: false,
        pending: Vec::new(),
        last_revision: None,
        last_success_ms: None,
        last: None,
        waiting_since_ms: None,
        recent: Vec::new(),
        kemlock: Some(done.state.clone()),
    }
}

impl Client {
    fn from(done: &Connected, server: &Server, email: &str) -> Client {
        Client { connection: connection_of(done, server, email), access: None, locals: BTreeMap::new(), links: BTreeMap::new(), persisted: Vec::new(), now_ms: merge::now_ms() }
    }

    fn connect(net: &mut Net, server: &Server, email: &str, settings: &Settings<'_>) -> Client {
        let done = connected(sign_in(net, server, email, PASSWORD, settings));
        Client::from(&done, server, email)
    }

    fn state(&self) -> &amethystora_vault_core::kemlock::sync::state::KemlockState {
        self.connection.kemlock.as_ref().unwrap()
    }

    fn server(&self) -> Server {
        self.connection.server()
    }

    fn key(&self) -> DpopKey {
        DpopKey::from_hex(&self.state().dpop_key).unwrap()
    }

    fn account(&self) -> KemAccount {
        account::open_state(&self.connection.user_key, &self.connection.user_id, self.state()).expect("the account opens")
    }

    fn put(&mut self, kind: &str, id: &str, value: Value) {
        let name = map::name_of(kind, &value);
        self.locals.insert((kind.into(), id.into()), Local { kind: kind.into(), id: id.into(), name, meta: Value::Null, approval: Approval::WhileOpen, value });
    }

    fn add(&mut self, local: Local) {
        self.locals.insert((local.kind.clone(), local.id.clone()), local);
    }

    fn value(&self, kind: &str, id: &str) -> Value {
        self.locals.get(&(kind.into(), id.into())).map(|local| local.value.clone()).unwrap_or(Value::Null)
    }

    fn edit(&mut self, kind: &str, id: &str, change: impl FnOnce(&mut Value)) {
        let local = self.locals.get_mut(&(kind.to_string(), id.to_string())).expect("an item to edit");
        change(&mut local.value);
        local.name = map::name_of(kind, &local.value);
    }

    fn sync(&mut self, net: &mut Net) -> Outcome {
        let log = RefCell::new(Vec::new());
        let persist = |token: &str| {
            log.borrow_mut().push((token.to_string(), log_len()));
            true
        };
        let input = Input {
            connection: self.connection.clone(),
            access: self.access.take(),
            links: self.links.values().cloned().collect(),
            locals: self.locals.values().cloned().collect(),
            accept: false,
            full: false,
            now_ms: self.now_ms,
            local_unreadable: 0,
            links_unreadable: false,
        };
        let mut outcome = engine::run(net, &Direct, input, &persist);
        self.persisted.extend(log.into_inner());
        self.apply(&mut outcome);
        outcome
    }

    /// As the service applies a run: a group whose basis no longer holds is skipped whole
    fn apply(&mut self, outcome: &mut Outcome) {
        let mut skipped = std::collections::HashSet::new();
        for group in outcome.groups.drain(..) {
            let holds = group.basis.iter().all(|basis| self.locals.get(&(basis.kind.clone(), basis.id.clone())).map(map::hash) == basis.hash);
            if skipped.contains(&group.cipher) || !holds {
                skipped.insert(group.cipher.clone());
                continue;
            }
            for write in group.writes {
                self.locals.insert((write.kind.clone(), write.id.clone()), Local { kind: write.kind, id: write.id, name: write.name, meta: write.meta, approval: write.approval, value: write.value });
            }
            match group.link {
                Some(link) => {
                    self.links.insert(group.cipher, link);
                }
                None => {
                    self.links.remove(&group.cipher);
                }
            }
        }
        if let Some(refresh) = &outcome.refresh {
            self.connection.refresh = Some(refresh.to_string());
        }
        self.access = outcome.access.take();
        if let (Some(news), Some(state)) = (outcome.kemlock.take(), self.connection.kemlock.as_mut()) {
            state.apply(news);
        }
    }

    /// An access token, from the last run or a refresh, for the calls the test makes itself
    fn token(&mut self, net: &mut Net) -> Zeroizing<String> {
        if let Some(access) = &self.access
            && access.until_ms > merge::now_ms() + 30_000
        {
            return access.token.clone();
        }
        let (server, key) = (self.server(), self.key());
        let mut api = KemApi::new(net, &server, &key);
        let tokens = api.refresh(self.connection.refresh.as_deref().unwrap()).expect("a refresh");
        self.connection.refresh = Some(tokens.refresh.to_string());
        self.access = Some(Access { token: tokens.access.clone(), until_ms: merge::now_ms() + tokens.expires_in * 1000 });
        tokens.access
    }

    /// A call of the test's own on this device's session
    fn with_api<R>(&mut self, net: &mut Net, call: impl FnOnce(&mut KemApi<'_>) -> R) -> R {
        let token = self.token(net);
        let (server, key) = (self.server(), self.key());
        let mut api = KemApi::new(net, &server, &key);
        api.access = Some(token);
        call(&mut api)
    }
}

// --- The makers of items ----------------------------------------------------------------------------------------------------

fn password(title: &str, username: &str, secret: &str, address: &str) -> Value {
    serde_json::to_value(Password { title: title.into(), username: username.into(), password: Secret::new(secret), address: address.into(), added_at: 1_760_000_000_000, ..Password::default() }).unwrap()
}

fn with_id(mut value: Value, id: &str) -> Value {
    value["id"] = json!(id);
    value
}

fn key_local(id: &str, name: &str, key_kind: &str, key_type: KeyType) -> Local {
    let key = keys::generate(key_type).unwrap();
    let public = key.public().ok();
    let public_json = public.as_ref().map_or(Value::Null, |forms| json!({"type": key_type.name(), "pem": forms.spki_pem, "openssh": forms.openssh, "sha256": forms.sha256, "ssh_sha256": forms.ssh_sha256}));
    let value = json!({"key_kind": key_kind, "type": key_type.name(), "key": B64.encode(key.as_bytes()), "exportable": true, "public": public_json, "comment": null});
    let meta = json!({"key_kind": key_kind, "type": key_type.name(), "exportable": true});
    Local { kind: "key".into(), id: id.into(), name: name.into(), meta, approval: Approval::WhileOpen, value }
}

/// A self-signed certificate of an Ed25519 key, as the vault's own certificate item holds one
fn cert_local(id: &str, name: &str) -> Local {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let pkey = openssl::pkey::PKey::generate_ed25519().unwrap();
    let pkcs8 = pkey.private_key_to_pkcs8().unwrap();
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut builder = X509Builder::new().unwrap();
    builder.set_version(2).unwrap();
    builder.set_serial_number(&BigNum::from_u32(7).unwrap().to_asn1_integer().unwrap()).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(&pkey).unwrap();
    builder.set_not_before(&Asn1Time::days_from_now(0).unwrap()).unwrap();
    builder.set_not_after(&Asn1Time::days_from_now(365).unwrap()).unwrap();
    builder.sign(&pkey, MessageDigest::null()).unwrap();
    let der = builder.build().to_der().unwrap();
    let told = amethystora_vault_core::pki::describe(&der).unwrap();
    let value = json!({"profile": "code", "type": "ed25519", "key": B64.encode(&pkcs8), "cert": B64.encode(&der), "chain": [], "fields": {}});
    let meta = json!({"profile": "code", "subject": told.subject, "issuer": told.issuer, "not_before": told.not_before, "not_after": told.not_after, "sha256": told.sha256, "spki_sha256": told.key.sha256, "key_type": "ed25519"});
    Local { kind: "certificate".into(), id: id.into(), name: name.into(), meta, approval: Approval::WhileOpen, value }
}

/// A file bigger than one KMA1 chunk, so that the server keeps more than one
fn file_local(id: &str, path: &str, bytes: &[u8]) -> Local {
    let value = json!({"what": "file", "files": [{"at": "", "mode": 0o600, "data": B64.encode(bytes)}], "folders": []});
    Local { kind: "protected".into(), id: id.into(), name: path.into(), meta: json!({"path": path, "what": "file", "size": bytes.len(), "files": 1}), approval: Approval::WhileOpen, value }
}

fn folder_local(id: &str, path: &str) -> Local {
    let value = json!({"what": "folder", "files": [{"at": "a/one.txt", "mode": 0o600, "data": B64.encode(b"one")}, {"at": "two.bin", "mode": 0o644, "data": B64.encode(vec![9u8; 6000])}], "folders": [{"at": "a", "mode": 0o700}]});
    Local { kind: "protected".into(), id: id.into(), name: path.into(), meta: json!({"path": path, "what": "folder", "files": 2}), approval: Approval::WhileOpen, value }
}

struct Ids {
    password: &'static str,
    account: &'static str,
    codes: &'static str,
    other: &'static str,
}

/// Ids that are UUIDs are the server's ids as they are, for every account of the server: so each account gets its own
fn fresh_ids() -> Ids {
    let leak = || -> &'static str { Box::leak(Uuid::random_v4().to_string().into_boxed_str()) };
    Ids { password: leak(), account: leak(), codes: leak(), other: leak() }
}

const SSH_ID: &str = "3f2c9a71e4b0d856";
const EXCHANGE_ID: &str = "a07c5e19d2b34f60";
const AES_ID: &str = "b6e1f3a2c4d58e97";
const CERT_ID: &str = "5e8a0f2c71b94d36";
const FILE_ID: &str = "d93b0e7a5f214c68";
const FOLDER_ID: &str = "0aa1b2c3d4e5f607";

/// A file of 70 000 bytes: two KMA1 chunks
fn big_file() -> Vec<u8> {
    (0..70_000u32).map(|n| (n % 251) as u8).collect()
}

/// Every kind the Vault sends, under ids of the vault's own (16 hex characters for what is not a UUID)
fn every_kind(client: &mut Client, ids: &Ids) {
    client.put("password", ids.password, with_id(password("Larkspur Mail", "sam@example.org", "cobalt-otter-41", "https://mail.larkspur.example/login"), ids.password));
    let totp = Account { kind: Some(OtpKind::Totp), issuer: "GitHub".into(), label: "sam".into(), secret: Secret::new("JBSWY3DPEHPK3PXP"), added_at: 1_760_000_000_000, ..Account::default() };
    client.put("authenticator", ids.account, with_id(serde_json::to_value(totp).unwrap(), ids.account));
    let codes = BackupService { service_name: "GitHub".into(), codes: vec![BackupCode::new("1111-2222"), BackupCode::new("3333-4444")], added_at: 1_760_000_000_000, ..BackupService::default() };
    client.put("backup-codes", ids.codes, with_id(serde_json::to_value(codes).unwrap(), ids.codes));
    client.add(key_local(SSH_ID, "laptop", "ssh", KeyType::Ed25519));
    client.add(key_local(EXCHANGE_ID, "backup recipient", "exchange", KeyType::X25519));
    client.add(key_local(AES_ID, "disk image key", "symmetric", KeyType::Aes256));
    client.add(cert_local(CERT_ID, "Document signing"));
    client.add(file_local(FILE_ID, "tax-2025.pdf", &big_file()));
    client.add(folder_local(FOLDER_ID, "keys"));
}

fn expected_kinds(ids: &Ids) -> [(&str, &str, &str); 9] {
    [
    ("password", ids.password, "login"),
    ("authenticator", ids.account, "otp"),
    ("backup-codes", ids.codes, "backup-codes"),
    ("key", SSH_ID, "ssh-key"),
    ("key", EXCHANGE_ID, "key"),
    ("key", AES_ID, "note"),
    ("certificate", CERT_ID, "certificate"),
    ("protected", FILE_ID, "note"),
    ("protected", FOLDER_ID, "note"),
    ]
}

// --- What the server holds --------------------------------------------------------------------------------------------------

fn sha256(bytes: &[u8]) -> [u8; 32] {
    openssl::sha::sha256(bytes)
}

fn assert_clean(outcome: &Outcome, what: &str) {
    if outcome.problem.is_some() {
        let log = LOG.lock().unwrap();
        for line in log.iter().skip(log.len().saturating_sub(40)) {
            eprintln!("  {} {} -> {} {}", line.0, line.1, line.2, line.3);
        }
    }
    assert!(outcome.problem.is_none(), "{what}: the run stopped: {:?}", outcome.problem);
}

/// The server's whole sync, from no cursor
fn server_items(net: &mut Net, client: &mut Client) -> Vec<WireItem> {
    let mut items = Vec::new();
    let mut since: Option<String> = None;
    loop {
        let page = client.with_api(net, |api| api.sync(since.as_deref())).expect("a token").ok().expect("no 410").expect("a page");
        items.extend(page.items);
        if !page.more {
            return items;
        }
        since = Some(page.cursor);
    }
}

fn plain_of(client: &Client, wire: &WireItem) -> Value {
    let account = client.account();
    let (_, json) = wire.kem1().expect("a kem1 item").open(&account.item_wrap).expect("it opens under the account's keys");
    serde_json::from_slice(&json).expect("JSON")
}

fn server_id(client: &Client, vault_id: &str) -> String {
    item_uuid(&Owner::user(client.account().id), vault_id).to_string()
}

fn find<'a>(items: &'a [WireItem], id: &str) -> &'a WireItem {
    items.iter().find(|item| item.id == id).unwrap_or_else(|| panic!("{id} is not on the server"))
}

/// The manifest the server holds, verified under the account's own `sig1` key
fn server_manifest(net: &mut Net, client: &mut Client) -> Option<Manifest> {
    let owner = Owner::user(client.account().id).to_string();
    let answer = client.with_api(net, |api| api.manifest(&owner)).expect("a token")?;
    let bytes = b64_decode(answer["manifest"].as_str().unwrap()).unwrap();
    let signature = b64_decode(answer["signature"].as_str().unwrap()).unwrap();
    assert_eq!(answer["counter"].as_u64(), Manifest::parse(&bytes).ok().map(|m| m.counter), "the counter the server says is the one in the bytes");
    assert_eq!(answer["signer"].as_str(), Some(client.connection.user_id.as_str()));
    Some(Manifest::parse_signed(&bytes, &signature, &client.account().sig_public).expect("the manifest verifies under the account's sig1"))
}

/// What a Kemlock app does after it writes: signs a manifest above the stored one, listing every item the server serves
fn kemlock_app_signs(net: &mut Net, client: &mut Client) {
    let items = server_items(net, client);
    let counter = server_manifest(net, client).map_or(0, |m| m.counter);
    let account = client.account();
    let owner = Owner::user(account.id);
    let entries: Vec<Entry> = items
        .iter()
        .filter(|item| item.owner == owner.to_string())
        .map(|item| {
            let id = Uuid::parse(&item.id).unwrap();
            if item.deleted { Entry::tombstone(id, item.revision) } else { Entry::live(id, item.revision, &b64_decode(item.ciphertext.as_deref().unwrap()).unwrap()) }
        })
        .collect();
    let manifest = Manifest::new(owner, counter + 1, entries).unwrap();
    let (bytes, signature) = (manifest.to_bytes(), manifest.sign(&account.sig_private).unwrap());
    let owner_text = owner.to_string();
    let put = client.with_api(net, |api| api.put_manifest(&owner_text, &bytes, &signature)).expect("a token");
    assert!(put.is_ok(), "the server did not take a manifest signed above its own: {put:?}");
}

fn requests(since: usize, method: &str, needle: &str) -> usize {
    log_since(since).iter().filter(|(m, path, _, _)| m == method && path.contains(needle)).count()
}

// --- The scenario both kinds of account go through ---------------------------------------------------------------------------

/// What the person's vault holds, as the items the other client must equal
fn vault_of(client: &Client) -> BTreeMap<(String, String), Value> {
    client.locals.iter().filter(|(_, local)| !map::deleted(local)).map(|(key, local)| (key.clone(), local.value.clone())).collect()
}

/// `bw_ciphers`: the ids of the account's Bitwarden ciphers, which the Kemlock API lists as `bw` items and the run must leave alone
fn scenario(net: &mut Net, server: &Server, email: &str, first: &mut Client, bw_ciphers: &[String], ids: &Ids) {
    // --- The first device sends everything: one run, every kind, the files first, then the notes, then the manifest
    every_kind(first, ids);
    let first_run = log_len();
    let outcome = first.sync(net);
    assert_clean(&outcome, "the first run");
    assert_eq!(outcome.report.created_there, 9, "refused: {:?}", outcome.report.refused);
    // A run's first request carries no nonce: the server's `use-dpop-nonce` is answered by one retry
    let seen = log_since(first_run);
    assert!(seen.iter().any(|(_, _, status, slug)| *status == 401 && slug == "use-dpop-nonce"), "no nonce round trip in a first run: {seen:?}");
    let retried = seen.iter().position(|(_, _, status, slug)| *status == 401 && slug == "use-dpop-nonce").unwrap();
    assert!(seen[retried + 1].2 < 400, "the retry with the server's nonce was refused: {:?}", seen[retried + 1]);
    // Files: the slot, the bytes, then the batch of notes, for each of the two
    let paths: Vec<String> = seen.iter().map(|(method, path, _, _)| format!("{method} {path}")).filter(|p| p.contains("/files") || p.contains("items:batch")).collect();
    let batch_at = paths.iter().position(|p| p.ends_with("items:batch")).expect("a batch");
    let uploads_before_batch = paths[..batch_at].iter().filter(|p| p.starts_with("PUT ") && p.contains("/files/")).count();
    assert_eq!(uploads_before_batch, 2, "the two files are uploaded before the notes that name them: {paths:?}");
    assert_eq!(paths.iter().filter(|p| p.starts_with("POST ") && p.ends_with("/files")).count(), 2, "{paths:?}");

    let items = server_items(net, first);
    for (_, vault_id, kind) in expected_kinds(ids) {
        let wire = find(&items, &server_id(first, vault_id));
        assert_eq!((wire.kind.as_str(), wire.format.as_str(), wire.revision, wire.key_version, wire.deleted), (kind, "kem1", 1, 1, false), "{vault_id}");
        assert_eq!(plain_of(first, wire)["id"], vault_id, "the vault's own id is inside the item");
    }
    // The bw copies of a Compatible account are listed, in their format, and were not touched
    for cipher in bw_ciphers {
        let wire = find(&items, cipher);
        assert_eq!((wire.format.as_str(), wire.key_version, wire.revision, wire.deleted), ("bw", 0, 1, false), "{cipher}");
        assert!(wire.item_key.is_none());
    }
    assert_eq!(items.len(), 9 + bw_ciphers.len());
    // A file: KMA1 bytes of 70 000 bytes, two chunks, and a note naming it
    let file_wire = find(&items, &server_id(first, FILE_ID));
    let file_plain = plain_of(first, file_wire);
    assert!(file_plain["attachments"][0]["kemlockFile"].is_string(), "{file_plain}");
    let (file_server, size) = (file_plain["attachments"][0]["kemlockFile"].as_str().unwrap().to_string(), file_plain["attachments"][0]["size"].as_u64().unwrap() as usize);
    let stored = first.with_api(net, |api| api.file_download(&file_wire.id, &file_server, 1 << 20)).expect("a token").expect("a file");
    assert_eq!((size, stored.len()), (70_000, amethystora_vault_core::kemlock::kma1::sealed_len(70_000)), "two chunks: 12 + 70000 + 2 * 16");
    assert!(stored.starts_with(b"KMA1"));
    let key = amethystora_vault_core::kemlock::sync::items::attachment_key(&file_plain["attachments"][0]).expect("the attachment's key");
    assert_eq!(&amethystora_vault_core::kemlock::kma1::decrypt(&key, &stored, 1 << 20).expect("the file opens with its key")[..], &big_file()[..]);
    assert!(amethystora_vault_core::kemlock::kma1::decrypt(&Key::random(), &stored, 1 << 20).is_err());
    let bw_before: Vec<(String, Option<String>)> = bw_ciphers.iter().map(|id| (id.clone(), find(&items, id).ciphertext.clone())).collect();
    // The manifest: signed by the account, one entry for each item including the bw ones (by the hash of the cipher's bytes)
    let manifest = server_manifest(net, first).expect("a manifest");
    assert_eq!(manifest.counter, 1);
    assert_eq!(manifest.entries.len(), items.len());
    for entry in &manifest.entries {
        let wire = find(&items, &entry.item_id.to_string());
        assert_eq!((entry.revision, entry.deleted), (wire.revision, wire.deleted));
        assert_eq!(entry.ciphertext_hash, sha256(&b64_decode(wire.ciphertext.as_deref().unwrap()).unwrap()), "{}", wire.id);
    }
    assert_eq!(first.state().manifest_counter, 1);
    assert!(first.state().cursor.is_some());
    // Nothing the person keeps secret went out in the clear
    // (the proofs and bodies are not logged here: the fake's tests grep every body; this checks only the paths)
    assert!(requests(first_run, "POST", "/accounts/register") == 0);

    // --- A second device, its own key and session: it reads everything back
    let settings = Settings { device_id: None, bitwarden_device: None, opaque_seen: true, second: None };
    let mut second = Client::connect(net, server, email, &settings);
    assert_ne!(second.state().device_id, first.state().device_id, "a second device of its own");
    assert_ne!(second.state().dpop_key, first.state().dpop_key);
    // A certificate and a protected file are paired, never made from the server's (a certificate's chain, a file's bytes and mode are the vault's)
    for key in [("certificate", CERT_ID), ("protected", FILE_ID), ("protected", FOLDER_ID)] {
        second.add(first.locals[&(key.0.to_string(), key.1.to_string())].clone());
    }
    let before = log_len();
    let outcome = second.sync(net);
    assert_clean(&outcome, "the second device's first run");
    assert_eq!(outcome.report.sent, 0, "pairing wrote something: {:?}", outcome.report.refused);
    assert_eq!(outcome.report.created_here, 6, "{:?}", outcome.report.refused);
    // It downloaded the two files the notes name, to check they open
    assert_eq!(requests(before, "GET", "/files/"), 2);
    let (a, b) = (vault_of(first), vault_of(&second));
    assert_eq!(a.keys().collect::<Vec<_>>(), b.keys().collect::<Vec<_>>());
    for (key, value) in &a {
        assert_eq!(&b[key], value, "{key:?} differs between the two devices");
    }
    assert_eq!(server_manifest(net, first).unwrap().counter, 1, "reading wrote no manifest");
    assert_eq!(second.state().manifest_counter, 1);

    // --- An edit on the second device goes to the first; each writing run signs a manifest above the last
    second.edit("password", ids.password, |value| {
        value["password"] = json!("cobalt-otter-99");
        value["updatedAt"] = json!(1_770_000_000_000i64);
    });
    assert_clean(&second.sync(net), "an edit on the second");
    let id = server_id(first, ids.password);
    let wire = find(&server_items(net, &mut second), &id).clone();
    assert_eq!(wire.revision, 2);
    assert_eq!(plain_of(&second, &wire)["password"], "cobalt-otter-99");
    assert_eq!(server_manifest(net, &mut second).unwrap().counter, 2);
    let outcome = first.sync(net);
    assert_clean(&outcome, "the first reads the edit");
    assert_eq!(outcome.report.received, 1);
    assert_eq!(first.value("password", ids.password)["password"], "cobalt-otter-99");

    // --- A conflict: both edit, the first writes first, the later change wins and the password it replaced is kept
    first.edit("password", ids.password, |value| {
        value["password"] = json!("pA");
        value["updatedAt"] = json!(1_770_000_001_000i64);
    });
    second.edit("password", ids.password, |value| {
        value["password"] = json!("pB");
        value["updatedAt"] = json!(1_770_000_002_000i64);
    });
    assert_clean(&first.sync(net), "the first edit of the conflict");
    let outcome = second.sync(net);
    assert_clean(&outcome, "the conflict");
    assert_eq!(outcome.report.conflicts, 1);
    let wire = find(&server_items(net, &mut second), &id).clone();
    assert_eq!(wire.revision, 4);
    let plain = plain_of(&second, &wire);
    assert_eq!(plain["password"], "pB", "the later change wins as a whole");
    assert!(plain["previousPasswords"].as_array().unwrap().iter().any(|old| old["password"] == "pA"), "nothing is lost: {plain}");
    assert_clean(&first.sync(net), "the first reads the winner");
    assert_eq!(first.value("password", ids.password)["password"], "pB");
    assert!(first.value("password", ids.password)["history"].as_array().unwrap().iter().any(|old| old["password"] == "pA"));
    assert_eq!(server_manifest(net, first).unwrap().counter, 4);

    // --- A deletion in the vault is a tombstone there; the other device trashes it
    first.edit("authenticator", ids.account, |value| value["deletedAt"] = json!(1_770_000_003_000i64));
    assert_clean(&first.sync(net), "a trash");
    let items = server_items(net, first);
    let tomb = find(&items, &server_id(first, ids.account));
    assert!(tomb.deleted && tomb.ciphertext.is_none() && tomb.kind == "otp" && tomb.revision == 2, "{tomb:?}");
    let manifest = server_manifest(net, first).unwrap();
    assert!(manifest.entries.iter().any(|entry| entry.item_id.to_string() == tomb.id && entry.deleted && entry.ciphertext_hash == [0u8; 32]));
    let outcome = second.sync(net);
    assert_clean(&outcome, "the tombstone");
    assert_eq!(outcome.report.trashed_here, 1);
    assert!(map::deleted(&second.locals[&("authenticator".to_string(), ids.account.to_string())]), "it is in the second vault's own trash");

    // --- An item another writer made: a kem1 login sealed with the account's keys under an id of its own, as the Kemlock app writes
    let account = first.account();
    let owner = Owner::user(account.id);
    let planted_id = Uuid::parse(ids.other).unwrap();
    let plain = json!({"id": ids.other, "name": "Router", "username": "admin", "password": "r0uter-pass", "websites": ["192.168.1.1"], "note": "from the Kemlock app", "addedAt": 1_761_000_000_000i64, "updatedAt": 1_761_000_000_000i64});
    let sealed = Kem1Item::seal(&account.item_wrap, account.key_version, planted_id, owner, "login", 1, &serde_json::to_vec(&plain).unwrap()).unwrap().to_wire();
    let batch = first.with_api(net, |api| api.batch(&[(None, &sealed)])).expect("a token");
    assert!(batch.is_ok(), "{batch:?}");
    kemlock_app_signs(net, first);
    let outcome = first.sync(net);
    assert_clean(&outcome, "reading an item another writer made");
    assert_eq!(outcome.report.created_here, 1);
    let taken = first.value("password", ids.other);
    assert_eq!((taken["title"].as_str(), taken["username"].as_str(), taken["password"].as_str()), (Some("Router"), Some("admin"), Some("r0uter-pass")), "{taken}");
    assert_clean(&second.sync(net), "the second reads it too");
    assert_eq!(second.value("password", ids.other), taken);

    // --- The signed manifest: the Kemlock app's, over ours, the second device verifies it and goes above it
    let counter_app = server_manifest(net, first).unwrap().counter;
    second.edit("password", ids.password, |value| {
        value["password"] = json!("pC");
        value["updatedAt"] = json!(1_770_000_004_000i64);
    });
    assert_clean(&second.sync(net), "a run over the app's manifest");
    assert_eq!(server_manifest(net, &mut second).unwrap().counter, counter_app + 1);
    assert_clean(&first.sync(net), "the first catches up");

    // --- A token refresh: the engine is given no access token, refreshes, hands the new refresh token over before it uses it
    let old_refresh = first.connection.refresh.clone().unwrap();
    first.access = None;
    first.persisted.clear();
    let before = log_len();
    assert_clean(&first.sync(net), "a run with no access token");
    assert_eq!(first.persisted.len(), 1, "one refresh, one token kept");
    let (kept, at) = first.persisted[0].clone();
    assert_ne!(kept, old_refresh, "the refresh token rotated");
    assert_eq!(Some(&kept), first.connection.refresh.as_ref());
    let seen = log_since(before);
    assert_eq!(seen[0].1, "/kem/v1/auth/token", "{seen:?}");
    let first_token_call = seen.iter().position(|(_, path, status, _)| path == "/kem/v1/auth/token" && *status == 200).unwrap();
    assert!(at - before > first_token_call, "the token was kept after its answer came");
    assert!(seen.len() > at - before, "and before the next request");
    assert!(seen[at - before..].iter().all(|(_, path, _, _)| path != "/kem/v1/auth/token"));
    // The old one is spent: a device that used it again would end its session
    let done = connected(sign_in(net, server, email, PASSWORD, &Settings { device_id: None, bitwarden_device: None, opaque_seen: true, second: None }));
    let mut third = Client::from(&done, server, email);
    let spent = third.connection.refresh.clone().unwrap();
    third.access = None;
    assert_clean(&third.sync(net), "a third device's first run, which refreshes");
    let (server3, key3) = (third.server(), third.key());
    let mut api = KemApi::new(net, &server3, &key3);
    assert_eq!(api.refresh(&spent).err(), Some(Problem::Kemlock(word::SESSION_ENDED)), "a refresh token used twice ends the session");

    // --- The devices: ours is "Amethystora Vault" of kind amethystora, and a spent session is gone for the others
    let devices = first.with_api(net, |api| api.devices()).expect("a token");
    let devices = devices["devices"].as_array().unwrap().clone();
    let ours = devices.iter().find(|d| d["id"] == first.state().device_id.as_str()).expect("this device is listed");
    assert_eq!((ours["name"].as_str(), ours["kind"].as_str(), ours["current"].as_bool()), (Some("Amethystora Vault"), Some("amethystora"), Some(true)), "{ours}");
    assert!(devices.iter().any(|d| d["id"] == second.state().device_id.as_str()));

    // --- Sign out: the device is gone, its refresh token is refused
    // Nothing of all this touched a Bitwarden copy
    let items = server_items(net, first);
    for (id, ciphertext) in &bw_before {
        let wire = find(&items, id);
        assert_eq!((wire.revision, wire.deleted, &wire.ciphertext), (1, false, ciphertext), "a bw item changed");
    }

    let (device, refresh) = (second.state().device_id.clone(), second.connection.refresh.clone().unwrap());
    second.with_api(net, |api| api.sign_out(&device)).expect("signed out");
    let devices = first.with_api(net, |api| api.devices()).expect("a token");
    assert!(!devices["devices"].as_array().unwrap().iter().any(|d| d["id"] == device.as_str()), "the signed-out device is still listed");
    let (server2, key2) = (second.server(), second.key());
    let mut api = KemApi::new(net, &server2, &key2);
    assert!(api.refresh(&refresh).is_err(), "a signed-out device's refresh token still works");
}

// --- The tests -------------------------------------------------------------------------------------------------------------

#[test]
#[ignore = "needs the Kemlock Server container"]
fn a_kemlock_only_account_signs_in_syncs_every_kind_both_ways_and_signs_the_manifest() {
    let container = container();
    let server = server_of(&container);
    let mut net = Net::new(&container.address);
    let email = unique_email("kemlock-only");
    let id = register_kemlock(&mut net, &server, &email, PASSWORD);

    // Connecting: the real Argon2id, OPAQUE, the keys opened and the bundle's signature checked
    let started = Instant::now();
    let done = connected(sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: None, opaque_seen: false, second: None }));
    println!("sign-in took {:?}", started.elapsed());
    assert_eq!(done.tokens.user_id, id);
    assert!(done.state.opaque_seen && !done.enrolled, "a Kemlock-only account is signed in by OPAQUE alone");
    assert_eq!((done.state.key_version, done.state.kdf_memory_kib, done.state.kdf_iterations, done.state.kdf_parallelism), (1, 65_536, 3, 4));
    let mut first = Client::from(&done, &server, &email);
    // Its device is listed as this Vault
    let devices = first.with_api(&mut net, |api| api.devices()).unwrap();
    let ours = devices["devices"].as_array().unwrap().iter().find(|d| d["current"] == json!(true)).expect("a current device").clone();
    assert_eq!((ours["name"].as_str(), ours["kind"].as_str()), (Some("Amethystora Vault"), Some("amethystora")));

    // A wrong password with the Bitwarden route closed: said as such, and nothing of Bitwarden's was asked
    let before = log_len();
    let wrong = sign_in(&mut net, &server, &email, "not the password", &Settings { device_id: None, bitwarden_device: None, opaque_seen: true, second: None });
    assert_eq!(wrong.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert_eq!(requests(before, "POST", "/auth/bitwarden"), 0, "the Bitwarden hash was sent after OPAQUE had been seen");

    scenario(&mut net, &server, &email, &mut first, &[], &fresh_ids());
}

#[test]
#[ignore = "needs the Kemlock Server container"]
fn a_compatible_account_is_enrolled_once_and_its_bitwarden_copies_are_left_alone() {
    let container = container();
    let server = server_of(&container);
    let mut net = Net::new(&container.address);
    let email = unique_email("compatible");
    let (bw_device, bw_user_key, cipher_id) = register_compatible(&mut net, &server, &email);

    // The first sign-in on the Kemlock API: OPAQUE fails (no record yet), the Bitwarden hash goes once, the account's own key is opened
    let before = log_len();
    let done = connected(sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: Some(&bw_device), opaque_seen: false, second: None }));
    assert!(done.enrolled, "the Compatible account was enrolled");
    assert!(done.state.opaque_seen);
    assert_eq!(done.root.as_bytes()[..], bw_user_key[..], "the root key is the Bitwarden user key: the same 64 bytes open both copies");
    assert_eq!(requests(before, "POST", "/auth/bitwarden/start"), 1);
    assert_eq!(requests(before, "POST", "/auth/bitwarden/finish"), 1);
    assert_eq!(done.state.key_version, 1);
    assert_eq!((done.state.kdf_memory_kib, done.state.kdf_iterations, done.state.kdf_parallelism), (65_536, 3, 4));
    let mut first = Client::from(&done, &server, &email);

    // One device row for both APIs
    let devices = first.with_api(&mut net, |api| api.devices()).unwrap();
    let ours: Vec<&Value> = devices["devices"].as_array().unwrap().iter().filter(|d| d["name"] == "Amethystora Vault").collect();
    assert_eq!(ours.len(), 1, "{devices}");
    assert_eq!(ours[0]["kind"], "amethystora");
    println!("the device: {}", ours[0]);

    // A second connection: OPAQUE works now, the Bitwarden route is not taken, and with opaque_seen it is closed
    let before = log_len();
    let again = connected(sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: Some(&done.tokens.device_id), bitwarden_device: Some(&bw_device), opaque_seen: true, second: None }));
    assert!(!again.enrolled && again.state.opaque_seen);
    assert_eq!(again.root.as_bytes()[..], done.root.as_bytes()[..]);
    assert_eq!(again.tokens.device_id, done.tokens.device_id, "the same device when its id is given back");
    // A reconnection under the same device id replaces its session: the earlier refresh token is spent, so this is the device now
    let mut first = Client::from(&again, &server, &email);
    assert_eq!(requests(before, "POST", "/auth/bitwarden"), 0);
    let wrong = sign_in(&mut net, &server, &email, "not the password", &Settings { device_id: None, bitwarden_device: None, opaque_seen: true, second: None });
    assert_eq!(wrong.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert_eq!(requests(before, "POST", "/auth/bitwarden"), 0, "the Bitwarden hash is never sent again");
    // The account stays Compatible: Bitwarden's own login still works with the same password
    let pending = merge::prepare(&mut net, &crypto::master_key, server.clone(), &email, PASSWORD.as_bytes(), None, None, None, bw_device.clone()).expect("prelogin");
    let (bw_connection, _) = merge::finish(&mut net, &pending, &Extra::default()).expect("a Bitwarden login after enrolment");
    assert_eq!(bw_connection.key().unwrap().bytes(), &bw_user_key[..]);

    scenario(&mut net, &server, &email, &mut first, std::slice::from_ref(&cipher_id), &fresh_ids());
    // And the cipher is still what Bitwarden's API shows, untouched by anything the Kemlock back end did
    let access = merge::finish(&mut net, &pending, &Extra::default()).unwrap().1;
    let (status, sync) = bw_raw(&mut net, "GET", &format!("{}/sync?excludeDomains=true", server.api), &access.token, None);
    assert_eq!(status, 200);
    let ciphers = sync["ciphers"].as_array().unwrap();
    assert_eq!(ciphers.len(), 1, "the Bitwarden API shows no kem1 item: {sync}");
    assert_eq!(ciphers[0]["id"], cipher_id.as_str());
}

/// The code an authenticator app shows for a base32 secret at a time
fn totp_at(secret: &str, unix: i64) -> String {
    let account = Account { kind: Some(OtpKind::Totp), secret: Secret::new(secret), algorithm: "SHA1".into(), digits: 6, period: 30, ..Account::default() };
    let code = amethystora_vault_core::otp::code_at(&account, unix, 0);
    assert!(code.is_usable(), "a code");
    code.as_str().to_string()
}

fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64
}

/// Waits for the next 30-second step and a second more, so that a code is not one the server spent already
fn next_step() -> i64 {
    let now = unix_now();
    let wait = 30 - now.rem_euclid(30) + 1;
    println!("waiting {wait} s for the next authenticator step");
    std::thread::sleep(Duration::from_secs(wait as u64));
    unix_now()
}

#[test]
#[ignore = "needs the Kemlock Server container; waits up to a minute for authenticator steps"]
fn a_compatible_account_with_an_authenticator_is_enrolled_with_a_code_and_then_asked_for_another() {
    let container = container();
    let server = server_of(&container);
    let mut net = Net::new(&container.address);
    let email = unique_email("compatible-totp");
    let (bw_device, bw_user_key, cipher_id) = register_compatible(&mut net, &server, &email);

    // The account turns an authenticator on through the Bitwarden API, as it would in a Bitwarden app, before it ever meets Kemlock's
    let pending = merge::prepare(&mut net, &crypto::master_key, server.clone(), &email, PASSWORD.as_bytes(), None, None, None, bw_device.clone()).expect("prelogin");
    let (_, access) = merge::finish(&mut net, &pending, &Extra::default()).expect("a Bitwarden login");
    let master = crypto::master_key(PASSWORD.as_bytes(), &email, &bw_kdf()).unwrap();
    let hash = crypto::master_hash(&master, PASSWORD.as_bytes());
    let (status, got) = bw_raw(&mut net, "POST", &format!("{}/two-factor/get-authenticator", server.api), &access.token, Some(&json!({"masterPasswordHash": hash.as_str()})));
    assert_eq!(status, 200, "{got}");
    let (secret, verification) = (got["authenticator"]["key"].as_str().unwrap().to_string(), got["userVerificationToken"].as_str().unwrap().to_string());
    let (status, on) = bw_raw(&mut net, "PUT", &format!("{}/two-factor/authenticator", server.api), &access.token, Some(&json!({"key": secret, "token": totp_at(&secret, unix_now()), "userVerificationToken": verification})));
    assert_eq!(status, 200, "{on}");

    // 1. No code given: OPAQUE fails (no record), the Bitwarden hash goes, and the account says it wants an authenticator code
    let before = log_len();
    let asked = sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: Some(&bw_device), opaque_seen: false, second: None });
    assert_eq!(asked.err(), Some(Problem::TwoFactor(vec![0])));
    assert_eq!(requests(before, "POST", "/auth/bitwarden/start"), 1);
    assert_eq!(requests(before, "POST", "/auth/bitwarden/finish"), 0, "nothing was enrolled without the code");

    // 2. A code of the next step: the enrolment goes through with it, and the sign-in after it asks for yet another (a code is used once)
    let unix = next_step();
    let code = totp_at(&secret, unix);
    let before = log_len();
    let again = sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: Some(&bw_device), opaque_seen: false, second: Some(("totp", &code)) });
    println!("after enrolling with a code: {:?}", again.as_ref().err());
    assert_eq!(again.err(), Some(Problem::TwoFactor(vec![0])), "enrolled; the account's second step is asked again");
    assert_eq!(requests(before, "POST", "/auth/bitwarden/finish"), 1);
    assert_eq!(log_since(before).iter().find(|(_, path, _, _)| path.ends_with("/auth/bitwarden/finish")).map(|l| l.2), Some(204));

    // 3. Enrolled now: OPAQUE signs in, the second step is the next step's code, and the account's keys open
    let unix = next_step();
    let code = totp_at(&secret, unix);
    let before = log_len();
    let done = connected(sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: Some(&bw_device), opaque_seen: false, second: Some(("totp", &code)) }));
    assert!(!done.enrolled && done.state.opaque_seen);
    assert_eq!(done.root.as_bytes()[..], bw_user_key[..], "the Bitwarden user key is the root key");
    assert_eq!(requests(before, "POST", "/auth/bitwarden"), 0);
    assert_eq!(requests(before, "POST", "/auth/two-factor"), 1);
    // A wrong code is refused as a second step, not as a wrong password
    let wrong = sign_in(&mut net, &server, &email, PASSWORD, &Settings { device_id: None, bitwarden_device: Some(&bw_device), opaque_seen: true, second: Some(("totp", "000000")) });
    assert_eq!(wrong.err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));

    // 4. And it syncs: one password goes up beside the Bitwarden cipher, which stays
    let mut client = Client::from(&done, &server, &email);
    let ids = fresh_ids();
    client.put("password", ids.password, with_id(password("Larkspur Mail", "sam@example.org", "cobalt-otter-41", "https://mail.larkspur.example/login"), ids.password));
    let outcome = client.sync(&mut net);
    assert_clean(&outcome, "a run for an account with a second step");
    let items = server_items(&mut net, &mut client);
    assert_eq!(items.len(), 2);
    assert_eq!(find(&items, &cipher_id).format, "bw");
    assert_eq!(server_manifest(&mut net, &mut client).unwrap().entries.len(), 2);
}
