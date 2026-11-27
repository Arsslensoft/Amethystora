//! Sync with a Kemlock Server through the whole path of the service: a person's requests on the Vault's socket, the service, the
//! network service's socket, `amethystora-vault-net`'s own code, and an in-memory Kemlock Server (`FakeKemlock`) of the test's own
//! behind a real TCP port, answering with the headers the protocol needs (`DPoP-Nonce`, `Date`...). Argon2id is the real one, made by
//! the service's own child; polkit and logind are the stand-ins of every service test.

mod common;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use amethystora_vault_core::items::{BackupCode, BackupService, Password, Secret};
use amethystora_vault_core::kemlock::sync::fake::{Attack, FakeKemlock};
use amethystora_vault_core::protocol::Approval;
use amethystora_vault_core::slots::fake::FakeChip;
use amethystora_vault_core::store::Store;
use amethystora_vault_core::sync::api::{Http, Request};
use amethystora_vault_core::sync::cipher::{self, Content, Field, LOGIN};
use amethystora_vault_core::sync::fake::{Fake, EMAIL as BW_EMAIL, PASSWORD as BW_PASSWORD};
use amethystora_vault_core::sync::merge::{CONNECTION_ID, KIND_CONNECTION};
use amethystora_vault_net::http::Session;
use amethystora_vault_service::outside::say;
use amethystora_vault_service::server::Server;
use amethystora_vault_service::service::{Config, Service};
use amethystora_vault_service::sync_kemlock::Persists;
use base64::Engine as _;
use common::{b64, fake, Folder, Handle};

const VAULT_PASSWORD: &str = "correct horse battery";
const EMAIL: &str = "sam@kemlock.example.test";
const PASSWORD: &str = "a kemlock master password";

// --- A server of our own on a real port ------------------------------------------------------------------------------------

type Shared<F> = Arc<Mutex<F>>;

fn method_of(name: &str) -> Option<&'static str> {
    ["GET", "POST", "PUT", "DELETE", "PATCH"].into_iter().find(|method| *method == name)
}

/// One connection: what comes in is handed to the server as a request at `base` plus its path, and what it answers goes out with its
/// headers, which Kemlock's DPoP nonce and clock handling read
fn handle<F: Http>(stream: TcpStream, fake: Shared<F>, base: String) {
    let Ok(clone) = stream.try_clone() else { return };
    let mut reader = BufReader::new(clone);
    let mut writer = stream;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            return;
        }
        let mut words = line.split_whitespace();
        let (Some(method), Some(path)) = (words.next().and_then(method_of), words.next()) else { return };
        let path = path.to_string();
        let (mut length, mut headers) = (0usize, Vec::new());
        loop {
            let mut header = String::new();
            if reader.read_line(&mut header).unwrap_or(0) == 0 {
                return;
            }
            let header = header.trim_end().to_string();
            if header.is_empty() {
                break;
            }
            if let Some((name, value)) = header.split_once(':') {
                if name.eq_ignore_ascii_case("content-length") {
                    length = value.trim().parse().unwrap_or(0);
                }
                headers.push((&*Box::leak(name.trim().to_string().into_boxed_str()), value.trim().to_string()));
            }
        }
        let mut body = vec![0u8; length];
        if reader.read_exact(&mut body).is_err() {
            return;
        }
        let response = fake.lock().unwrap().call(Request { method, url: format!("{base}{path}"), headers, body: zeroize::Zeroizing::new(body) });
        let Ok(response) = response else { return };
        let mut head = format!("HTTP/1.1 {} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n", response.status, response.body.len());
        for (name, value) in &response.headers {
            if !["content-type", "content-length", "connection", "transfer-encoding"].contains(&name.to_ascii_lowercase().as_str()) {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
        }
        head.push_str("\r\n");
        if writer.write_all(head.as_bytes()).and_then(|()| writer.write_all(&response.body)).is_err() {
            return;
        }
    }
}

fn serve<F: Http + Send + 'static>(fake: Shared<F>, listener: TcpListener, base: String) {
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            let (fake, base) = (fake.clone(), base.clone());
            std::thread::spawn(move || handle(stream, fake, base));
        }
    });
}

/// The network service's own code on a socket of its own, as systemd would hand it
fn serve_net(path: &PathBuf) {
    let listener = UnixListener::bind(path).unwrap();
    std::thread::spawn(move || {
        for stream in listener.incoming().flatten() {
            std::thread::spawn(move || {
                let mut writer = stream.try_clone().unwrap();
                let mut reader = BufReader::new(stream);
                amethystora_vault_net::serve(&mut reader, &mut writer, &|origins, ca, pin| Session::new(origins, ca, pin));
            });
        }
    });
}

// --- The service ------------------------------------------------------------------------------------------------------------

struct Rig {
    /// Removes its files when the test ends
    #[allow(dead_code)]
    folder: Folder,
    socket: PathBuf,
    outside: Handle,
    kem: Shared<FakeKemlock>,
    kem_port: u16,
    kem_id: String,
    /// A Bitwarden server too, for the move
    bw: Shared<Fake>,
    bw_port: u16,
    persists: Persists,
    stop: OwnedFd,
    thread: Option<std::thread::JoinHandle<()>>,
}

struct Settings {
    net: bool,
    interval: Duration,
    run_limit: Duration,
}

impl Default for Settings {
    fn default() -> Settings {
        Settings { net: true, interval: Duration::from_secs(3600), run_limit: Duration::from_secs(600) }
    }
}

fn rig(name: &str, settings: Settings) -> Rig {
    let folder = Folder::new(name);
    let socket = folder.0.join("vault.sock");
    let net = folder.0.join("vault-net.sock");
    if settings.net {
        serve_net(&net);
    }
    let listener = UnixListener::bind(&socket).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o666)).unwrap();
    std::fs::set_permissions(&folder.0, std::fs::Permissions::from_mode(0o755)).unwrap();
    let state = folder.0.join("state");
    std::fs::create_dir_all(&state).unwrap();

    // The Kemlock Server's DOMAIN is the address it is reached at, exactly: DPoP proofs are checked against it
    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let kem_port = tcp.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{kem_port}");
    let mut server = FakeKemlock::new(&base);
    server.real_argon2 = true;
    let kem_id = server.make_account(EMAIL, PASSWORD);
    let kem = Arc::new(Mutex::new(server));
    serve(kem.clone(), tcp, base);

    let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
    let bw_port = tcp.local_addr().unwrap().port();
    let base = format!("http://127.0.0.1:{bw_port}");
    let bw = Arc::new(Mutex::new(Fake::default()));
    bw.lock().unwrap().base = base.clone();
    serve(bw.clone(), tcp, base);

    let mut pipe = [0; 2];
    // SAFETY: pipe2 writes two descriptors, which are then owned
    let (stop_read, stop_write) = unsafe {
        assert_eq!(libc::pipe2(pipe.as_mut_ptr(), libc::O_CLOEXEC), 0);
        (OwnedFd::from_raw_fd(pipe[0]), OwnedFd::from_raw_fd(pipe[1]))
    };
    let (outside, handle) = fake();
    let (sender, receiver) = std::sync::mpsc::channel();
    let thread = std::thread::spawn(move || {
        let mut service = Service::new(Config { state, log_n: 10, worker: PathBuf::from(env!("CARGO_BIN_EXE_amethystora-vault-work")) }, Arc::new(FakeChip::new()), Box::new(outside));
        service.sync.net = net;
        service.sync.debounce = Duration::from_millis(150);
        service.sync.run_limit = settings.run_limit;
        service.sync.kdf_child = PathBuf::from(env!("CARGO_BIN_EXE_amethystora-vault-service"));
        service.sync.interval = settings.interval;
        sender.send(service.sync.persists.clone()).unwrap();
        let server = Server::new(listener, Some(stop_read.as_raw_fd()), service, Duration::from_secs(600)).unwrap();
        server.run();
        drop(stop_read);
    });
    let persists = receiver.recv().unwrap();
    Rig { folder, socket, outside: handle, kem, kem_port, kem_id, bw, bw_port, persists, stop: stop_write, thread: Some(thread) }
}

impl Drop for Rig {
    fn drop(&mut self) {
        // SAFETY: one byte, from a live buffer
        unsafe { libc::write(self.stop.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

struct Talk {
    stream: UnixStream,
    reader: BufReader<UnixStream>,
}

impl Talk {
    fn ask(&mut self, mut request: Value) -> Value {
        request["v"] = json!(1);
        self.stream.write_all(format!("{request}\n").as_bytes()).unwrap();
        let mut answer = String::new();
        self.reader.read_line(&mut answer).unwrap();
        serde_json::from_str(&answer).unwrap()
    }
}

fn until<T>(mut check: impl FnMut() -> Option<T>) -> T {
    let end = Instant::now() + Duration::from_secs(90);
    loop {
        if let Some(found) = check() {
            return found;
        }
        assert!(Instant::now() < end, "it never happened");
        std::thread::sleep(Duration::from_millis(40));
    }
}

/// A key made as the vault makes one, and its private bytes in the vault's own text, which a server must never see in the clear
fn key_value() -> (Value, String) {
    use amethystora_vault_core::keys::{self, KeyType};
    let key = keys::generate(KeyType::X25519).unwrap();
    let forms = key.public().unwrap();
    let private = amethystora_vault_core::protocol::encode(key.as_bytes());
    let public = json!({"type": "x25519", "pem": forms.spki_pem, "openssh": forms.openssh, "sha256": forms.sha256, "ssh_sha256": forms.ssh_sha256});
    (json!({"key_kind": "exchange", "type": "x25519", "key": private, "exportable": true, "public": public, "comment": null}), private)
}

fn protected_file(bytes: &[u8]) -> (Value, Value) {
    let meta = json!({"path": "big.bin", "what": "file", "size": bytes.len(), "files": 1});
    let value = json!({"what": "file", "files": [{"at": "", "mode": 0o600, "data": base64::engine::general_purpose::STANDARD.encode(bytes)}], "folders": []});
    (meta, value)
}

impl Rig {
    fn ask(&self, mut request: Value) -> Value {
        request["v"] = json!(1);
        amethystora_vault_client::exchange(&self.socket, &request, Duration::from_secs(120)).unwrap()
    }

    fn kem_address(&self) -> String {
        format!("http://127.0.0.1:{}", self.kem_port)
    }

    fn bw_address(&self) -> String {
        format!("http://127.0.0.1:{}", self.bw_port)
    }

    fn set_up(&self) {
        let answer = self.ask(json!({"op": "setup", "method": "password", "name": "Personal", "secret": b64(VAULT_PASSWORD)}));
        assert_eq!(answer["ok"], json!(true), "{answer}");
        let recovery = answer["recovery"].as_str().unwrap().to_string();
        assert_eq!(self.ask(json!({"op": "confirm", "recovery": b64(&recovery)}))["ok"], json!(true));
    }

    /// Runs `what` over the first vault's store, as the plugs' writes would: locked first when it writes, so that nothing else does
    fn with_store<T>(&self, lock: bool, what: impl FnOnce(&mut Store) -> T) -> T {
        use amethystora_vault_core::slots::{self, Table};
        use amethystora_vault_core::vaults::Account;
        if lock {
            assert_eq!(self.ask(json!({"op": "lock"}))["ok"], json!(true));
        }
        let state = self.folder.0.join("state");
        // SAFETY: getuid cannot fail
        let account = Account::load(&state, unsafe { libc::getuid() }).unwrap().unwrap();
        let under = slots::derive(VAULT_PASSWORD.as_bytes(), &account.file.kdf).unwrap();
        let found = slots::search(&under, &account.records(Table::Password), Table::Password);
        let mut store = Store::open(&account.folder_of(&found[0].vault), &found[0].vault, found[0].key.copy()).unwrap();
        let result = what(&mut store);
        drop(store);
        if lock {
            let answer = self.ask(json!({"op": "unlock", "method": "password", "secret": b64(VAULT_PASSWORD)}));
            assert_eq!(answer["ok"], json!(true), "{answer}");
        }
        result
    }

    /// The kinds only the service writes cannot be put over the socket (and a big file should not travel on one): the test lays them
    /// in the closed vault's folder and opens it again
    fn inject(&self, kind: &str, id: &str, name: &str, meta: &Value, value: &Value) {
        self.with_store(true, |store| {
            store.put(kind, id, name, meta, Approval::WhileOpen, value).unwrap();
        });
    }

    fn put(&self, kind: &str, id: &str, name: &str, meta: Value, value: Value) {
        if amethystora_vault_core::protocol::service_only(kind) {
            return self.inject(kind, id, name, &meta, &value);
        }
        let answer = self.ask(json!({"op": "put", "kind": kind, "id": id, "name": name, "meta": meta, "value": value}));
        assert_eq!(answer["ok"], json!(true), "{answer}");
    }

    fn password(&self, id: &str, title: &str, user: &str, secret: &str, address: &str) {
        let value = serde_json::to_value(Password { id: id.into(), title: title.into(), username: user.into(), password: Secret::new(secret), address: address.into(), ..Password::default() }).unwrap();
        self.put("password", id, title, json!({"username": user, "address": address}), value);
    }

    fn value_of(&self, kind: &str, id: &str) -> Value {
        let answer = self.ask(json!({"op": "get", "kind": kind, "id": id}));
        assert_eq!(answer["ok"], json!(true), "{answer}");
        answer["value"].clone()
    }

    fn items(&self, kind: &str) -> Vec<Value> {
        self.ask(json!({"op": "list", "kind": kind}))["items"].as_array().cloned().unwrap_or_default()
    }

    fn connection_request(&self) -> Value {
        json!({"op": "sync-connect", "address": self.kem_address(), "email": EMAIL, "secret": b64(PASSWORD)})
    }

    fn connect(&self) -> Value {
        self.talk().ask(self.connection_request())
    }

    /// Keys, certificates and files turned on, as a person does with the Export question: on Kemlock they start off, as on Bitwarden.
    /// After the first run, then a run that sends them
    fn choose_kept_off(&self) {
        self.synced();
        for word in ["keys", "certificates", "files"] {
            assert_eq!(self.ask(json!({"op": "sync-kind", "kind": word, "choice": "on"}))["ok"], json!(true), "{word}");
        }
        self.synced();
        self.sync_now();
    }

    fn talk(&self) -> Talk {
        let stream = UnixStream::connect(&self.socket).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(180))).unwrap();
        Talk { reader: BufReader::new(stream.try_clone().unwrap()), stream }
    }

    fn status(&self) -> Value {
        self.ask(json!({"op": "sync-status"}))
    }

    /// Until the status says a run has finished well
    fn synced(&self) -> Value {
        until(|| {
            let status = self.status();
            (status["connected"] == json!(true) && status["last_success_ms"].is_number() && status["running"] != json!(true)).then_some(status)
        })
    }

    /// Until nothing runs, whatever it ended in
    fn idle(&self) -> Value {
        until(|| {
            let status = self.status();
            (status["running"] != json!(true)).then_some(status)
        })
    }

    /// Until a run has ended and no other follows its debounce: a change made while a run is in flight is picked up by the next one, not
    /// that one
    fn settle(&self) {
        let mut before = None;
        until(|| {
            std::thread::sleep(Duration::from_millis(500));
            let status = self.status();
            let at = status["last"]["at_ms"].clone();
            let quiet = status["running"] != json!(true) && before.as_ref() == Some(&at);
            before = Some(at);
            quiet.then_some(())
        });
    }

    fn sync_now(&self) -> Value {
        until(|| {
            let answer = self.ask(json!({"op": "sync-now"}));
            (answer["why"] != json!("failed")).then_some(answer)
        })
    }

    /// What the connection holds, read from the vault's own store (it is only read here, between runs)
    fn connection(&self) -> Value {
        self.with_store(false, |store| store.get(KIND_CONNECTION, CONNECTION_ID).unwrap())
    }

    /// The Kemlock Server's live items: id and what they open to
    fn server_items(&self) -> Vec<(String, Value)> {
        let kem = self.kem.lock().unwrap();
        kem.live_ids(EMAIL).into_iter().filter_map(|id| kem.plain_of(EMAIL, &id).map(|plain| (id, plain))).collect()
    }

    fn server_item(&self, name: &str) -> (String, Value) {
        self.server_items().into_iter().find(|(_, plain)| plain["name"] == json!(name)).unwrap_or_else(|| panic!("no item {name} on the server"))
    }

    fn batches(&self) -> usize {
        self.kem.lock().unwrap().requests_to("items:batch")
    }

    fn revisions(&self) -> BTreeMap<String, u64> {
        let kem = self.kem.lock().unwrap();
        kem.account(EMAIL).items.iter().map(|(id, stored)| (id.clone(), stored.wire.revision)).collect()
    }

    fn token_requests(&self) -> usize {
        self.kem.lock().unwrap().requests_to("auth/token")
    }

    fn sessions(&self) -> usize {
        self.kem.lock().unwrap().session_count(EMAIL)
    }

    /// Takes the persister's requests away before the loop can serve them: each is dropped unanswered, which the run's thread hears as
    /// the connection not holding the token
    fn refuse_persists(&self) -> Stealer {
        let wake = self.persists.wake.lock().unwrap().take();
        let (stop, count) = (Arc::new(AtomicBool::new(false)), Arc::new(AtomicUsize::new(0)));
        let (queue, flag, counted) = (self.persists.queue.clone(), stop.clone(), count.clone());
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::SeqCst) {
                let dropped = queue.lock().map(|mut queue| queue.drain(..).count()).unwrap_or(0);
                counted.fetch_add(dropped, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(1));
            }
        });
        Stealer { stop, count, thread, persists: self.persists.clone(), wake }
    }
}

struct Stealer {
    stop: Arc<AtomicBool>,
    count: Arc<AtomicUsize>,
    thread: std::thread::JoinHandle<()>,
    persists: Persists,
    wake: Option<Arc<OwnedFd>>,
}

impl Stealer {
    /// The loop hears its runs again; how many requests were dropped
    fn release(self) -> usize {
        self.stop.store(true, Ordering::SeqCst);
        self.thread.join().unwrap();
        *self.persists.wake.lock().unwrap() = self.wake;
        self.count.load(Ordering::SeqCst)
    }
}

/// The vault a person has, with one of every kind the Vault sends and the Kemlock Server holds a place for
fn full_vault(rig: &Rig) -> (String, String) {
    rig.set_up();
    rig.password("p1", "Example", "person", "hunter2 ✓", "https://example.test/login");
    let codes = BackupService { id: "c1".into(), service_name: "Example".into(), codes: vec![BackupCode::new("1111-2222")], ..BackupService::default() };
    rig.put("backup-codes", "c1", "Example", Value::Null, serde_json::to_value(&codes).unwrap());
    let account = amethystora_vault_core::items::Account { id: "a1".into(), kind: Some(amethystora_vault_core::items::OtpKind::Totp), issuer: "Elsewhere".into(), label: "me".into(), secret: Secret::new("JBSWY3DPEHPK3PXP"), ..Default::default() };
    rig.put("authenticator", "a1", "Elsewhere", Value::Null, serde_json::to_value(&account).unwrap());
    let (value, private) = key_value();
    rig.put("key", "k1", "A key", json!({"key_kind": "exchange", "exportable": true}), value);
    let (meta, value) = protected_file(b"a file of the person's, with some body to it");
    rig.inject("protected", "f1", "tax.pdf", &meta, &value);
    (private, "JBSWY3DPEHPK3PXP".to_string())
}

// --- Tests ------------------------------------------------------------------------------------------------------------------

#[test]
fn the_service_picks_kemlock_on_its_own_and_every_kind_goes_by_default() {
    let rig = rig("kem-meet", Settings::default());
    let (key_secret, otp_secret) = full_vault(&rig);

    // No program has the service reach out to a server of its choosing
    assert_eq!(rig.ask(json!({"op": "sync-probe", "address": rig.kem_address()}))["ok"], json!(false));
    // A non-exportable key never goes, whatever the kind says
    let (never_value, never_secret) = {
        let (mut value, private) = key_value();
        value["exportable"] = json!(false);
        (value, private)
    };
    rig.put("key", "k2", "Locked in", json!({"key_kind": "exchange", "exportable": false}), never_value);

    let answer = rig.connect();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!((answer["connected"].clone(), answer["backend"].clone(), answer["moved"].clone()), (json!(true), json!("kemlock"), json!(false)));
    let asked = rig.outside.said.lock().unwrap().asked.clone();
    assert!(asked.iter().any(|ask| ask.message == say::SYNC_CONNECT && ask.item == format!("{} ({})", rig.kem_address(), EMAIL)), "{asked:?}");

    let status = rig.synced();
    assert_eq!((status["backend"].clone(), status["email"].clone()), (json!("kemlock"), json!(EMAIL)));
    for word in ["passwords", "codes", "backup-codes"] {
        assert_eq!(status["kinds"][word], json!("on"), "{word}: {status}");
    }
    // Connecting says yes to the account, not to sending a private key: keys, certificates and files wait to be chosen
    for word in ["keys", "certificates", "files"] {
        assert_eq!(status["kinds"][word], json!("off"), "{word}: {status}");
    }
    rig.choose_kept_off();
    let status = rig.synced();
    assert_eq!(status["problem"], Value::Null, "{status}");
    // The login, the authenticator account, the backup codes, the key and the file: five items, no more
    assert_eq!(status["linked"], json!(5), "{status}");
    let items = rig.server_items();
    assert_eq!(items.len(), 5, "{items:?}");
    let (login_id, login) = rig.server_item("Example");
    assert_eq!((login["username"].as_str(), login["password"].as_str()), (Some("person"), Some("hunter2 ✓")));
    {
        let kem = rig.kem.lock().unwrap();
        let mut kinds: Vec<String> = kem.live_ids(EMAIL).iter().map(|id| kem.wire_of(EMAIL, id).unwrap().kind).collect();
        kinds.sort();
        assert_eq!(kinds, ["backup-codes", "key", "login", "note", "otp"], "{kinds:?}");
        assert!(kem.wire_of(EMAIL, &login_id).unwrap().format == "kem1");
        // A signed manifest lists everything, and one file went with the protected note
        assert_eq!(kem.manifest(EMAIL).unwrap().entries.len(), 5);
        assert_eq!(kem.account(EMAIL).files.len(), 1);
        // Every request that left carried a proof, the ones with an account a token, and none had a secret in the clear
        for seen in &kem.seen {
            let everything = format!("{} {} {:?} {}", seen.method, seen.url, seen.headers, seen.body);
            for secret in [PASSWORD, VAULT_PASSWORD, "hunter2", "1111-2222", otp_secret.as_str(), key_secret.as_str(), never_secret.as_str(), "a file of the person"] {
                assert!(!everything.contains(secret), "{secret:?} left in the clear: {} {}", seen.method, seen.url);
            }
            if seen.path().contains("/auth/token") || seen.path().contains("items") || seen.path().contains("manifest") || seen.path().contains("devices") {
                assert!(seen.header("dpop").is_some(), "no proof: {} {}", seen.method, seen.url);
            }
            if seen.path().contains("items") || seen.path().contains("manifest") {
                assert!(seen.header("authorization").is_some_and(|value| value.starts_with("DPoP ")), "{} {}", seen.method, seen.url);
            }
            assert!(seen.method != "DELETE" || seen.path().contains("/files/"), "a delete other than of a file: {} {}", seen.method, seen.url);
        }
    }
    // The links and the connection are the service's: no program of the account reads, writes or approves them
    assert!(!rig.items("sync-links").is_empty());
    let listed = rig.items("sync-account");
    assert_eq!(listed.len(), 1);
    assert!(!listed[0].to_string().contains(EMAIL) && !listed[0].to_string().contains(&rig.kem_address()));
    assert_eq!(rig.ask(json!({"op": "get", "kind": "sync-account", "id": "account"}))["ok"], json!(false));
    assert_eq!(rig.ask(json!({"op": "put", "kind": "sync-account", "id": "account", "name": "x", "value": {}}))["ok"], json!(false));
    // The non-exportable key stayed
    assert!(rig.server_items().iter().all(|(_, plain)| plain["name"] != json!("Locked in")));

    // A second run changes nothing: no write, no new revision, no new item
    let (batches, revisions) = (rig.batches(), rig.revisions());
    let answer = rig.sync_now();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!((answer["report"]["sent"].clone(), answer["report"]["created_there"].clone(), answer["report"]["trashed_there"].clone()), (json!(0), json!(0), json!(0)), "{answer}");
    assert_eq!(rig.batches(), batches);
    assert_eq!(rig.revisions(), revisions);
}

#[test]
fn a_change_here_goes_there_and_a_change_there_comes_here_and_a_deletion_goes_both_ways() {
    let rig = rig("kem-both", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "first password", "https://example.test/login");
    rig.password("p2", "Doomed", "person", "doomed password", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    let (login_id, _) = rig.server_item("Example");
    let (doomed_id, _) = rig.server_item("Doomed");

    // Here to there, a little later and by itself
    rig.password("p1", "Example", "person", "changed here", "https://example.test/login");
    until(|| (rig.server_item("Example").1["password"] == json!("changed here")).then_some(()));
    assert!(rig.kem.lock().unwrap().revision_of(EMAIL, &login_id).unwrap() >= 2);

    // There to here: another Kemlock app edits the login and adds one of its own; a signed manifest follows, as the app does
    rig.synced();
    {
        let mut kem = rig.kem.lock().unwrap();
        let mut plain = kem.plain_of(EMAIL, &login_id).unwrap();
        plain["password"] = json!("changed there");
        kem.plant_item_as(EMAIL, &login_id, "login", &plain);
        kem.plant_item(EMAIL, "login", &json!({"id": "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257", "name": "GitHub", "username": "sam", "password": "hunter2-but-longer", "websites": ["github.com"], "addedAt": 1_762_000_000_000i64}));
        kem.sign_manifest(EMAIL);
    }
    let answer = rig.sync_now();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(rig.value_of("password", "p1")["password"], json!("changed there"));
    let github = rig.value_of("password", "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257");
    assert_eq!((github["title"].as_str(), github["password"].as_str()), (Some("GitHub"), Some("hunter2-but-longer")));

    // A deletion here becomes a tombstone there (the vault's own deletion is a mark and the item stays in its trash)
    let now = amethystora_vault_core::sync::merge::now_ms();
    let value = serde_json::to_value(Password { id: "p2".into(), title: "Doomed".into(), password: Secret::new("doomed password"), deleted_at: Some(now), ..Password::default() }).unwrap();
    rig.put("password", "p2", "Doomed", json!({"deletedAt": now}), value);
    until(|| rig.kem.lock().unwrap().wire_of(EMAIL, &doomed_id).is_some_and(|wire| wire.deleted).then_some(()));
    assert!(rig.kem.lock().unwrap().plain_of(EMAIL, &doomed_id).is_none() || rig.kem.lock().unwrap().wire_of(EMAIL, &doomed_id).unwrap().ciphertext.is_none());

    // A deletion there becomes one here
    rig.synced();
    let github_id = rig.server_item("GitHub").0;
    {
        let mut kem = rig.kem.lock().unwrap();
        kem.plant_tombstone(EMAIL, &github_id);
        kem.sign_manifest(EMAIL);
    }
    let answer = rig.sync_now();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    let gone = rig.value_of("password", "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257");
    assert!(gone["deletedAt"].is_number(), "{gone}");
    // And the server's side holds what it did: the live ones are the edited login alone
    let names: Vec<String> = rig.server_items().iter().map(|(_, plain)| plain["name"].as_str().unwrap_or("").to_string()).collect();
    assert_eq!(names, vec!["Example".to_string()]);
}

#[test]
fn a_kind_and_an_item_are_switched_with_the_kemlock_sentences_and_the_server_follows() {
    let rig = rig("kem-kinds", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw one", "");
    rig.password("p2", "Second", "person", "pw two", "");
    let (value, _) = key_value();
    rig.put("key", "k1", "A key", json!({"key_kind": "exchange", "exportable": true}), value);
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.choose_kept_off();
    assert_eq!(rig.server_items().len(), 3);
    let asked = |rig: &Rig| rig.outside.said.lock().unwrap().asked.last().unwrap().message;

    // A kind off: one question, the Kemlock one, and its copies leave the server
    let before = rig.outside.asked();
    assert_eq!(rig.ask(json!({"op": "sync-kind", "kind": "keys", "choice": "off"}))["ok"], json!(true));
    assert_eq!((rig.outside.asked(), asked(&rig)), (before + 1, say::SYNC_KIND_OFF_KEM));
    until(|| (rig.server_items().len() == 2).then_some(()));
    rig.settle();
    assert_eq!(rig.status()["kinds"]["keys"], json!("off"));
    // The vault still has the key; a second run changes nothing there
    assert_eq!(rig.items("key").len(), 1);
    let (batches, revisions) = (rig.batches(), rig.revisions());
    rig.synced();
    rig.sync_now();
    assert_eq!((rig.batches(), rig.revisions()), (batches, revisions));

    // On again: the other sentence, and the key is sent again (at a new revision, not a second item)
    assert_eq!(rig.ask(json!({"op": "sync-kind", "kind": "keys", "choice": "on"}))["ok"], json!(true));
    assert_eq!(asked(&rig), say::SYNC_KIND_ON_KEM);
    until(|| (rig.server_items().len() == 3).then_some(()));
    rig.settle();
    assert_eq!(rig.kem.lock().unwrap().live_ids(EMAIL).len(), 3);

    // An item off and on
    assert_eq!(rig.ask(json!({"op": "sync-choose", "kind": "password", "id": "p2", "choice": "off"}))["ok"], json!(true));
    assert_eq!(asked(&rig), say::SYNC_ITEM_OFF_KEM);
    until(|| (!rig.server_items().iter().any(|(_, plain)| plain["name"] == json!("Second"))).then_some(()));
    rig.settle();
    assert_eq!(rig.ask(json!({"op": "sync-choose", "kind": "password", "id": "p2", "choice": "on"}))["ok"], json!(true));
    assert_eq!(asked(&rig), say::SYNC_ITEM_KEM);
    until(|| rig.server_items().iter().any(|(_, plain)| plain["name"] == json!("Second")).then_some(()));
    rig.settle();

    // A no leaves the copy where it is
    rig.outside.said.lock().unwrap().refuse = true;
    assert_eq!(rig.ask(json!({"op": "sync-kind", "kind": "passwords", "choice": "off"}))["ok"], json!(false));
    std::thread::sleep(Duration::from_millis(500));
    assert!(rig.server_items().iter().any(|(_, plain)| plain["name"] == json!("Example")));
    rig.outside.said.lock().unwrap().refuse = false;
    // What is not a kind is refused, and nothing was asked
    let before = rig.outside.asked();
    assert_eq!(rig.ask(json!({"op": "sync-kind", "kind": "bananas", "choice": "on"}))["problem"], json!("not-syncable"));
    assert_eq!(rig.outside.asked(), before);
}

#[test]
fn the_new_refresh_token_is_kept_before_it_is_used_and_a_token_that_was_not_kept_is_never_used() {
    let rig = rig("kem-refresh", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    assert_eq!(rig.sessions(), 1);
    let first = rig.connection()["refresh"].as_str().unwrap().to_string();

    // A token that ran out: the run signs in again with the refresh token, and the connection holds the new one when it is done. If it
    // held a spent one the second refresh would be a reuse, which the server answers by ending every session of the account.
    for _ in 0..2 {
        let before = rig.connection()["refresh"].as_str().unwrap().to_string();
        let tokens = rig.token_requests();
        rig.kem.lock().unwrap().expire_access_tokens();
        let answer = rig.sync_now();
        assert_eq!(answer["ok"], json!(true), "{answer}");
        assert!(rig.token_requests() > tokens, "no new sign-in was needed");
        assert_ne!(rig.connection()["refresh"].as_str().unwrap(), before, "the connection kept the new token");
        assert_eq!(rig.sessions(), 1);
    }
    assert_ne!(rig.connection()["refresh"].as_str().unwrap(), first);

    // The loop does not hear of the new token: the run's thread is told the connection does not hold it, and it stops there, with the
    // new access token never used for anything
    rig.synced();
    let held = rig.connection()["refresh"].as_str().unwrap().to_string();
    let stealer = rig.refuse_persists();
    let tokens = rig.token_requests();
    let seen = rig.kem.lock().unwrap().seen.len();
    rig.kem.lock().unwrap().expire_access_tokens();
    let answer = rig.sync_now();
    let stolen = stealer.release();
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(stolen, 1, "the one token this run was given was offered to the loop");
    assert_eq!(rig.token_requests(), tokens + 1);
    {
        let kem = rig.kem.lock().unwrap();
        let after: Vec<String> = kem.seen[seen..].iter().map(|seen| format!("{} {}", seen.method, seen.path())).collect();
        assert_eq!(after.last().map(String::as_str), Some("POST /kem/v1/auth/token"), "the new token was used: {after:?}");
        assert!(after.iter().filter(|line| line.contains("/items") || line.contains("manifest")).all(|line| line.starts_with("GET")), "{after:?}");
    }
    // The run hands back the new token, never the one the server has spent: with the vault open its end writes it into the connection
    // (closed, the service keeps it in memory for the next run). A refresh with the spent one would be a reuse, which ends the session.
    assert_ne!(rig.connection()["refresh"].as_str().unwrap(), held);
    rig.idle();
    let answer = rig.sync_now();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_ne!(rig.connection()["refresh"].as_str().unwrap(), held, "the spent token never comes back");
    assert_eq!(rig.sessions(), 1);
    assert_eq!(rig.status()["problem"], Value::Null);
}

#[test]
fn a_session_the_server_ended_is_said_once_and_is_not_tried_again_with_the_same_token() {
    let rig = rig("kem-ended", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    let held = rig.connection()["refresh"].as_str().unwrap().to_string();
    rig.kem.lock().unwrap().attack(Attack::SessionEnds("refresh-token-reuse"));
    rig.kem.lock().unwrap().expire_access_tokens();
    let tokens = rig.token_requests();
    let answer = rig.sync_now();
    assert_eq!((answer["ok"].clone(), answer["problem"]["name"].clone()), (json!(false), json!("session-ended")), "{answer}");
    assert_eq!(rig.token_requests(), tokens + 1, "one try");
    // It waits for a person now: no run starts by itself, and the connection is as it was
    std::thread::sleep(Duration::from_millis(700));
    assert_eq!(rig.token_requests(), tokens + 1);
    assert_eq!(rig.status()["problem"]["name"], json!("session-ended"));
    assert_eq!(rig.connection()["refresh"].as_str().unwrap(), held);
    assert_eq!(rig.items("password").len(), 1);
}

#[test]
fn turning_sync_off_signs_the_device_out_and_removes_the_connection_and_the_links_and_nothing_else() {
    let rig = rig("kem-off", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    assert_eq!(rig.kem.lock().unwrap().account(EMAIL).devices.len(), 1);
    // The access token has run out by then: signing out signs in again first
    rig.kem.lock().unwrap().expire_access_tokens();
    let before = rig.outside.asked();
    assert_eq!(rig.ask(json!({"op": "sync-off"}))["ok"], json!(true));
    assert_eq!((rig.outside.asked(), rig.outside.said.lock().unwrap().asked.last().unwrap().message), (before + 1, say::SYNC_OFF));
    until(|| (rig.status()["connected"] == json!(false)).then_some(()));
    assert_eq!(rig.kem.lock().unwrap().account(EMAIL).devices.len(), 0, "the device is signed out on the server");
    assert!(rig.items("sync-links").is_empty());
    assert!(rig.items("sync-account").is_empty());
    assert_eq!(rig.items("password").len(), 1, "the vault keeps its items");
    assert_eq!(rig.server_items().len(), 1, "and the server what it has");
    // Nothing runs any more
    let seen = rig.kem.lock().unwrap().seen.len();
    std::thread::sleep(Duration::from_millis(600));
    assert_eq!(rig.kem.lock().unwrap().seen.len(), seen);
    // A no to the question leaves everything as it is
    let rig = self::rig("kem-off-no", Settings::default());
    rig.set_up();
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    rig.outside.said.lock().unwrap().refuse = true;
    assert_eq!(rig.ask(json!({"op": "sync-off"}))["ok"], json!(false));
    assert_eq!((rig.status()["connected"].clone(), rig.kem.lock().unwrap().account(EMAIL).devices.len()), (json!(true), 1));
}

#[test]
fn a_server_that_signs_out_is_still_left_when_it_cannot_be_reached() {
    let rig = rig("kem-off-down", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    rig.kem.lock().unwrap().down = Some(amethystora_vault_core::sync::api::NetFailure::Unreachable);
    assert_eq!(rig.ask(json!({"op": "sync-off"}))["ok"], json!(true));
    until(|| (rig.status()["connected"] == json!(false)).then_some(()));
    assert!(rig.items("sync-links").is_empty());
}

#[test]
fn a_protected_file_goes_through_the_network_service_whole() {
    let rig = rig("kem-files", Settings::default());
    rig.set_up();
    // The largest file a vault holds is some 11 MiB (an item is one file of 16 MiB at most, the file in it in base64): that goes through the
    // network service's limits, in a request of its own and back, and the server holds it as it was sent
    let size = 11 * 1024 * 1024;
    let bytes: Vec<u8> = (0..size).map(|at| (at % 251) as u8).collect();
    let (meta, value) = protected_file(&bytes);
    rig.inject("protected", "big", "big.bin", &meta, &value);
    let (meta, value) = protected_file(b"small");
    rig.inject("protected", "small", "small.bin", &meta, &value);
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.choose_kept_off();
    let status = rig.synced();
    assert_eq!(status["problem"], Value::Null, "{status}");
    assert_eq!(status["last"]["report"]["refused_total"], json!(0), "{status}");
    {
        let kem = rig.kem.lock().unwrap();
        let mut sizes: Vec<u64> = kem.account(EMAIL).files.values().map(|file| file.size).collect();
        sizes.sort();
        let sealed = |n: usize| amethystora_vault_core::kemlock::kma1::sealed_len(n) as u64;
        assert_eq!(sizes, vec![sealed(5), sealed(size)], "{sizes:?}");
    }
    // A second run neither sends the file again nor makes another
    let (batches, revisions, files) = (rig.batches(), rig.revisions(), rig.kem.lock().unwrap().account(EMAIL).files.len());
    assert_eq!(rig.sync_now()["ok"], json!(true));
    assert_eq!((rig.batches(), rig.revisions(), rig.kem.lock().unwrap().account(EMAIL).files.len()), (batches, revisions, files));
    assert_eq!(rig.items("protected").len(), 2);
}

#[test]
fn a_file_the_server_refuses_as_too_large_is_said_with_its_reason_and_the_rest_goes() {
    let rig = rig("kem-toolarge", Settings::default());
    rig.set_up();
    rig.kem.lock().unwrap().max_file = 5 * 1024 * 1024;
    let (meta, value) = protected_file(&vec![7u8; 8 * 1024 * 1024]);
    rig.inject("protected", "big", "big.bin", &meta, &value);
    let (meta, value) = protected_file(&vec![1u8; 1024 * 1024]);
    rig.inject("protected", "ok", "ok.bin", &meta, &value);
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.choose_kept_off();
    let status = until(|| {
        let status = rig.status();
        (status["last"].is_object() && status["running"] != json!(true)).then_some(status)
    });
    let refused = status["last"]["report"]["refused"].as_array().cloned().unwrap_or_default();
    assert_eq!(refused.len(), 1, "{status}");
    assert!(refused[0]["why"].as_str().is_some_and(|why| why.contains("too-large") || why.contains("file")), "{status}");
    assert_eq!(rig.server_items().len(), 2, "the login and the small file went: {:?}", rig.server_items());
    assert_eq!(rig.kem.lock().unwrap().account(EMAIL).files.len(), 1);
    // Nothing of the refused one is lost here
    assert_eq!(rig.items("protected").len(), 2);
}

#[test]
fn a_person_accepts_what_went_and_is_asked() {
    let rig = rig("kem-accept", Settings::default());
    rig.set_up();
    for n in 0..8 {
        rig.password(&format!("p{n}"), &format!("Item {n}"), "person", &format!("pw {n}"), "");
    }
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    // Accepting asks, and a no is not a run
    rig.outside.said.lock().unwrap().refuse = true;
    let seen = rig.kem.lock().unwrap().seen.len();
    let before = rig.outside.asked();
    assert_eq!(rig.ask(json!({"op": "sync-now", "accept_gone": true}))["ok"], json!(false));
    assert_eq!(rig.outside.asked(), before + 1);
    assert_eq!(rig.kem.lock().unwrap().seen.len(), seen);
    rig.outside.said.lock().unwrap().refuse = false;

    // The server empties the account of many items at once: a run does not take that over by itself, it stops and says so
    let ids = rig.kem.lock().unwrap().live_ids(EMAIL);
    {
        let mut kem = rig.kem.lock().unwrap();
        for id in &ids {
            kem.plant_tombstone(EMAIL, id);
        }
        kem.sign_manifest(EMAIL);
    }
    let answer = rig.sync_now();
    assert_eq!((answer["ok"].clone(), answer["problem"]["name"].clone()), (json!(false), json!("many-gone")), "{answer}");
    assert_eq!(answer["problem"]["detail"]["count"], json!(8));
    assert!(rig.items("password").iter().all(|item| item["meta"]["deletedAt"].is_null()), "nothing was trashed here without being asked");
    // Said to the person, who says yes: the vault's items go to its trash
    let before = rig.outside.asked();
    let answer = rig.ask(json!({"op": "sync-now", "accept_gone": true}));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!((rig.outside.asked(), rig.outside.said.lock().unwrap().asked.last().unwrap().message), (before + 1, say::SYNC_ACCEPT));
    assert!(rig.items("password").iter().all(|item| item["meta"]["deletedAt"].is_number()));
}

#[test]
fn a_server_that_is_not_a_kemlock_server_is_left_to_the_bitwarden_side_and_a_wrong_choice_is_refused() {
    let rig = rig("kem-which", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "hunter2 ✓", "");
    // The Bitwarden server answers no `/kem/v1/config`, so the service goes on as it always did
    let answer = rig.talk().ask(json!({"op": "sync-connect", "address": rig.bw_address(), "email": BW_EMAIL, "secret": b64(BW_PASSWORD)}));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert!(answer.get("backend").is_none() || answer["backend"] != json!("kemlock"), "{answer}");
    let status = rig.synced();
    assert_eq!(status["backend"], json!("bitwarden"));
    assert_eq!(rig.bw.lock().unwrap().ciphers.len(), 1);
    // A word that is not a back end is refused
    let answer = rig.talk().ask(json!({"op": "sync-connect", "address": rig.kem_address(), "email": EMAIL, "secret": b64(PASSWORD), "backend": "elsewhere"}));
    assert_eq!(answer["ok"], json!(false));
    // Asking for the Kemlock back end of a Bitwarden server says it is not one, and changes nothing
    let answer = rig.talk().ask(json!({"op": "sync-connect", "address": rig.bw_address(), "email": BW_EMAIL, "secret": b64(BW_PASSWORD), "backend": "kemlock", "reconnect": true}));
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(rig.status()["backend"], json!("bitwarden"));
}

#[test]
fn a_vault_synced_with_bitwarden_moves_to_the_kemlock_server_of_the_same_account_and_adopts_the_login_both_hold() {
    let rig = rig("kem-move", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw one", "https://example.test/login");
    // A key, which Bitwarden's connection leaves at home until it is chosen
    let (key, _) = key_value();
    rig.put("key", "k1", "A key", json!({"key_kind": "exchange", "exportable": true}), key);
    // The Kemlock app's own item, on the Kemlock Server, and its copy on the Bitwarden API, as that app writes both: a Login with the hidden
    // `Kemlock` field that names its entry
    let entry = "1b712e6d-bbb9-4f9c-acf2-d3aad29f7257";
    {
        let mut kem = rig.kem.lock().unwrap();
        kem.plant_item(EMAIL, "login", &json!({"id": entry, "name": "GitHub", "username": "sam", "password": "hunter2-but-longer", "websites": ["github.com"], "addedAt": 1_762_000_000_000i64, "pinned": true}));
        kem.sign_manifest(EMAIL);
    }
    {
        let mut bw = rig.bw.lock().unwrap();
        let content = Content {
            kind: LOGIN,
            name: "GitHub".into(),
            username: Some("sam".into()),
            password: Some("hunter2-but-longer".into()),
            uri: Some("github.com".into()),
            fields: vec![Field { name: "Kemlock".into(), value: json!({"id": entry}).to_string(), hidden: true }],
            ..Content::default()
        };
        let body = cipher::create_body(&content, amethystora_vault_core::sync::fake::USER_ID, &bw.user).unwrap();
        bw.store(body);
    }
    // The vault syncs with Bitwarden's API first
    let answer = rig.talk().ask(json!({"op": "sync-connect", "address": rig.bw_address(), "email": BW_EMAIL, "secret": b64(BW_PASSWORD), "backend": "bitwarden"}));
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!(rig.synced()["backend"], json!("bitwarden"));
    let titles: Vec<String> = rig.items("password").iter().map(|item| item["name"].as_str().unwrap().to_string()).collect();
    assert!(titles.contains(&"GitHub".to_string()) && titles.contains(&"Example".to_string()), "{titles:?}");

    // The two servers cannot share an account id, so the connection says it is the Kemlock account's: then the move is the same account's
    let kem_id = rig.kem_id.clone();
    rig.with_store(true, |store| {
        let mut value = store.get(KIND_CONNECTION, CONNECTION_ID).unwrap();
        value["user_id"] = json!(kem_id);
        store.put(KIND_CONNECTION, CONNECTION_ID, "account", &Value::Null, Approval::Never, &value).unwrap();
    });
    rig.idle();

    // Another account of the same server is not moved over: the ids differ, and nothing is changed
    rig.kem.lock().unwrap().make_account("someone@else.test", "another password");
    let mut other = rig.connection_request();
    other["email"] = json!("someone@else.test");
    other["secret"] = json!(b64("another password"));
    other["reconnect"] = json!(true);
    other["backend"] = json!("kemlock");
    let answer = rig.talk().ask(other);
    assert_eq!((answer["ok"].clone(), answer["problem"].clone()), (json!(false), json!("other-account")), "{answer}");
    assert_eq!(rig.status()["backend"], json!("bitwarden"));
    assert_eq!(rig.items("sync-account").len(), 1);

    // Without the Kemlock API chosen, a reconnection stays on Bitwarden's: the Kemlock server is not even asked, and nothing moves
    let mut request = rig.connection_request();
    request["reconnect"] = json!(true);
    let asked = rig.kem.lock().unwrap().requests_to("/kem/v1/");
    let answer = rig.talk().ask(request.clone());
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(rig.kem.lock().unwrap().requests_to("/kem/v1/"), asked, "the Kemlock API was not asked");
    assert_eq!(rig.status()["backend"], json!("bitwarden"));
    // Chosen, it moves
    request["backend"] = json!("kemlock");
    let answer = rig.talk().ask(request);
    assert_eq!((answer["ok"].clone(), answer["backend"].clone(), answer["moved"].clone()), (json!(true), json!("kemlock"), json!(true)), "{answer}");
    let status = until(|| {
        let status = rig.status();
        (status["backend"] == json!("kemlock") && status["moved"]["finished_ms"].is_number() && status["running"] != json!(true)).then_some(status)
    });
    assert_eq!(status["problem"], Value::Null, "{status}");
    // A kind that was off on Bitwarden's connection only by default is still off: no key was sent after the one question about moving
    for word in ["keys", "certificates", "files"] {
        assert_eq!(status["kinds"][word], json!("off"), "{word}: {status}");
    }
    assert_eq!(status["kinds"]["passwords"], json!("on"));
    // The server holds the login of the Kemlock app once, as the app wrote it, and the vault's own login under its id
    let items = rig.server_items();
    assert_eq!(items.len(), 2, "{items:?}");
    let (shared_id, shared) = rig.server_item("GitHub");
    assert_eq!(shared["pinned"], json!(true), "the app's own keys were left as they were");
    assert_eq!(rig.kem.lock().unwrap().revision_of(EMAIL, &shared_id), Some(1), "an item that is the same is not written over");
    assert_eq!(rig.server_item("Example").1["password"], json!("pw one"));
    // Nothing was trashed on either side, and the Bitwarden server was left as it was
    assert!(rig.items("password").iter().all(|item| item["meta"]["deletedAt"].is_null()));
    assert!(rig.bw.lock().unwrap().ciphers.iter().all(|raw| raw["deletedDate"].is_null()));
    // It goes on as an ordinary connection
    let (batches, revisions) = (rig.batches(), rig.revisions());
    let answer = rig.sync_now();
    assert_eq!(answer["ok"], json!(true), "{answer}");
    assert_eq!((rig.batches(), rig.revisions()), (batches, revisions));
}

#[test]
fn a_server_that_is_down_connects_nothing_and_stops_nothing() {
    // The network service is not there at all
    let rig = rig("kem-down", Settings { net: false, ..Settings::default() });
    rig.set_up();
    rig.password("p1", "Example", "u", "p", "");
    let answer = rig.connect();
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(rig.status()["connected"], json!(false));
    assert!(rig.kem.lock().unwrap().seen.is_empty());
    assert_eq!(rig.value_of("password", "p1")["password"], "p");
}

#[test]
fn a_refused_approval_connects_nothing() {
    let rig = rig("kem-refused", Settings::default());
    rig.set_up();
    rig.outside.said.lock().unwrap().refuse = true;
    let answer = rig.connect();
    assert_eq!(answer["ok"], json!(false));
    assert!(rig.kem.lock().unwrap().seen.is_empty(), "the server heard nothing");
}

#[test]
fn a_wrong_password_connects_nothing_and_a_closed_vault_syncs_nothing() {
    let rig = rig("kem-wrong", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "u", "p", "");
    let mut request = rig.connection_request();
    request["secret"] = json!(b64("not the password"));
    let answer = rig.talk().ask(request);
    assert_eq!(answer["ok"], json!(false), "{answer}");
    assert_eq!(rig.status()["connected"], json!(false));
    assert!(rig.items("sync-account").is_empty());
    assert_eq!(rig.sessions(), 0);

    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    assert_eq!(rig.ask(json!({"op": "lock"}))["ok"], json!(true));
    for op in ["sync-status", "sync-now", "sync-off", "sync-connect"] {
        let answer = rig.ask(json!({"op": op, "address": rig.kem_address()}));
        assert_eq!(answer["why"], json!("closed"), "{op}: {answer}");
    }
    let seen = rig.kem.lock().unwrap().seen.len();
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(rig.kem.lock().unwrap().seen.len(), seen);
    // Opened again, it looks at the server by itself
    assert_eq!(rig.ask(json!({"op": "unlock", "method": "password", "secret": b64(VAULT_PASSWORD)}))["ok"], json!(true));
    until(|| (rig.kem.lock().unwrap().seen.len() > seen).then_some(()));
    rig.synced();
}

#[test]
fn a_kemlock_connection_never_falls_back_to_bitwardens_login_when_the_server_does_not_answer_like_one() {
    let rig = rig("kem-downgrade", Settings::default());
    rig.set_up();
    rig.password("p1", "Example", "person", "pw", "");
    assert_eq!(rig.connect()["ok"], json!(true));
    rig.synced();
    // The question that finds a Kemlock Server fails on the next connection: a hostile or broken server, a proxy
    rig.kem.lock().unwrap().config_override = Some((503, json!({})));
    let seen = rig.kem.lock().unwrap().seen.len();
    let mut request = rig.connection_request();
    request["reconnect"] = json!(true);
    let answer = rig.talk().ask(request);
    assert_eq!(answer["ok"], json!(false), "{answer}");
    // No Bitwarden prelogin or login went to the server, which is where the master password's Bitwarden hash would have gone
    let after: Vec<String> = rig.kem.lock().unwrap().seen[seen..].iter().map(|seen| seen.path()).collect();
    assert!(after.iter().all(|path| !path.contains("/identity/") && !path.contains("/api/")), "{after:?}");
    // And the connection is what it was
    rig.kem.lock().unwrap().config_override = None;
    rig.idle();
    let status = rig.status();
    assert_eq!((status["backend"].clone(), status["connected"].clone()), (json!("kemlock"), json!(true)), "{status}");
}
