//! Sync with Kemlock Server's own API, the service's side (plans/vault-kemlock). The protocol is `vault-core/src/kemlock/sync`; this
//! file is what the service adds to it: the Argon2id of a sign-in made in a child of its own, discovery, the connection built from a
//! sign-in, the move from Bitwarden's copies, and the refresh token kept before it is used.
//!
//! Everything else is `sync.rs`'s: the hub that says when a run starts, the thread it runs on, the slices its result is put in
//! place in. A Kemlock run is the same `Outcome`, with a little more for the connection to keep (`News`).

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::Path;
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc::{SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use serde_json::{Value, json};
use zeroize::Zeroizing;

use amethystora_vault_core::kemlock::conv::b64_encode;
use amethystora_vault_core::kemlock::master::KdfParams;
use amethystora_vault_core::kemlock::sync::api::{KemApi, ServerConfig, base_of, read_config};
use amethystora_vault_core::kemlock::sync::dpop::DpopKey;
use amethystora_vault_core::kemlock::sync::signin::{self, Attempt as SignIn, Connected, Pending, Second, Step};
use amethystora_vault_core::kemlock::sync::state::{Adoption, MoveRecord};
use amethystora_vault_core::kemlock::Key;
use amethystora_vault_core::sync::address::Server;
use amethystora_vault_core::sync::api::{Http, Problem};
use amethystora_vault_core::sync::cipher;
use amethystora_vault_core::sync::crypto::Kdf;
use amethystora_vault_core::sync::merge::{Access, Connection, Link};

use crate::service::Service;
use crate::sync::{self as bw, KDF_CHILD, load_connection, save_connection};

/// Sign-in's Argon2id is as big as the Bitwarden side's, made the same way: by a child of this program, whose memory goes with it
pub fn derive_in(exe: &Path, password: &str, salt: &[u8], params: &KdfParams) -> Result<Key, Problem> {
    params.check().map_err(|_| Problem::Kdf(amethystora_vault_core::sync::crypto::KdfProblem::TooStrong))?;
    let request = Zeroizing::new(json!({"kemlock": true, "password": base64::engine::general_purpose::STANDARD.encode(password.as_bytes()), "salt": b64_encode(salt), "memory_kib": params.memory_kib, "iterations": params.iterations, "parallelism": params.parallelism}).to_string());
    let unknown = || Problem::Kdf(amethystora_vault_core::sync::crypto::KdfProblem::Unknown);
    let mut child = Command::new(exe).arg(KDF_CHILD).env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn().map_err(|_| unknown())?;
    let sent = child.stdin.take().is_some_and(|mut stdin| stdin.write_all(request.as_bytes()).is_ok());
    let mut answer = Zeroizing::new(Vec::new());
    let read = child.stdout.take().is_some_and(|stdout| stdout.take(256).read_to_end(&mut answer).is_ok());
    let status = child.wait().map_err(|_| unknown())?;
    if !(sent && read && status.success()) {
        return Err(unknown());
    }
    let bytes = Zeroizing::new(amethystora_vault_core::seal::unhex(std::str::from_utf8(&answer).map_err(|_| unknown())?.trim()).ok_or_else(unknown)?);
    Key::from_slice(&bytes).ok_or_else(unknown)
}

/// The child's side for a Kemlock key: one request, the key in hex on standard output
pub fn kdf_child(request: &Value) -> ExitCode {
    let b64 = |name: &str| request.get(name).and_then(Value::as_str).and_then(|text| base64::engine::general_purpose::STANDARD.decode(text).ok());
    let password = b64("password").map(Zeroizing::new).and_then(|bytes| String::from_utf8(bytes.to_vec()).ok()).map(Zeroizing::new);
    let salt = request.get("salt").and_then(Value::as_str).and_then(|salt| amethystora_vault_core::kemlock::conv::b64_decode(salt).ok());
    let number = |name: &str| request.get(name).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
    let (Some(password), Some(salt), Some(memory_kib), Some(iterations), Some(parallelism)) = (password, salt, number("memory_kib"), number("iterations"), number("parallelism")) else { return ExitCode::FAILURE };
    match amethystora_vault_core::kemlock::master::master_key(&password, &salt, &KdfParams { memory_kib, iterations, parallelism }) {
        Ok(key) => {
            let hex = Zeroizing::new(amethystora_vault_core::seal::hex(key.as_bytes()));
            if std::io::stdout().write_all(hex.as_bytes()).is_ok() { ExitCode::SUCCESS } else { ExitCode::FAILURE }
        }
        Err(_) => ExitCode::FAILURE,
    }
}

// --- Keeping the refresh token before it is used --------------------------------------------------------------------------------

/// A new refresh token a run's thread has, waiting for the loop to write it into the connection: the old one is spent, and a run
/// cut short between receiving the new and keeping it would leave the connection with a token the server takes as a theft
pub struct PersistRequest {
    uid: u32,
    closes: u64,
    refresh: Zeroizing<String>,
    ack: SyncSender<bool>,
}

#[derive(Default, Clone)]
pub struct Persists {
    pub queue: Arc<Mutex<VecDeque<PersistRequest>>>,
    pub wake: Arc<Mutex<Option<Arc<OwnedFd>>>>,
}

impl Persists {
    /// What a run's thread calls with each new refresh token: true once the connection holds it. It waits, within reason, for the
    /// loop, which is woken through the same pipe a finished job uses.
    pub fn persister(&self, uid: u32, closes: u64) -> Box<dyn Fn(&str) -> bool + Send> {
        let (queue, wake) = (self.queue.clone(), self.wake.clone());
        Box::new(move |refresh: &str| {
            let (ack, answer) = sync_channel(1);
            let Ok(mut waiting) = queue.lock() else { return false };
            waiting.push_back(PersistRequest { uid, closes, refresh: Zeroizing::new(refresh.to_string()), ack });
            drop(waiting);
            if let Ok(wake) = wake.lock()
                && let Some(fd) = wake.as_ref()
            {
                // SAFETY: one byte from a live buffer, to the loop's own pipe, which this holds a reference to
                unsafe { libc::write(fd.as_raw_fd(), [1u8].as_ptr().cast(), 1) };
            }
            answer.recv_timeout(Duration::from_secs(60)).unwrap_or(false)
        })
    }
}

/// The loop's side: each waiting token is written into the connection of the vault that is still the one it was made for
pub fn serve_persists(service: &mut Service) {
    let requests: Vec<PersistRequest> = service.sync.persists.queue.lock().map(|mut queue| queue.drain(..).collect()).unwrap_or_default();
    for request in requests {
        let kept = service.closes_so_far(request.uid) == request.closes
            && service.first_open(request.uid).is_some_and(|store| match load_connection(store) {
                Some(mut connection) if connection.kemlock.is_some() => {
                    connection.refresh = Some(request.refresh.to_string());
                    save_connection(store, &connection).is_ok()
                }
                _ => false,
            });
        let _ = request.ack.send(kept);
    }
}

// --- Connecting ----------------------------------------------------------------------------------------------------------------

/// Whether the server answers like a Kemlock Server on its own API: the only thing that offers the Kemlock back end
pub fn discover(http: &mut dyn Http, server: &Server) -> Option<ServerConfig> {
    let key = DpopKey::generate();
    let mut api = KemApi::new(http, server, &key);
    read_config(&api.config().ok()?)
}

pub struct KemAttempt<'a> {
    pub server: &'a Server,
    pub email: &'a str,
    pub password: &'a str,
    pub confirmed: Option<u32>,
    pub second: Option<(&'static str, &'a str)>,
    pub send_email: bool,
    pub pinned: Option<KdfParams>,
    pub device_id: Option<&'a str>,
    pub bitwarden_device: Option<&'a str>,
    pub opaque_seen: bool,
    /// What a login kept while the email's code was typed
    pub pending: Option<Box<Pending>>,
}

pub enum KemStep {
    Connected(Box<Connected>),
    Email(Box<Pending>),
    Problem(Problem),
}

/// The Kemlock sign-in, with Argon2id and Bitwarden's derived by the child
pub fn connect(http: &mut dyn Http, attempt: KemAttempt<'_>, exe: &Path) -> KemStep {
    let derive = |password: &str, salt: &[u8], params: &KdfParams| derive_in(exe, password, salt, params);
    let bitwarden = |password: &[u8], email: &str, kdf: &Kdf| bw::derive_for_kemlock(exe, password, email, kdf);
    let result = match (attempt.pending, &attempt.second) {
        (Some(pending), Some(("email", code))) => signin::finish_email(http, attempt.server, *pending, code, attempt.bitwarden_device),
        (_, _) => {
            let dpop = DpopKey::generate();
            let sign = SignIn {
                server: attempt.server,
                email: attempt.email,
                password: attempt.password,
                confirmed: attempt.confirmed,
                second: attempt.second.map(|(method, code)| Second { method, code }),
                send_email: attempt.send_email,
                pinned: attempt.pinned,
                device_id: attempt.device_id,
                bitwarden_device: attempt.bitwarden_device,
                opaque_seen: attempt.opaque_seen,
                dpop: &dpop,
            };
            signin::sign_in(http, &sign, &derive, &bitwarden)
        }
    };
    match result {
        Ok(Step::Connected(connected)) => KemStep::Connected(connected),
        Ok(Step::EmailSent(pending)) => KemStep::Email(pending),
        Err(problem) => KemStep::Problem(problem),
    }
}

/// The connection a sign-in makes, and the token it holds: its root key where the user key is, its refresh token where a Bitwarden
/// connection's is, and `kemlock` for the rest
pub fn connection_from(connected: Connected, server: &Server, email: &str, device: String, now_ms: i64) -> (Connection, Access) {
    let Connected { mut state, root, tokens, .. } = connected;
    let params = state.params();
    let user_id = tokens.user_id.clone();
    let access = Access { token: tokens.access.clone(), until_ms: now_ms + (tokens.expires_in.min(600) - 30) * 1000 };
    state.cursor = None;
    let connection = Connection {
        address: server.address.clone(),
        identity: format!("{}/identity", server.address),
        api: base_of(server),
        email: email.to_string(),
        user_id,
        user_key: amethystora_vault_core::seal::hex(root.as_bytes()),
        protected_key: String::new(),
        kdf: Kdf { kind: 1, iterations: params.iterations, memory: Some(params.memory_kib / 1024), parallelism: Some(params.parallelism) },
        device,
        api_key: None,
        refresh: Some(tokens.refresh.to_string()),
        remember: None,
        ca: None,
        pin: None,
        choices: Default::default(),
        kinds: Default::default(),
        no_files: None,
        files_read: false,
        pending: Vec::new(),
        last_revision: None,
        last_success_ms: None,
        last: None,
        waiting_since_ms: None,
        recent: Vec::new(),
        kemlock: Some(state),
    };
    (connection, access)
}

/// The vault items the Kemlock app wrote as Logins on the Bitwarden API that the Vault took in (a cipher it did not make, carrying the
/// app's own hidden `Kemlock` field): Kemlock's own `kem1` item is the same login, and the move links it rather than write it twice
/// (`spec-protocol.md` 10.4)
pub fn adoptions(old: &Connection, links: &[Link]) -> Vec<Adoption> {
    let Some(user) = old.key() else { return Vec::new() };
    let mut found = Vec::new();
    for link in links.iter().filter(|link| !link.made && !link.deleted) {
        let [part] = link.parts.as_slice() else { continue };
        let Ok(opened) = cipher::open(&link.raw, &user) else { continue };
        let Some(field) = opened.content.fields.iter().find(|field| field.name == "Kemlock") else { continue };
        let Ok(entry) = serde_json::from_str::<Value>(&field.value) else { continue };
        if let Some(id) = entry.get("id").and_then(Value::as_str).filter(|id| !id.is_empty() && id.len() <= 64) {
            found.push(Adoption { kind: part.kind.clone(), id: part.id.clone(), entry: id.to_string() });
        }
    }
    found
}

/// What a Kemlock connection carries over a Bitwarden connection of the same account: the choices and the device, and the move
pub fn carry_over(connection: &mut Connection, old: &Connection, links: &[Link], now_ms: i64) {
    connection.choices = old.choices.clone();
    connection.kinds = old.kinds.clone();
    connection.ca = old.ca.clone();
    connection.pin = old.pin.clone();
    if old.kemlock.is_none() {
        let adopt = adoptions(old, links);
        if let Some(state) = connection.kemlock.as_mut() {
            state.bitwarden_device = Some(old.device.clone());
            state.adopt = adopt;
            state.moved = Some(MoveRecord { started_ms: now_ms, ..MoveRecord::default() });
        }
        connection.device = old.device.clone();
    } else if let (Some(state), Some(old_state)) = (connection.kemlock.as_mut(), old.kemlock.as_ref()) {
        state.opaque_seen |= old_state.opaque_seen;
        state.bitwarden_device = old_state.bitwarden_device.clone();
        // The same back end again: where the sync stood, the manifest, and the move if it was not finished
        state.cursor = old_state.cursor.clone();
        state.manifest_counter = old_state.manifest_counter;
        state.manifest_sha256 = old_state.manifest_sha256.clone();
        state.held = old_state.held.clone();
        state.adopt = old_state.adopt.clone();
        state.moved = old_state.moved.clone();
    }
}

/// Signs this device out on the server, best effort: whatever it answers, the connection ends
pub fn sign_out(http: &mut dyn Http, connection: &Connection) {
    let Some(state) = &connection.kemlock else { return };
    let Some(key) = DpopKey::from_hex(&state.dpop_key) else { return };
    let server = connection.server();
    let mut api = KemApi::new(http, &server, &key);
    let Some(refresh) = connection.refresh.as_deref() else { return };
    let Ok(tokens) = api.refresh(refresh) else { return };
    api.access = Some(tokens.access);
    let _ = api.sign_out(&state.device_id);
}

