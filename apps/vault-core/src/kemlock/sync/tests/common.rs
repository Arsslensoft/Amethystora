//! What the test files share: the vault, the client, and the makers of every kind of item.

use std::cell::RefCell;
use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use serde_json::{Value, json};

use crate::items::{Account, BackupCode, BackupService, OtpKind, Password, Secret};
use crate::keys::{self, KeyType};
use crate::protocol::Approval;
use crate::kemlock::master::KdfParams;
use crate::sync::address::Server;
use crate::sync::api::Problem;
use crate::sync::convert::Direct;
use crate::sync::crypto::Kdf;
use crate::sync::map::{self, Local};
use crate::sync::merge::{Access, Connection, Link, Outcome};

use crate::kemlock::sync::api::unix_now;
use crate::kemlock::sync::dpop::DpopKey;
use crate::kemlock::sync::engine::{self, Input};
use crate::kemlock::sync::fake::{self, FakeKemlock};
use crate::kemlock::sync::signin::{self, Attempt, Connected, Second, Step};

pub const EMAIL: &str = "sam@example.test";
pub const PASSWORD: &str = "a master password for tests";

pub fn now_ms() -> i64 {
    unix_now() * 1000
}

pub fn server() -> FakeKemlock {
    let mut server = FakeKemlock::new(fake::BASE);
    server.make_account(EMAIL, PASSWORD);
    server
}

/// What a test changes in an attempt: owned, so that a closure may name a code or an id that lives in the test
#[derive(Default)]
pub struct Tweak {
    pub confirmed: Option<u32>,
    pub second: Option<(String, String)>,
    pub send_email: bool,
    pub pinned: Option<KdfParams>,
    pub device_id: Option<String>,
    pub bitwarden_device: Option<String>,
    pub opaque_seen: bool,
}

impl Tweak {
    pub fn attempt<'a>(&'a self, server: &'a Server, email: &'a str, password: &'a str, key: &'a DpopKey) -> Attempt<'a> {
        Attempt {
            server,
            email,
            password,
            confirmed: self.confirmed,
            second: self.second.as_ref().map(|(method, code)| Second { method, code }),
            send_email: self.send_email,
            pinned: self.pinned,
            device_id: self.device_id.as_deref(),
            bitwarden_device: self.bitwarden_device.as_deref(),
            opaque_seen: self.opaque_seen,
            dpop: key,
        }
    }
}

/// Signs in as the tests do: the stand-in key derivations the fake's accounts were made with
pub fn sign(fake: &mut FakeKemlock, email: &str, password: &str, key: &DpopKey, tweak: impl FnOnce(&mut Tweak)) -> Result<Step, Problem> {
    let mut tweaked = Tweak::default();
    tweak(&mut tweaked);
    let address = fake.server();
    let attempt = tweaked.attempt(&address, email, password, key);
    signin::sign_in(fake, &attempt, &fake::derive, &fake::bitwarden_derive)
}

pub fn connected(step: Result<Step, Problem>) -> Connected {
    match step {
        Ok(Step::Connected(connected)) => *connected,
        Ok(Step::EmailSent(_)) => panic!("an email's code was asked for"),
        Err(problem) => panic!("not connected: {problem:?}"),
    }
}

/// The connection the service would keep after a sign-in: the root key where the Bitwarden user key goes, the refresh token, the state
pub fn connection_of(connected: &Connected, address: &Server, email: &str) -> Connection {
    Connection {
        address: address.address.clone(),
        identity: address.identity.clone(),
        api: address.api.clone(),
        email: email.to_string(),
        user_id: connected.tokens.user_id.clone(),
        user_key: crate::seal::hex(connected.root.as_bytes()),
        protected_key: String::new(),
        kdf: Kdf { kind: 1, iterations: 3, memory: Some(64), parallelism: Some(4) },
        device: "dev-1".into(),
        api_key: None,
        refresh: Some(connected.tokens.refresh.to_string()),
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
        kemlock: Some(connected.state.clone()),
    }
}

/// A device of the person's: a connection, the vault it syncs, and the links between them
pub struct Client {
    pub connection: Connection,
    pub access: Option<Access>,
    pub locals: BTreeMap<(String, String), Local>,
    pub links: BTreeMap<String, Link>,
    /// Every refresh token handed to the service to keep, in order
    pub persisted: Vec<String>,
    pub refuse_persist: bool,
    pub now_ms: i64,
}

impl Client {
    pub fn connect(fake: &mut FakeKemlock, email: &str) -> Client {
        Client::connect_as(fake, email, PASSWORD)
    }

    pub fn connect_as(fake: &mut FakeKemlock, email: &str, password: &str) -> Client {
        let key = DpopKey::generate();
        let done = connected(sign(fake, email, password, &key, |_| {}));
        Client::from(done, &fake.server(), email)
    }

    pub fn from(done: Connected, address: &Server, email: &str) -> Client {
        Client { connection: connection_of(&done, address, email), access: None, locals: BTreeMap::new(), links: BTreeMap::new(), persisted: Vec::new(), refuse_persist: false, now_ms: now_ms() }
    }

    pub fn put(&mut self, kind: &str, id: &str, value: Value) {
        let name = map::name_of(kind, &value);
        self.locals.insert((kind.into(), id.into()), Local { kind: kind.into(), id: id.into(), name, meta: Value::Null, approval: Approval::WhileOpen, value });
    }

    pub fn add(&mut self, local: Local) {
        self.locals.insert((local.kind.clone(), local.id.clone()), local);
    }

    pub fn value(&self, kind: &str, id: &str) -> Value {
        self.locals.get(&(kind.into(), id.into())).map(|local| local.value.clone()).unwrap_or(Value::Null)
    }

    pub fn has(&self, kind: &str, id: &str) -> bool {
        self.locals.contains_key(&(kind.into(), id.into()))
    }

    pub fn of_kind(&self, kind: &str) -> Vec<&Local> {
        self.locals.values().filter(|local| local.kind == kind).collect()
    }

    pub fn sync(&mut self, fake: &mut FakeKemlock) -> Outcome {
        self.run(fake, false, false)
    }

    pub fn accept(&mut self, fake: &mut FakeKemlock) -> Outcome {
        self.run(fake, true, false)
    }

    pub fn run(&mut self, fake: &mut FakeKemlock, accept: bool, full: bool) -> Outcome {
        let log = RefCell::new(Vec::new());
        let refuse = self.refuse_persist;
        let persist = |token: &str| {
            log.borrow_mut().push(token.to_string());
            !refuse
        };
        let input = Input {
            connection: self.connection.clone(),
            access: self.access.take(),
            links: self.links.values().cloned().collect(),
            locals: self.locals.values().cloned().collect(),
            accept,
            full,
            now_ms: self.now_ms,
            local_unreadable: 0,
            links_unreadable: false,
        };
        let mut outcome = engine::run(fake, &Direct, input, &persist);
        self.persisted.extend(log.into_inner());
        self.apply(&mut outcome);
        outcome
    }

    /// As the service applies a run: a group whose basis no longer holds is skipped whole, and so is every later one for that item
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

}

// --- The makers of items -------------------------------------------------------------------------------------------------------

pub fn password(title: &str, username: &str, secret: &str, address: &str) -> Value {
    serde_json::to_value(Password { title: title.into(), username: username.into(), password: Secret::new(secret), address: address.into(), added_at: 1_760_000_000_000, ..Password::default() }).unwrap()
}

pub fn with_id(mut value: Value, id: &str) -> Value {
    value["id"] = json!(id);
    value
}

pub fn totp_account(issuer: &str, label: &str) -> Value {
    serde_json::to_value(Account { kind: Some(OtpKind::Totp), issuer: issuer.into(), label: label.into(), secret: Secret::new("JBSWY3DPEHPK3PXP"), added_at: 1_760_000_000_000, ..Account::default() }).unwrap()
}

pub fn backup_codes(service: &str) -> Value {
    serde_json::to_value(BackupService { service_name: service.into(), codes: vec![BackupCode::new("1111-2222"), BackupCode::new("3333-4444")], added_at: 1_760_000_000_000, ..BackupService::default() }).unwrap()
}

pub fn key_local(id: &str, name: &str, key_kind: &str, key_type: KeyType) -> Local {
    let key = keys::generate(key_type).unwrap();
    let public = key.public().ok();
    let public_json = public.as_ref().map_or(Value::Null, |forms| json!({"type": key_type.name(), "pem": forms.spki_pem, "openssh": forms.openssh, "sha256": forms.sha256, "ssh_sha256": forms.ssh_sha256}));
    let value = json!({"key_kind": key_kind, "type": key_type.name(), "key": B64.encode(key.as_bytes()), "exportable": true, "public": public_json, "comment": null});
    let meta = json!({"key_kind": key_kind, "type": key_type.name(), "exportable": true});
    Local { kind: "key".into(), id: id.into(), name: name.into(), meta, approval: Approval::WhileOpen, value }
}

/// A self-signed certificate of an Ed25519 key, as the vault's own certificate item holds one
pub fn cert_local(id: &str, name: &str) -> Local {
    use openssl::asn1::Asn1Time;
    use openssl::bn::BigNum;
    use openssl::hash::MessageDigest;
    use openssl::x509::{X509Builder, X509NameBuilder};
    let key = keys::generate(KeyType::Ed25519).unwrap();
    let pkey = key.pkey().unwrap();
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
    let told = crate::pki::describe(&der).unwrap();
    let value = json!({"profile": "code", "type": "ed25519", "key": B64.encode(key.as_bytes()), "cert": B64.encode(&der), "chain": [], "fields": {}});
    let meta = json!({"profile": "code", "subject": told.subject, "issuer": told.issuer, "not_before": told.not_before, "not_after": told.not_after, "sha256": told.sha256, "spki_sha256": told.key.sha256, "key_type": "ed25519"});
    Local { kind: "certificate".into(), id: id.into(), name: name.into(), meta, approval: Approval::WhileOpen, value }
}

pub fn file_local(id: &str, path: &str, bytes: &[u8]) -> Local {
    let value = json!({"what": "file", "files": [{"at": "", "mode": 0o600, "data": B64.encode(bytes)}], "folders": []});
    Local { kind: "protected".into(), id: id.into(), name: path.into(), meta: json!({"path": path, "what": "file", "size": bytes.len(), "files": 1}), approval: Approval::WhileOpen, value }
}

pub fn folder_local(id: &str, path: &str) -> Local {
    let value = json!({"what": "folder", "files": [{"at": "a/one.txt", "mode": 0o600, "data": B64.encode(b"one")}, {"at": "two.bin", "mode": 0o644, "data": B64.encode(vec![9u8; 6000])}], "folders": [{"at": "a", "mode": 0o700}]});
    Local { kind: "protected".into(), id: id.into(), name: path.into(), meta: json!({"path": path, "what": "folder", "files": 2}), approval: Approval::WhileOpen, value }
}

pub const PASSWORD_ID: &str = "6bce1f8e-000f-4565-9ef6-5a1bfd58a156";
pub const ACCOUNT_ID: &str = "848d7ae8-73b0-431e-8f3a-0efce7efc966";
pub const CODES_ID: &str = "0b4d2e4c-6a44-4f5e-9b1a-2f3c4d5e6f70";
pub const SSH_ID: &str = "3f2c9a71e4b0d856";
pub const EXCHANGE_ID: &str = "a07c5e19d2b34f60";
pub const AES_ID: &str = "b6e1f3a2c4d58e97";
pub const CERT_ID: &str = "5e8a0f2c71b94d36";
pub const FILE_ID: &str = "d93b0e7a5f214c68";
pub const FOLDER_ID: &str = "0aa1b2c3d4e5f607";

/// Every kind the Vault sends, under ids of the vault's own (16 hex characters for what is not a UUID)
pub fn every_kind(client: &mut Client) {
    client.put("password", PASSWORD_ID, with_id(password("Larkspur Mail", "sam@example.org", "cobalt-otter-41", "https://mail.larkspur.example/login"), PASSWORD_ID));
    client.put("authenticator", ACCOUNT_ID, with_id(totp_account("GitHub", "sam"), ACCOUNT_ID));
    client.put("backup-codes", CODES_ID, with_id(backup_codes("GitHub"), CODES_ID));
    client.add(key_local(SSH_ID, "laptop", "ssh", KeyType::Ed25519));
    client.add(key_local(EXCHANGE_ID, "backup recipient", "exchange", KeyType::X25519));
    client.add(key_local(AES_ID, "disk image key", "symmetric", KeyType::Aes256));
    client.add(cert_local(CERT_ID, "Document signing"));
    client.add(file_local(FILE_ID, "tax-2025.pdf", b"a file of the person's"));
    client.add(folder_local(FOLDER_ID, "keys"));
}

pub fn assert_clean(problem: &Option<Problem>) {
    assert!(problem.is_none(), "the run stopped: {problem:?}");
}
