//! Signing in to Kemlock Server (`spec-protocol.md` 2): Argon2id and OPAQUE for an account made on the Kemlock API, the one-time
//! enrolment through the Bitwarden hash for a Compatible account (one made through Bitwarden's API), the second steps a desktop
//! can do headlessly, and the account's keys opened and checked at the end. What a connection keeps comes out as a `KemlockState`.
//!
//! Nothing is kept here: a failure leaves nothing behind, and the master password is never an argument past `derive`.

use serde_json::{Value, json};
use zeroize::Zeroizing;

use crate::kemlock::conv::{Uuid, b64_decode, b64_encode};
use crate::kemlock::keys::{PrivateKeys, password_wrap_key, unwrap_root_key, user_key, wrap_root_key};
use crate::kemlock::master::{Confirm, DEFAULT_PARAMS, KdfParams};
use crate::kemlock::opaque;
use crate::kemlock::{Key, RootKey, Secret};
use crate::sync::address::Server;
use crate::sync::api::{self, Expired, Http, Problem};
use crate::sync::crypto::{self, KdfProblem};
use crate::sync::merge::Derive as BitwardenDerive;

use super::account::{self, Account};
use super::api::{KemApi, SignedIn, Tokens, read_config, same_domain};
use super::dpop::DpopKey;
use super::state::KemlockState;
use super::{DEVICE_KIND, DEVICE_NAME, word};

/// Argon2id, made where the service wants it made (a child of its own): the typed password, the account's salt and the settings
pub type Derive<'a> = dyn Fn(&str, &[u8], &KdfParams) -> Result<Key, Problem> + 'a;

/// A second step the person gave: `totp`, `email` or `recovery`, and the code
pub struct Second<'a> {
    pub method: &'a str,
    pub code: &'a str,
}

pub struct Attempt<'a> {
    pub server: &'a Server,
    /// Trimmed and in lower case
    pub email: &'a str,
    pub password: &'a str,
    /// What the person agreed to be made of a key under Kemlock's defaults or over 256 MiB: `confirm_token` of the settings
    pub confirmed: Option<u32>,
    pub second: Option<Second<'a>>,
    /// Ask for the email's code, and keep what the login holds until it is given
    pub send_email: bool,
    /// The settings of an earlier sign-in to this account: asking for less is refused
    pub pinned: Option<KdfParams>,
    /// The device id an earlier sign-in was given
    pub device_id: Option<&'a str>,
    /// The identifier the same account's Bitwarden sign-in used, so that both are one device on the server
    pub bitwarden_device: Option<&'a str>,
    /// OPAQUE worked for this account on this Vault before: the Bitwarden-hash route is closed
    pub opaque_seen: bool,
    pub dpop: &'a DpopKey,
}

/// What the person confirms for these settings: a heavy key by its memory, a weak one by memory and passes together
pub fn confirm_token(confirm: Confirm) -> u32 {
    match confirm {
        Confirm::Heavy { memory_mib } => memory_mib,
        Confirm::Weak { memory_mib, iterations } => (memory_mib << 8 | iterations & 0xff) | 0x8000_0000,
    }
}

pub struct Connected {
    pub state: KemlockState,
    pub root: RootKey,
    pub tokens: Tokens,
    /// The Bitwarden hash went to the server, once, to make the account's Kemlock keys
    pub enrolled: bool,
    /// The server's DPoP nonce and the clock skew this sign-in learned, for the first run to start from
    pub nonce: Option<String>,
    pub skew: i64,
}

/// What a login holds while the person types the email's code: five minutes' worth, in memory only
pub struct Pending {
    pub dpop_hex: Zeroizing<String>,
    pub challenge: String,
    pub master: Key,
    pub export: Secret<64>,
    pub params: KdfParams,
    pub salt: Vec<u8>,
    pub device: Value,
    pub opaque_seen: bool,
    pub enrolled: bool,
    pub born: i64,
}

pub enum Step {
    Connected(Box<Connected>),
    /// The email's code was sent
    EmailSent(Box<Pending>),
}

fn kdf_problem(params: &KdfParams) -> Problem {
    let weak = params.memory_kib < crate::kemlock::master::MIN_MEMORY_KIB || params.iterations < crate::kemlock::master::MIN_ITERATIONS || params.parallelism < 1;
    Problem::Kdf(if weak { KdfProblem::TooWeak } else { KdfProblem::TooStrong })
}

/// The settings and salt a prelogin answered, held to the bounds and, when there is one, the pin
fn read_prelogin(body: &Value, pinned: Option<&KdfParams>) -> Result<(KdfParams, Vec<u8>), Problem> {
    let kdf = body.get("kdf").ok_or(Problem::BadResponse)?;
    let number = |name: &str| kdf.get(name).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok());
    let params = KdfParams { memory_kib: number("memoryKib").ok_or(Problem::BadResponse)?, iterations: number("iterations").ok_or(Problem::BadResponse)?, parallelism: number("parallelism").ok_or(Problem::BadResponse)? };
    let salt = kdf.get("salt").and_then(Value::as_str).and_then(|salt| b64_decode(salt).ok()).ok_or(Problem::BadResponse)?;
    if params.check().is_err() {
        return Err(kdf_problem(&params));
    }
    if !(crate::kemlock::master::SALT_MIN..=crate::kemlock::master::SALT_MAX).contains(&salt.len()) {
        return Err(Problem::BadResponse);
    }
    if pinned.is_some_and(|pinned| params.below(pinned)) {
        return Err(Problem::Kdf(KdfProblem::BelowPin));
    }
    Ok((params, salt))
}

fn device_of(attempt: &Attempt<'_>) -> Value {
    let mut device = json!({"name": DEVICE_NAME, "kind": DEVICE_KIND});
    if let Some(identifier) = attempt.bitwarden_device.filter(|id| super::is_device_identifier(id)) {
        // One row on both APIs: the server ignores `id` then
        device["bitwardenDeviceIdentifier"] = json!(identifier);
    } else if let Some(id) = attempt.device_id.filter(|id| api::is_uuid(id)) {
        device["id"] = json!(id);
    }
    device
}

/// OPAQUE's two rounds. `Ok(None)` is a server proof that did not verify: a wrong password, a Compatible account with no OPAQUE
/// record yet, or a server that is not the one registered with: the caller cannot tell which.
fn opaque_login(api: &mut KemApi<'_>, email: &str, master: &Key, device: &Value) -> Result<Option<(opaque::LoggedIn, SignedIn)>, Problem> {
    let (state, ke1) = opaque::login_start(master).map_err(|_| Problem::BadResponse)?;
    let (ke2, login_state) = api.opaque_start(email, &ke1)?;
    let logged = match opaque::login_finish(state, master, &ke2) {
        Ok(logged) => logged,
        Err(crate::kemlock::Error::Unopened) => return Ok(None),
        Err(_) => return Err(Problem::BadResponse),
    };
    let signed = api.opaque_finish(email, &login_state, &logged.ke3, device)?;
    Ok(Some((logged, signed)))
}

/// The methods an account asks for as the numbers the window's second step knows (Bitwarden's provider numbers): 0 an authenticator
/// app, 1 an email's code, 8 a recovery code, which the server takes whatever the account has
pub fn providers_of(methods: &[String]) -> Vec<u8> {
    let mut providers: Vec<u8> = Vec::new();
    for method in methods {
        match method.as_str() {
            "totp" => providers.push(0),
            "email" => providers.push(1),
            _ => {}
        }
    }
    providers.push(8);
    providers
}

pub fn method_of(provider: u8) -> Option<&'static str> {
    match provider {
        0 => Some("totp"),
        1 => Some("email"),
        8 => Some("recovery"),
        _ => None,
    }
}

/// Signs in. A step that needs the person (a second step, a confirmation) is a `Problem` that says so; the same attempt is made
/// again with what they gave.
pub fn sign_in(http: &mut dyn Http, attempt: &Attempt<'_>, derive: &Derive<'_>, bitwarden: &BitwardenDerive<'_>) -> Result<Step, Problem> {
    let mut api = KemApi::new(http, attempt.server, attempt.dpop);
    let config = read_config(&api.config()?).ok_or(Problem::Kemlock(word::NOT_KEMLOCK))?;
    if !["opaque", "dpop", "sync"].iter().all(|feature| config.has(feature)) {
        return Err(Problem::Kemlock(word::SERVER_TOO_OLD));
    }
    if !config.domain.is_empty() && !same_domain(&attempt.server.address, &config.domain) {
        return Err(Problem::Kemlock(word::DOMAIN_DIFFERS));
    }
    let methods = api.methods(attempt.email)?;
    if methods.get("methods").and_then(Value::as_array).is_some_and(|methods| !methods.iter().any(|m| m.as_str() == Some("password"))) {
        return Err(Problem::Kemlock(word::SSO_ONLY));
    }
    let (params, salt) = read_prelogin(&api.prelogin(attempt.email)?, attempt.pinned.as_ref())?;
    if let Some(confirm) = params.confirm()
        && attempt.confirmed != Some(confirm_token(confirm))
    {
        return Err(match confirm {
            Confirm::Heavy { memory_mib } => Problem::KdfMemoryConfirm(memory_mib),
            Confirm::Weak { memory_mib, iterations } => Problem::KdfWeakConfirm { memory: memory_mib, iterations },
        });
    }
    let master = derive(attempt.password, &salt, &params)?;
    let device = device_of(attempt);
    match opaque_login(&mut api, attempt.email, &master, &device)? {
        Some((logged, signed)) => with_signed(&mut api, attempt, master, logged.export_key, params, salt, device, signed, true, false),
        None => {
            // A wrong password, a Compatible account's first sign-in, or a server that is not the one registered with. Only the first
            // may send Bitwarden's hash, and only if this Vault never saw OPAQUE work for the account, which a hostile server cannot
            // fake and a rolled-back one cannot undo.
            if attempt.opaque_seen || !config.has("bitwarden-enrol") {
                return Err(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER));
            }
            enrol(&mut api, attempt, derive, bitwarden)
        }
    }
}

/// After OPAQUE: the tokens, through the second step if one is owed, and the account's keys
#[allow(clippy::too_many_arguments)]
fn with_signed(api: &mut KemApi<'_>, attempt: &Attempt<'_>, master: Key, export: Secret<64>, params: KdfParams, salt: Vec<u8>, device: Value, signed: SignedIn, opaque_seen: bool, enrolled: bool) -> Result<Step, Problem> {
    let tokens = match signed {
        SignedIn::Tokens(tokens) => tokens,
        SignedIn::SecondStep { challenge, methods } => match &attempt.second {
            Some(second) => api.second_step(second.method, &challenge, second.code)?,
            None if attempt.send_email => {
                api.email_send(&challenge)?;
                return Ok(Step::EmailSent(Box::new(Pending {
                    dpop_hex: attempt.dpop.to_hex(),
                    challenge,
                    master,
                    export,
                    params,
                    salt,
                    device,
                    opaque_seen,
                    enrolled,
                    born: super::api::unix_now(),
                })));
            }
            None => return Err(Problem::TwoFactor(providers_of(&methods))),
        },
    };
    finish(api, attempt, master, export, params, salt, tokens, opaque_seen, enrolled)
}

/// The email's code, for a login that kept what it needed
pub fn finish_email(http: &mut dyn Http, server: &Server, pending: Pending, code: &str, bitwarden_device: Option<&str>) -> Result<Step, Problem> {
    const LIFE: i64 = 5 * 60;
    if super::api::unix_now() - pending.born > LIFE {
        return Err(Problem::LoginExpired);
    }
    let dpop = DpopKey::from_hex(&pending.dpop_hex).ok_or(Problem::BadResponse)?;
    let mut api = KemApi::new(http, server, &dpop);
    // The nonce is the server's to hand out again by the first refusal
    api.config()?;
    let tokens = api.second_step("email", &pending.challenge, code)?;
    let attempt = Attempt { server, email: "", password: "", confirmed: None, second: None, send_email: false, pinned: None, device_id: None, bitwarden_device, opaque_seen: pending.opaque_seen, dpop: &dpop };
    finish(&mut api, &attempt, pending.master.clone(), pending.export.clone(), pending.params, pending.salt.clone(), tokens, pending.opaque_seen, pending.enrolled)
}

#[allow(clippy::too_many_arguments)]
fn finish(api: &mut KemApi<'_>, attempt: &Attempt<'_>, master: Key, export: Secret<64>, params: KdfParams, salt: Vec<u8>, tokens: Tokens, opaque_seen: bool, enrolled: bool) -> Result<Step, Problem> {
    api.access = Some(tokens.access.clone());
    let keys = api.account_keys().map_err(|expired| match expired {
        Expired::Token => Problem::LoginExpired,
        Expired::Problem(problem) => problem,
    })?;
    let text = |name: &str| keys.get(name).and_then(Value::as_str).and_then(|text| b64_decode(text).ok()).ok_or(Problem::BadResponse);
    let key_version = keys.get("keyVersion").and_then(Value::as_u64).and_then(|v| u32::try_from(v).ok()).filter(|v| *v > 0).ok_or(Problem::BadResponse)?;
    let (wrapped, bundle, signature, sealed) = (text("wrappedRootKey")?, text("publicBundle")?, text("bundleSignature")?, text("sealedPrivateKeys")?);
    let account_id = Uuid::parse(&tokens.user_id).map_err(|_| Problem::BadResponse)?;
    let wrap = password_wrap_key(&master, export.as_bytes());
    let root = unwrap_root_key(&wrapped, &wrap, &account_id, key_version).map_err(|_| Problem::CannotOpen)?;
    let Account { .. } = account::open(&root, &account_id, key_version, &bundle, &signature, &sealed)?;
    let state = KemlockState {
        dpop_key: attempt.dpop.to_hex().to_string(),
        device_id: tokens.device_id.clone(),
        key_version,
        kdf_memory_kib: params.memory_kib,
        kdf_iterations: params.iterations,
        kdf_parallelism: params.parallelism,
        public_bundle: b64_encode(&bundle),
        bundle_signature: b64_encode(&signature),
        sealed_private_keys: b64_encode(&sealed),
        opaque_seen,
        bitwarden_device: attempt.bitwarden_device.map(str::to_string),
        ..KemlockState::default()
    };
    let _ = salt;
    Ok(Step::Connected(Box::new(Connected { state, root, tokens, enrolled, nonce: api.nonce.clone(), skew: api.skew })))
}

/// A Compatible account's first sign-in on this API (`spec-protocol.md` 2.4): the Bitwarden hash, once, makes its OPAQUE record and
/// its Kemlock keys, which are wrapped around the key the account already has. Then OPAQUE signs in as for any other.
fn enrol(api: &mut KemApi<'_>, attempt: &Attempt<'_>, derive: &Derive<'_>, bitwarden: &BitwardenDerive<'_>) -> Result<Step, Problem> {
    let wrong = || Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER);
    // Bitwarden's own prelogin on the same server, held to the same bounds
    let kdf = api::prelogin(&mut *api.http, attempt.server, attempt.email).map_err(|_| wrong())?;
    if kdf.check().map_err(Problem::Kdf)? && attempt.confirmed != Some(kdf.iterations) {
        return Err(Problem::KdfConfirm(kdf.iterations));
    }
    let password = attempt.password.as_bytes();
    let bw_master = bitwarden(password, attempt.email, &kdf).map_err(Problem::Kdf)?;
    let hash = crypto::master_hash(&bw_master, password);
    let stretched = crypto::stretch(&bw_master);
    let mut salt = [0u8; 16];
    crate::seal::random(&mut salt);
    let master = derive(attempt.password, &salt, &DEFAULT_PARAMS)?;
    let (registration, request) = opaque::registration_start(&master).map_err(|_| Problem::BadResponse)?;
    let start = api.bitwarden_start(attempt.email, &hash, &request)?;
    let two_factor = !start.two_factor.is_empty();
    if two_factor && !start.two_factor.iter().any(|method| method == "totp") {
        return Err(Problem::Kemlock(word::ENROL_NEEDS_TOTP));
    }
    let code = match (&attempt.second, two_factor) {
        (Some(second), true) if second.method == "totp" => Some(second.code),
        (_, true) => return Err(Problem::TwoFactor(vec![0])),
        _ => None,
    };
    // The account's own key, which is what every Kemlock key of it is made around
    let user = api::unwrap_user_key(&start.key, &stretched)?;
    let root = RootKey::from_slice(&user.bytes()[..]).ok_or(Problem::CannotOpen)?;
    let account_id = Uuid::parse(&start.user_id).map_err(|_| Problem::BadResponse)?;
    let registered = opaque::registration_finish(registration, &master, &start.response).map_err(|_| Problem::BadResponse)?;
    let private = PrivateKeys::generate();
    let bundle = crate::kemlock::bundle::Bundle { account_id, key_version: 1, kx1: private.kx1.public_key(), sig1: private.sig1.public_key() };
    let signature = bundle.sign(&private.sig1).map_err(|_| Problem::BadResponse)?;
    let sealed = private.seal(&user_key(&root), &account_id, 1);
    let wrapped = wrap_root_key(&root, &password_wrap_key(&master, registered.export_key.as_bytes()), &account_id, 1);
    let mut body = json!({
        "ticket": start.ticket,
        "upload": b64_encode(&registered.upload),
        "kdf": {"memoryKib": DEFAULT_PARAMS.memory_kib, "iterations": DEFAULT_PARAMS.iterations, "parallelism": DEFAULT_PARAMS.parallelism, "salt": b64_encode(&salt)},
        "publicBundle": b64_encode(&bundle.to_bytes()),
        "bundleSignature": b64_encode(&signature),
        "sealedPrivateKeys": b64_encode(&sealed),
        "wrappedRootKey": b64_encode(&wrapped),
    });
    if let Some(code) = code {
        body["twoFactorCode"] = json!(code);
    }
    api.bitwarden_finish(&body)?;
    if two_factor {
        // A code is used once, and the sign-in that follows asks for a second step again: the person gives the next
        return Err(Problem::TwoFactor(vec![0]));
    }
    let device = device_of(attempt);
    let Some((logged, signed)) = opaque_login(api, attempt.email, &master, &device)? else { return Err(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)) };
    with_signed(api, attempt, master, logged.export_key, DEFAULT_PARAMS, salt.to_vec(), device, signed, true, true)
}

/// A new access token from the refresh token, which is spent by it
pub fn refresh(api: &mut KemApi<'_>, refresh_token: &str) -> Result<Tokens, Problem> {
    api.refresh(refresh_token)
}
