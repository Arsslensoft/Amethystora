//! The Kemlock API's requests (`spec-protocol.md` sections 1 to 8): one place that signs every request with a DPoP proof, keeps
//! the server's nonce and clock, retries a nonce once, and reads an answer's problem. Each call below is one endpoint; what the
//! answers mean to a run is `engine.rs` and `signin.rs`.

use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::kemlock::conv::{b64_decode, b64_encode};
use crate::kemlock::item::WireItem;
use crate::sync::address::Server;
use crate::sync::api::{self, Expired, Http, Problem, Request};

use super::dpop::DpopKey;
use super::word;

const MOST_PAGE: usize = 32 * 1024 * 1024;
const MOST_PROBLEM: usize = 64 * 1024;
/// A sync page's size: small enough that a page of large items still fits the network service's answer
pub const PAGE_LIMIT: u32 = 100;
/// `spec-protocol.md` 5.2: a cursor this long travels in a POST's body, not a URL
const LONG_CURSOR: usize = 1500;

/// An answer as it came: the status, the body, the few headers the network service passes on, and a problem's slug
pub struct Answer {
    pub status: u16,
    pub body: Zeroizing<Vec<u8>>,
    pub headers: Vec<(String, String)>,
    /// `urn:kemlock:problem:<slug>`'s slug, on an `application/problem+json` body
    pub slug: Option<String>,
}

impl Answer {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.iter().find(|(key, _)| key == name).map(|(_, value)| value.as_str())
    }

    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }

    /// The body as JSON
    pub fn json(&self) -> Result<Value, Problem> {
        if self.body.len() > MOST_PAGE {
            return Err(Problem::BadResponse);
        }
        serde_json::from_slice(&self.body).map_err(|_| Problem::BadResponse)
    }

    fn problem_field(&self, name: &str) -> Option<Value> {
        self.slug.as_ref()?;
        serde_json::from_slice::<Value>(&self.body).ok()?.get(name).cloned()
    }

    /// `currentRevision` of a `stale-revision`
    pub fn current_revision(&self) -> Option<u64> {
        self.problem_field("currentRevision")?.as_u64()
    }

    pub fn item_id(&self) -> Option<String> {
        self.problem_field("itemId")?.as_str().map(str::to_string)
    }

    pub fn current_counter(&self) -> Option<u64> {
        self.problem_field("currentCounter")?.as_u64()
    }

    pub fn max_size(&self) -> Option<u64> {
        self.problem_field("maxSize")?.as_u64()
    }

    /// What this answer is, as a problem, when it is a refusal: the server's own words only ever shown as data
    pub fn problem(&self) -> Problem {
        let slug = self.slug.as_deref().unwrap_or("");
        match (self.status, slug) {
            (401, "session-ended") => Problem::Kemlock(word::SESSION_ENDED),
            (401, "use-dpop-nonce") => Problem::Kemlock(word::DPOP_NONCE),
            (401, "invalid-dpop-proof") => Problem::Kemlock(word::DPOP_REFUSED),
            (401, _) => Problem::LoginExpired,
            (403, "sso-required") => Problem::Kemlock(word::SSO_ONLY),
            (403, _) => Problem::Kemlock(word::ACCOUNT_REFUSED),
            (429, _) => Problem::RateLimited,
            (500..=599, _) => Problem::ServerDown,
            _ => {
                let detail = self.problem_field("detail").and_then(|detail| detail.as_str().map(api::clean));
                match (slug, detail) {
                    ("", None) => Problem::ServerRefused,
                    (slug, detail) => Problem::ServerSaid(detail.unwrap_or_else(|| api::clean(slug))),
                }
            }
        }
    }

    /// The token ran out, or never was one, as opposed to a proof or a session the server refused
    pub fn token_refused(&self) -> bool {
        self.status == 401 && !matches!(self.slug.as_deref(), Some("session-ended" | "use-dpop-nonce" | "invalid-dpop-proof"))
    }
}

/// How a request is signed
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// No proof at all: `config`, `prelogin`, `methods`, registration
    Open,
    /// A proof without a token: every sign-in step and the refresh
    Proof,
    /// `Authorization: DPoP <token>` and a proof that names the token
    Token,
}

pub struct KemApi<'a> {
    pub http: &'a mut dyn Http,
    /// `<address>/kem/v1`
    pub base: String,
    pub key: &'a DpopKey,
    /// The server's last `DPoP-Nonce`
    pub nonce: Option<String>,
    /// Seconds to add to this machine's clock for a proof's `iat`: what the server's `Date` said ours was off by
    pub skew: i64,
    pub access: Option<Zeroizing<String>>,
}

/// `<address>/kem/v1`
pub fn base_of(server: &Server) -> String {
    format!("{}/kem/v1", server.address)
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

/// An HTTP date (`Tue, 25 Nov 2026 10:00:00 GMT`) as Unix seconds
pub fn parse_http_date(text: &str) -> Option<i64> {
    let (_, rest) = text.split_once(", ")?;
    let mut parts = rest.split(' ');
    let day: i64 = parts.next()?.parse().ok()?;
    let name = parts.next()?;
    let month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|m| *m == name)? as i64 + 1;
    let year: i64 = parts.next()?.parse().ok()?;
    let mut clock = parts.next()?.split(':');
    let (h, m, s): (i64, i64, i64) = (clock.next()?.parse().ok()?, clock.next()?.parse().ok()?, clock.next()?.parse().ok()?);
    if parts.next()? != "GMT" || !(1..=31).contains(&day) || h > 23 || m > 59 || s > 60 {
        return None;
    }
    // Days from civil (Howard Hinnant's algorithm)
    let y = if month <= 2 { year - 1 } else { year };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let doy = (153 * (if month > 2 { month - 3 } else { month + 9 }) + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + h * 3600 + m * 60 + s)
}

impl<'a> KemApi<'a> {
    pub fn new(http: &'a mut dyn Http, server: &Server, key: &'a DpopKey) -> KemApi<'a> {
        KemApi { http, base: base_of(server), key, nonce: None, skew: 0, access: None }
    }

    /// One request, signed as `mode` says. A refused nonce is tried again once with the one the server gave; nothing else is
    /// retried, and a 5xx or a 429 is a problem of its own.
    pub fn send(&mut self, method: &'static str, path: &str, body: Option<Vec<u8>>, content_type: &'static str, mode: Mode, extra: &[(&'static str, String)]) -> Result<Answer, Problem> {
        let url = format!("{}{}", self.base, path);
        let mut retried = false;
        let mut clock_retried = false;
        loop {
            let skew_then = self.skew;
            let mut headers: Vec<(&'static str, String)> = vec![("Accept", "application/json".to_string()), ("User-Agent", crate::sync::USER_AGENT.to_string())];
            let token = if mode == Mode::Token { self.access.as_ref().map(|token| token.as_str().to_string()) } else { None };
            if mode != Mode::Open {
                let proof = self.key.proof(method, &url, token.as_deref(), self.nonce.as_deref(), unix_now() + self.skew);
                headers.push(("DPoP", proof));
            }
            if let Some(token) = &token {
                headers.push(("Authorization", format!("DPoP {token}")));
            }
            if body.is_some() {
                headers.push(("Content-Type", content_type.to_string()));
            }
            headers.extend(extra.iter().cloned());
            let request = Request { method, url: url.clone(), headers, body: Zeroizing::new(body.clone().unwrap_or_default()) };
            let response = self.http.call(request).map_err(Problem::Net)?;
            let headers: Vec<(String, String)> = response.headers;
            if let Some((_, nonce)) = headers.iter().find(|(name, _)| name == "dpop-nonce")
                && !nonce.is_empty()
                && nonce.len() <= 256
            {
                self.nonce = Some(nonce.clone());
            }
            if let Some(date) = headers.iter().find(|(name, _)| name == "date").and_then(|(_, value)| parse_http_date(value)) {
                let off = date - unix_now();
                if off.abs() > 60 {
                    self.skew = off;
                }
            }
            let slug = if response.status >= 400 && response.body.len() <= MOST_PROBLEM {
                serde_json::from_slice::<Value>(&response.body).ok().and_then(|problem| problem.get("type")?.as_str()?.strip_prefix("urn:kemlock:problem:").map(str::to_string))
            } else {
                None
            };
            let answer = Answer { status: response.status, body: response.body, headers, slug };
            if answer.status == 401 && answer.slug.as_deref() == Some("use-dpop-nonce") {
                if retried || self.nonce.is_none() {
                    return Err(Problem::Kemlock(word::DPOP_NONCE));
                }
                retried = true;
                continue;
            }
            if answer.status == 401 && answer.slug.as_deref() == Some("invalid-dpop-proof") {
                // The answer's Date just taught the clock that was off: the same request once more, under a proof made for the right time
                if !clock_retried && self.skew != skew_then {
                    clock_retried = true;
                    continue;
                }
                // The clock, or the address the server was set up under: never read as a wrong password, a wrong code or an expired login
                return Err(Problem::Kemlock(word::DPOP_REFUSED));
            }
            if answer.status >= 500 || answer.status == 429 {
                return Err(answer.problem());
            }
            return Ok(answer);
        }
    }

    fn json_post(&mut self, path: &str, body: &Value, mode: Mode) -> Result<Answer, Problem> {
        self.send("POST", path, Some(serde_json::to_vec(body).map_err(|_| Problem::BadResponse)?), "application/json", mode, &[])
    }

    // --- Before signing in ------------------------------------------------------------------------------------------------

    pub fn config(&mut self) -> Result<Answer, Problem> {
        self.send("GET", "/config", None, "", Mode::Open, &[])
    }

    pub fn prelogin(&mut self, email: &str) -> Result<Value, Problem> {
        let answer = self.json_post("/auth/prelogin", &json!({"email": email}), Mode::Open)?;
        if !answer.ok() {
            return Err(answer.problem());
        }
        answer.json()
    }

    pub fn methods(&mut self, email: &str) -> Result<Value, Problem> {
        let answer = self.json_post("/auth/methods", &json!({"email": email}), Mode::Open)?;
        if !answer.ok() {
            return Err(answer.problem());
        }
        answer.json()
    }

    // --- Signing in -------------------------------------------------------------------------------------------------------

    /// OPAQUE's first round: the server's KE2 and the sealed login state
    pub fn opaque_start(&mut self, email: &str, request: &[u8]) -> Result<(Vec<u8>, String), Problem> {
        let answer = self.json_post("/auth/opaque/start", &json!({"email": email, "request": b64_encode(request)}), Mode::Proof)?;
        if !answer.ok() {
            return Err(answer.problem());
        }
        let body = answer.json()?;
        let response = body.get("response").and_then(Value::as_str).and_then(|text| b64_decode(text).ok()).ok_or(Problem::BadResponse)?;
        let state = body.get("loginState").and_then(Value::as_str).filter(|state| state.len() <= 4096).ok_or(Problem::BadResponse)?.to_string();
        Ok((response, state))
    }

    pub fn opaque_finish(&mut self, email: &str, login_state: &str, finalization: &[u8], device: &Value) -> Result<SignedIn, Problem> {
        let body = json!({"email": email, "loginState": login_state, "finalization": b64_encode(finalization), "device": device});
        let answer = self.json_post("/auth/opaque/finish", &body, Mode::Proof)?;
        if answer.status == 401 {
            // A wrong password at this step: the server checked KE3
            return Err(Problem::CannotOpen);
        }
        if !answer.ok() {
            return Err(answer.problem());
        }
        signed_in(&answer.json()?)
    }

    /// A second step with a code: `method` is `totp`, `email` (after `email_send`) or `recovery`
    pub fn second_step(&mut self, method: &str, challenge: &str, code: &str) -> Result<Tokens, Problem> {
        let (path, body) = match method {
            "totp" => ("/auth/two-factor", json!({"challenge": challenge, "method": "totp", "code": code})),
            "email" => ("/auth/two-factor/email", json!({"challenge": challenge, "code": code})),
            "recovery" => ("/auth/two-factor/recovery", json!({"challenge": challenge, "code": code})),
            _ => return Err(Problem::Unsupported),
        };
        let answer = self.json_post(path, &body, Mode::Proof)?;
        if answer.status == 401 || answer.status == 400 {
            return Err(Problem::Kemlock(word::SECOND_STEP_REFUSED));
        }
        if !answer.ok() {
            return Err(answer.problem());
        }
        tokens(&answer.json()?)
    }

    pub fn email_send(&mut self, challenge: &str) -> Result<(), Problem> {
        let answer = self.json_post("/auth/two-factor/email/send", &json!({"challenge": challenge}), Mode::Proof)?;
        if answer.ok() { Ok(()) } else { Err(answer.problem()) }
    }

    /// The Compatible account's one-time enrolment, its first call: the Bitwarden user key as the Bitwarden API keeps it, OPAQUE's
    /// registration response and a ticket
    pub fn bitwarden_start(&mut self, email: &str, hash: &str, request: &[u8]) -> Result<BitwardenStart, Problem> {
        let answer = self.json_post("/auth/bitwarden/start", &json!({"email": email, "masterPasswordHash": hash, "request": b64_encode(request)}), Mode::Proof)?;
        if matches!(answer.status, 401 | 409) {
            return Err(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER));
        }
        if !answer.ok() {
            return Err(answer.problem());
        }
        let body = answer.json()?;
        let text = |name: &str| body.get(name).and_then(Value::as_str);
        Ok(BitwardenStart {
            user_id: text("userId").filter(|id| api::is_uuid(id)).ok_or(Problem::BadResponse)?.to_string(),
            key: text("key").ok_or(Problem::BadResponse)?.to_string(),
            response: text("response").and_then(|text| b64_decode(text).ok()).ok_or(Problem::BadResponse)?,
            ticket: text("ticket").filter(|ticket| ticket.len() <= 4096).ok_or(Problem::BadResponse)?.to_string(),
            two_factor: body.get("twoFactor").and_then(Value::as_array).into_iter().flatten().filter_map(|m| m.as_str().map(str::to_string)).collect(),
        })
    }

    pub fn bitwarden_finish(&mut self, body: &Value) -> Result<(), Problem> {
        let answer = self.json_post("/auth/bitwarden/finish", body, Mode::Proof)?;
        if answer.status == 401 {
            return Err(Problem::Kemlock(word::SECOND_STEP_REFUSED));
        }
        if answer.ok() { Ok(()) } else { Err(answer.problem()) }
    }

    /// A new token pair for a refresh token, which is spent by it
    pub fn refresh(&mut self, refresh_token: &str) -> Result<Tokens, Problem> {
        let answer = self.json_post("/auth/token", &json!({"grantType": "refresh_token", "refreshToken": refresh_token}), Mode::Proof)?;
        if answer.status == 401 && answer.slug.as_deref() != Some("session-ended") {
            return Err(Problem::LoginExpired);
        }
        if !answer.ok() {
            return Err(answer.problem());
        }
        tokens(&answer.json()?)
    }

    pub fn account_keys(&mut self) -> Result<Value, Expired> {
        let answer = self.authed("GET", "/account/keys", None)?;
        if !answer.ok() {
            return Err(Expired::Problem(answer.problem()));
        }
        answer.json().map_err(Expired::Problem)
    }

    pub fn sign_out(&mut self, device: &str) -> Result<(), Expired> {
        let answer = self.authed("POST", "/devices/sign-out", Some(serde_json::to_vec(&json!({"deviceId": device})).unwrap_or_default()))?;
        if answer.ok() || answer.status == 404 { Ok(()) } else { Err(Expired::Problem(answer.problem())) }
    }

    pub fn devices(&mut self) -> Result<Value, Expired> {
        let answer = self.authed("GET", "/devices", None)?;
        if !answer.ok() {
            return Err(Expired::Problem(answer.problem()));
        }
        answer.json().map_err(Expired::Problem)
    }

    // --- Signed in --------------------------------------------------------------------------------------------------------

    /// A call with the token: `Expired::Token` when the server says the token is not good, for the caller to refresh and try again
    pub fn authed(&mut self, method: &'static str, path: &str, body: Option<Vec<u8>>) -> Result<Answer, Expired> {
        self.authed_with(method, path, body, "application/json", &[])
    }

    pub fn authed_with(&mut self, method: &'static str, path: &str, body: Option<Vec<u8>>, content_type: &'static str, extra: &[(&'static str, String)]) -> Result<Answer, Expired> {
        let answer = self.send(method, path, body, content_type, Mode::Token, extra)?;
        if answer.token_refused() {
            return Err(Expired::Token);
        }
        Ok(answer)
    }

    /// One page of changes since a cursor. `None` is a 304: nothing since. `Err(FullSync)` is a 410.
    pub fn sync(&mut self, since: Option<&str>) -> Result<Result<Option<Page>, FullSync>, Expired> {
        let answer = match since {
            Some(cursor) if cursor.len() > LONG_CURSOR => self.authed("POST", "/sync", Some(serde_json::to_vec(&json!({"since": cursor, "limit": PAGE_LIMIT})).unwrap_or_default()))?,
            Some(cursor) => self.authed("GET", &format!("/sync?since={}&limit={PAGE_LIMIT}", query(cursor)), None)?,
            None => self.authed("GET", &format!("/sync?limit={PAGE_LIMIT}"), None)?,
        };
        match answer.status {
            304 => return Ok(Ok(None)),
            410 => return Ok(Err(FullSync)),
            _ if !answer.ok() => return Err(Expired::Problem(answer.problem())),
            _ => {}
        }
        let body = answer.json().map_err(Expired::Problem)?;
        page(&body).map(|page| Ok(Some(page))).ok_or(Expired::Problem(Problem::BadResponse))
    }

    /// A batch of writes, all or none. `Ok(Err(refused))` names the write the server refused.
    pub fn batch(&mut self, writes: &[(Option<u64>, &WireItem)]) -> Result<Result<Vec<Value>, Refused>, Expired> {
        let writes: Vec<Value> = writes.iter().map(|(expected, item)| json!({"expectedRevision": expected, "item": item})).collect();
        let body = serde_json::to_vec(&json!({"writes": writes})).map_err(|_| Expired::Problem(Problem::BadResponse))?;
        let answer = self.authed("POST", "/items:batch", Some(body))?;
        refusal_or(&answer, |answer| {
            let body = answer.json()?;
            body.get("items").and_then(Value::as_array).cloned().ok_or(Problem::BadResponse)
        })
    }

    pub fn manifest(&mut self, owner: &str) -> Result<Option<Value>, Expired> {
        let answer = self.authed("GET", &format!("/manifests/{}", query(owner)), None)?;
        if answer.status == 404 {
            return Ok(None);
        }
        if !answer.ok() {
            return Err(Expired::Problem(answer.problem()));
        }
        answer.json().map(Some).map_err(Expired::Problem)
    }

    /// Stores a signed manifest: `Ok(Err(counter))` when another device signed first, with the counter it holds
    pub fn put_manifest(&mut self, owner: &str, manifest: &[u8], signature: &[u8]) -> Result<Result<(), Option<u64>>, Expired> {
        let body = serde_json::to_vec(&json!({"manifest": b64_encode(manifest), "signature": b64_encode(signature)})).map_err(|_| Expired::Problem(Problem::BadResponse))?;
        let answer = self.authed("PUT", &format!("/manifests/{}", query(owner)), Some(body))?;
        if answer.status == 409 && answer.slug.as_deref() == Some("stale-manifest") {
            return Ok(Err(answer.current_counter()));
        }
        if answer.ok() { Ok(Ok(())) } else { Err(Expired::Problem(answer.problem())) }
    }

    // --- Files ------------------------------------------------------------------------------------------------------------

    /// Opens a file for an item: its id, and the server's limit
    pub fn file_start(&mut self, item: &str, size: u64) -> Result<Result<FileSlot, FileRefusal>, Expired> {
        let answer = self.authed("POST", &format!("/items/{item}/files"), Some(serde_json::to_vec(&json!({"size": size})).unwrap_or_default()))?;
        match answer.status {
            413 => return Ok(Err(FileRefusal::TooBig(answer.max_size()))),
            403 => return Ok(Err(FileRefusal::NotAllowed)),
            _ if !answer.ok() => return Err(Expired::Problem(answer.problem())),
            _ => {}
        }
        let body = answer.json().map_err(Expired::Problem)?;
        let file = body.get("fileId").and_then(Value::as_str).filter(|id| api::is_uuid(id)).ok_or(Expired::Problem(Problem::BadResponse))?.to_string();
        let presigned = body.get("presigned").and_then(Value::as_bool).unwrap_or(false);
        Ok(Ok(FileSlot { file, presigned, max_size: body.get("maxSize").and_then(Value::as_u64) }))
    }

    pub fn file_upload(&mut self, item: &str, file: &str, bytes: Vec<u8>) -> Result<Result<(), FileRefusal>, Expired> {
        let answer = self.authed_with("PUT", &format!("/items/{item}/files/{file}"), Some(bytes), "application/octet-stream", &[])?;
        match answer.status {
            413 => Ok(Err(FileRefusal::TooBig(answer.max_size()))),
            409 | 415 | 400 => Ok(Err(FileRefusal::Refused)),
            _ if answer.ok() => Ok(Ok(())),
            _ => Err(Expired::Problem(answer.problem())),
        }
    }

    /// A file's bytes, at most `most`: more than that is not the file
    pub fn file_download(&mut self, item: &str, file: &str, most: usize) -> Result<Option<Zeroizing<Vec<u8>>>, Expired> {
        let answer = self.authed_with("GET", &format!("/items/{item}/files/{file}"), None, "", &[("Accept", "application/octet-stream".to_string())])?;
        if answer.status == 404 {
            return Ok(None);
        }
        if !answer.ok() {
            return Err(Expired::Problem(answer.problem()));
        }
        if answer.body.len() > most {
            return Ok(None);
        }
        Ok(Some(answer.body))
    }

    pub fn file_delete(&mut self, item: &str, file: &str) -> Result<(), Expired> {
        let answer = self.authed("DELETE", &format!("/items/{item}/files/{file}"), None)?;
        if answer.ok() || answer.status == 404 { Ok(()) } else { Err(Expired::Problem(answer.problem())) }
    }
}

/// A value in a query: what is not plain is escaped
fn query(text: &str) -> String {
    text.bytes().map(|b| if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~' | b':') { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

/// `410 full-sync-required`
pub struct FullSync;

/// What the server refused a write for
#[derive(Debug, PartialEq, Eq)]
pub enum Refused {
    /// 409 `stale-revision`: the item and the revision it holds (none when the item is not there)
    Stale { item: Option<String>, current: Option<u64> },
    /// 422 `invalid-revision`, `invalid-item` and the like: a bug here, or an id that is another kind's
    Invalid(String),
    TooLarge,
}

fn refusal_or<T>(answer: &Answer, ok: impl FnOnce(&Answer) -> Result<T, Problem>) -> Result<Result<T, Refused>, Expired> {
    match (answer.status, answer.slug.as_deref()) {
        (409, Some("stale-revision")) => Ok(Err(Refused::Stale { item: answer.item_id(), current: answer.current_revision() })),
        (409, Some("already-exists")) | (422, _) | (400, Some("invalid-item" | "invalid-request")) => Ok(Err(Refused::Invalid(answer.slug.clone().unwrap_or_default()))),
        (413, _) => Ok(Err(Refused::TooLarge)),
        _ if answer.ok() => ok(answer).map(Ok).map_err(Expired::Problem),
        _ => Err(Expired::Problem(answer.problem())),
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum FileRefusal {
    /// 413: the server's limit, if it said
    TooBig(Option<u64>),
    /// The server keeps its files in a bucket, which the Vault does not use
    Bucket,
    /// 403: the account's file storage is off or spent
    NotAllowed,
    Refused,
}

pub struct FileSlot {
    pub file: String,
    pub presigned: bool,
    pub max_size: Option<u64>,
}

/// A token pair and who it is for
pub struct Tokens {
    pub access: Zeroizing<String>,
    pub refresh: Zeroizing<String>,
    pub expires_in: i64,
    pub user_id: String,
    pub device_id: String,
}

pub enum SignedIn {
    Tokens(Tokens),
    /// A second step is owed: the challenge, and the methods the account has
    SecondStep { challenge: String, methods: Vec<String> },
}

pub struct BitwardenStart {
    pub user_id: String,
    pub key: String,
    pub response: Vec<u8>,
    pub ticket: String,
    pub two_factor: Vec<String>,
}

fn tokens(body: &Value) -> Result<Tokens, Problem> {
    let text = |name: &str| body.get(name).and_then(Value::as_str);
    if text("tokenType") != Some("DPoP") {
        return Err(Problem::BadResponse);
    }
    let expires_in = body.get("expiresIn").and_then(Value::as_i64).filter(|seconds| (1..=24 * 3600).contains(seconds)).ok_or(Problem::BadResponse)?;
    Ok(Tokens {
        access: Zeroizing::new(text("accessToken").filter(|token| !token.is_empty() && token.len() <= 8192).ok_or(Problem::BadResponse)?.to_string()),
        refresh: Zeroizing::new(text("refreshToken").filter(|token| !token.is_empty() && token.len() <= 8192).ok_or(Problem::BadResponse)?.to_string()),
        expires_in,
        user_id: text("userId").filter(|id| api::is_uuid(id)).ok_or(Problem::BadResponse)?.to_string(),
        device_id: text("deviceId").filter(|id| api::is_uuid(id)).ok_or(Problem::BadResponse)?.to_string(),
    })
}

fn signed_in(body: &Value) -> Result<SignedIn, Problem> {
    match body.get("status").and_then(Value::as_str) {
        Some("signed_in") => Ok(SignedIn::Tokens(tokens(body.get("tokens").ok_or(Problem::BadResponse)?)?)),
        Some("two_factor_required") => {
            let challenge = body.get("challenge").and_then(Value::as_str).filter(|c| !c.is_empty() && c.len() <= 4096).ok_or(Problem::BadResponse)?.to_string();
            let methods = body.get("methods").and_then(Value::as_array).into_iter().flatten().filter_map(|m| m.as_str().map(str::to_string)).collect();
            Ok(SignedIn::SecondStep { challenge, methods })
        }
        _ => Err(Problem::BadResponse),
    }
}

/// One page of a sync, read for what it must be: leniently in what members an item has, strictly in what it is
pub struct Page {
    pub items: Vec<WireItem>,
    pub cursor: String,
    pub more: bool,
    /// Items a federated server holds two versions of: left to the Kemlock app
    pub siblings: usize,
}

fn page(body: &Value) -> Option<Page> {
    let items = body.get("items")?.as_array()?;
    if items.len() > 500 {
        return None;
    }
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        out.push(wire_item(item)?);
    }
    Some(Page {
        items: out,
        cursor: body.get("cursor")?.as_str().filter(|c| !c.is_empty() && c.len() <= 64 * 1024)?.to_string(),
        more: body.get("more").and_then(Value::as_bool).unwrap_or(false),
        siblings: body.get("siblings").and_then(Value::as_array).map_or(0, Vec::len),
    })
}

/// An item as an answer gives it: a member this client does not know is ignored (the request side is strict, not this one)
pub fn wire_item(value: &Value) -> Option<WireItem> {
    let text = |name: &str| value.get(name).and_then(Value::as_str).map(str::to_string);
    Some(WireItem {
        id: text("id")?,
        owner: text("owner")?,
        kind: text("kind")?,
        format: text("format")?,
        revision: value.get("revision")?.as_u64()?,
        key_version: u32::try_from(value.get("keyVersion").and_then(Value::as_u64).unwrap_or(0)).ok()?,
        ciphertext: text("ciphertext"),
        item_key: text("itemKey"),
        deleted: value.get("deleted")?.as_bool()?,
        collection_id: text("collectionId"),
        deleted_at: text("deletedAt"),
        held: value.get("held").and_then(Value::as_bool),
    })
}

/// What `GET /kem/v1/config` says, held to what a client needs (`spec-protocol.md` 1.3)
#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub version: String,
    pub domain: String,
    pub features: Vec<String>,
}

impl ServerConfig {
    pub fn has(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
    }
}

/// The server is a Kemlock Server when, and only when, its own config says so: the answer is 200, JSON, `server` is
/// `kemlock-server` and `apiVersions` holds `v1`. Anything else is not one, which keeps the Bitwarden back end.
pub fn read_config(answer: &Answer) -> Option<ServerConfig> {
    if answer.status != 200 || answer.body.len() > 512 * 1024 {
        return None;
    }
    let body: Value = serde_json::from_slice(&answer.body).ok()?;
    if body.get("server")?.as_str()? != "kemlock-server" || !body.get("apiVersions")?.as_array()?.iter().any(|v| v.as_str() == Some("v1")) {
        return None;
    }
    Some(ServerConfig {
        version: body.get("version").and_then(Value::as_str).unwrap_or("").chars().take(64).collect(),
        domain: body.get("domain").and_then(Value::as_str).unwrap_or("").chars().take(300).collect(),
        features: body.get("features").and_then(Value::as_array).into_iter().flatten().filter_map(|f| f.as_str().map(str::to_string)).take(64).collect(),
    })
}

/// Whether the address the person typed and the `domain` the server says it is set up under are one address: DPoP's `htu` is
/// checked against the second, so a difference makes every proof fail
pub fn same_domain(typed: &str, domain: &str) -> bool {
    super::dpop::htu(typed.trim_end_matches('/')).trim_end_matches('/') == super::dpop::htu(domain.trim_end_matches('/')).trim_end_matches('/')
}

/// Asked of the Bitwarden API's config: the hint that `/kem/v1` exists. Only a hint; the answer of `/kem/v1/config` decides.
pub fn hints_kemlock(config: &Value) -> bool {
    config.get("kemlock").and_then(|kemlock| kemlock.get("versions")).and_then(Value::as_array).is_some_and(|versions| versions.iter().any(|v| v.as_str() == Some("v1")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_http_date_is_seconds() {
        assert_eq!(parse_http_date("Thu, 01 Jan 1970 00:00:00 GMT"), Some(0));
        assert_eq!(parse_http_date("Tue, 25 Nov 2025 10:00:00 GMT"), Some(1_764_064_800));
        assert_eq!(parse_http_date("Tue, 25 Nov 2025 10:00:00 UTC"), None);
        assert_eq!(parse_http_date("garbage"), None);
    }

    #[test]
    fn a_domain_is_the_address_when_they_normalise_alike() {
        assert!(same_domain("https://Vault.test:443/", "https://vault.test"));
        assert!(same_domain("http://127.0.0.1:18299", "http://127.0.0.1:18299/"));
        assert!(!same_domain("http://localhost:18299", "http://127.0.0.1:18299"));
        assert!(!same_domain("https://vault.test/x", "https://vault.test"));
    }

    #[test]
    fn the_bitwarden_configs_hint_is_only_a_hint() {
        assert!(hints_kemlock(&json!({"kemlock": {"api": "https://x/kem/v1", "versions": ["v1"]}})));
        assert!(!hints_kemlock(&json!({"server": {"name": "Vaultwarden"}})));
        assert!(!hints_kemlock(&json!({"kemlock": {"versions": ["v2"]}})));
    }

    fn answer(status: u16, body: Value) -> Answer {
        let slug = body.get("type").and_then(Value::as_str).and_then(|t| t.strip_prefix("urn:kemlock:problem:")).map(str::to_string);
        Answer { status, body: Zeroizing::new(serde_json::to_vec(&body).unwrap()), headers: Vec::new(), slug }
    }

    #[test]
    fn a_config_is_a_kemlock_server_only_by_its_own_words() {
        let ok = answer(200, json!({"server": "kemlock-server", "apiVersions": ["v1"], "version": "0.1.2", "domain": "http://x", "features": ["opaque", "dpop", "sync"]}));
        let config = read_config(&ok).unwrap();
        assert!(config.has("dpop") && !config.has("manifest"));
        assert!(read_config(&answer(200, json!({"server": "Vaultwarden", "apiVersions": ["v1"]}))).is_none());
        assert!(read_config(&answer(200, json!({"server": "kemlock-server", "apiVersions": ["v2"]}))).is_none());
        assert!(read_config(&answer(404, json!({}))).is_none());
    }

    #[test]
    fn a_refusal_is_a_problem_by_its_slug() {
        let problem = |status, slug: &str| answer(status, json!({"type": format!("urn:kemlock:problem:{slug}"), "status": status})).problem();
        assert_eq!(problem(401, "session-ended"), Problem::Kemlock(word::SESSION_ENDED));
        assert_eq!(problem(401, "invalid-dpop-proof"), Problem::Kemlock(word::DPOP_REFUSED));
        assert_eq!(problem(403, "sso-required"), Problem::Kemlock(word::SSO_ONLY));
        assert_eq!(problem(429, "rate-limited"), Problem::RateLimited);
        assert_eq!(problem(503, "overloaded"), Problem::ServerDown);
        assert!(answer(401, json!({"type": "urn:kemlock:problem:unauthorized"})).token_refused());
        assert!(!answer(401, json!({"type": "urn:kemlock:problem:session-ended"})).token_refused());
    }

    #[test]
    fn a_stale_revision_names_the_item_and_the_revision() {
        let stale = answer(409, json!({"type": "urn:kemlock:problem:stale-revision", "itemId": "i", "currentRevision": 4}));
        assert_eq!((stale.item_id().as_deref(), stale.current_revision()), (Some("i"), Some(4)));
    }

    #[test]
    fn an_item_with_members_this_client_does_not_know_is_read_all_the_same() {
        let item = wire_item(&json!({"id": "a", "owner": "user:x", "kind": "login", "format": "kem1", "revision": 2, "keyVersion": 1, "deleted": false, "ciphertext": "AA", "itemKey": "BB", "tags": ["x"], "tagVersion": 3})).unwrap();
        assert_eq!((item.revision, item.kind.as_str()), (2, "login"));
        // `deleted` is always there; without it the item is not one
        assert!(wire_item(&json!({"id": "a", "owner": "user:x", "kind": "login", "format": "kem1", "revision": 2})).is_none());
    }
}
