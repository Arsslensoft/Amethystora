//! What each of the Vault's items becomes as a Kemlock item, and back (`spec-items.md` 1 to 4): a password is a `login`, an
//! authenticator account an `otp`, backup codes a `backup-codes`, a key an `ssh-key` or a `key` (an AES key a `note`), a
//! certificate a `certificate`, and a protected file or folder a `note` with one attachment.
//!
//! A write starts from the last plaintext the server had (`base`), sets the keys the Vault maps and touches nothing else, so that
//! what the Kemlock app or the web vault keeps in an item (a login's `pinned`, a key's `note`) is never lost by an edit here, and
//! what the Vault adds (`amethystora`) is a key the app keeps as unknown. A read takes only the keys it maps. Nothing here knows
//! a server: a plaintext goes in, a plaintext comes out.

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde_json::{Map, Value, json};
use zeroize::Zeroizing;

use crate::items::{Account, BackupService, KIND_ACCOUNT, KIND_BACKUP_CODES, KIND_PASSWORD, OldPassword, Password, Secret};
use crate::sync::convert::Convert;
use crate::sync::map::{self, Local, Unmapped};
use crate::sync::plain;

use super::kind;

/// The most previous passwords a login keeps, as the Vault does
const MOST_HISTORY: usize = 5;

/// A file that goes with a note: its bytes, and what the note's attachment says of it
pub struct FileOut {
    pub name: String,
    pub media: Option<&'static str>,
    pub bytes: Zeroizing<Vec<u8>>,
    pub sha256: String,
}

/// An item as a Kemlock plaintext, and the file that goes with it
pub struct Mapped {
    /// The item's kind on the server: it never changes once the item is there
    pub kind: &'static str,
    pub plain: Value,
    pub file: Option<FileOut>,
}

fn s(value: &Value, name: &str) -> Option<String> {
    value.get(name).and_then(Value::as_str).map(str::to_string)
}

fn set_or_remove(object: &mut Map<String, Value>, name: &str, value: Option<Value>) {
    match value {
        Some(value) => {
            object.insert(name.to_string(), value);
        }
        None => {
            object.remove(name);
        }
    }
}

/// The kind a vault item is on the Kemlock API, if it is one that goes: passwords, codes, backup codes, keys, certificates, files
pub fn kem_kind_for(local: &Local) -> Option<&'static str> {
    match local.kind.as_str() {
        KIND_PASSWORD => Some(kind::LOGIN),
        KIND_ACCOUNT => Some(kind::OTP),
        KIND_BACKUP_CODES => Some(kind::BACKUP_CODES),
        crate::protocol::KIND_KEY => match (local.value["type"].as_str()?, local.value["key_kind"].as_str()) {
            ("aes-256", _) => Some(kind::NOTE),
            (_, Some("ssh")) if ssh_form(local.value["type"].as_str()?) => Some(kind::SSH_KEY),
            _ => Some(kind::KEY),
        },
        crate::protocol::KIND_CERTIFICATE => Some(kind::CERTIFICATE),
        "protected" => Some(kind::NOTE),
        _ => None,
    }
}

fn ssh_form(key_type: &str) -> bool {
    matches!(key_type, "ed25519" | "ecdsa-p256" | "ecdsa-p384" | "rsa-3072" | "rsa-4096" | "rsa")
}

// --- Hosts -------------------------------------------------------------------------------------------------------------------

/// RFC 3492's encoder, for a label with letters outside ASCII
fn punycode(label: &str) -> Option<String> {
    const BASE: u32 = 36;
    let input: Vec<u32> = label.chars().map(|c| c as u32).collect();
    let mut out: String = label.chars().filter(char::is_ascii).collect();
    let basic = out.len() as u32;
    let mut handled = basic;
    if basic > 0 {
        out.push('-');
    }
    let (mut n, mut delta, mut bias) = (128u32, 0u32, 72u32);
    let digit = |d: u32| (if d < 26 { b'a' + d as u8 } else { b'0' + (d - 26) as u8 }) as char;
    let adapt = |mut delta: u32, points: u32, first: bool| {
        delta = if first { delta / 700 } else { delta / 2 };
        delta += delta / points;
        let mut k = 0;
        while delta > 455 {
            delta /= 35;
            k += BASE;
        }
        k + 36 * delta / (delta + 38)
    };
    while (handled as usize) < input.len() {
        let m = input.iter().copied().filter(|c| *c >= n).min()?;
        delta = delta.checked_add((m - n).checked_mul(handled + 1)?)?;
        n = m;
        for &c in &input {
            if c < n {
                delta = delta.checked_add(1)?;
            }
            if c == n {
                let mut q = delta;
                let mut k = BASE;
                loop {
                    let t = if k <= bias { 1 } else if k >= bias + 26 { 26 } else { k - bias };
                    if q < t {
                        break;
                    }
                    out.push(digit(t + (q - t) % (BASE - t)));
                    q = (q - t) / (BASE - t);
                    k += BASE;
                }
                out.push(digit(q));
                bias = adapt(delta, handled + 1, handled == basic);
                delta = 0;
                handled += 1;
            }
        }
        delta += 1;
        n += 1;
    }
    Some(format!("xn--{out}"))
}

/// `spec-items.md` 2.1: the host an address fills on, or none
pub fn host_of(address: &str) -> Option<String> {
    let text = address.trim();
    if text.is_empty() || text.chars().any(char::is_whitespace) {
        return None;
    }
    let mut rest = text;
    if let Some(at) = rest.find("://") {
        if rest[..at].chars().all(|c| c.is_ascii_alphabetic()) && at > 0 {
            rest = &rest[at + 3..];
        }
    } else if let Some(stripped) = rest.strip_prefix("//") {
        rest = stripped;
    }
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let mut authority = &rest[..end];
    if let Some(at) = authority.rfind('@') {
        authority = &authority[at + 1..];
    }
    if authority.starts_with('[') {
        return None;
    }
    if let Some((host, port)) = authority.rsplit_once(':')
        && !port.is_empty()
        && port.bytes().all(|b| b.is_ascii_digit())
    {
        authority = host;
    }
    let mut host = authority.to_lowercase();
    if let Some(stripped) = host.strip_suffix('.') {
        host = stripped.to_string();
    }
    let labels: Vec<&str> = host.split('.').collect();
    let ipv4 = labels.len() == 4 && labels.iter().all(|l| !l.is_empty() && l.len() <= 3 && l.bytes().all(|b| b.is_ascii_digit()));
    if ipv4 {
        return Some(host);
    }
    if let Some(stripped) = host.strip_prefix("www.") {
        host = stripped.to_string();
    }
    let mut out = Vec::new();
    for label in host.split('.') {
        let label = if label.is_ascii() { label.to_string() } else { punycode(label)? };
        let shaped = !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-') && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-');
        if !shaped {
            return None;
        }
        out.push(label);
    }
    let last_numeric = out.last().is_some_and(|l| l.bytes().all(|b| b.is_ascii_digit()));
    if out.len() < 2 || last_numeric || out.join(".").len() > 253 {
        return None;
    }
    Some(out.join("."))
}

/// A rule fills on a host when it is of the Default, base domain, host, starts-with or exact kind
fn rule_host(rule: &Value) -> Option<String> {
    let fills = match rule.get("match") {
        None | Some(Value::Null) => true,
        Some(number) => number.as_u64().is_some_and(|n| n <= 3),
    };
    if !fills {
        return None;
    }
    host_of(rule.get("uri")?.as_str()?)
}

fn rules_of(plain: &Value) -> Vec<Value> {
    plain.get("uris").and_then(Value::as_array).map(|rules| rules.iter().filter(|rule| rule.is_object()).cloned().collect()).unwrap_or_default()
}

fn websites_of(plain: &Value) -> Vec<String> {
    plain.get("websites").and_then(Value::as_array).map(|list| list.iter().filter_map(|h| h.as_str().map(str::to_string)).collect()).unwrap_or_default()
}

/// The address a login has, for a person's single address: the first rule's `uri`, else the web vault's first `urls`, else the first host
pub fn address_of(plain: &Value) -> String {
    if let Some(uri) = rules_of(plain).first().and_then(|rule| s(rule, "uri")) {
        return uri;
    }
    if let Some(url) = plain.get("urls").and_then(Value::as_array).and_then(|urls| urls.first()).and_then(Value::as_str) {
        return url.to_string();
    }
    websites_of(plain).into_iter().next().unwrap_or_default()
}

/// Puts a person's address first among a login's, keeping the others, and `websites` the hosts of every rule that fills on one
fn put_address(object: &mut Map<String, Value>, address: &str) {
    let current = Value::Object(object.clone());
    if address_of(&current) == address {
        return;
    }
    let rules = rules_of(&current);
    let websites = websites_of(&current);
    let host = host_of(address);
    if address.is_empty() {
        // The person cleared it: the first website goes, the rest stay
        if rules.is_empty() {
            set_or_remove(object, "websites", Some(json!(websites.iter().skip(1).collect::<Vec<_>>())).filter(|list| list.as_array().is_some_and(|l| !l.is_empty())));
        } else {
            let rest: Vec<Value> = rules.into_iter().skip(1).collect();
            let hosts = hosts_of_rules(&rest, &websites);
            set_or_remove(object, "uris", Some(json!(rest)).filter(|rest| rest.as_array().is_some_and(|l| !l.is_empty())));
            set_or_remove(object, "websites", Some(json!(hosts)).filter(|list| list.as_array().is_some_and(|l| !l.is_empty())));
        }
        if let Some(urls) = object.get_mut("urls").and_then(Value::as_array_mut)
            && !urls.is_empty()
        {
            urls.remove(0);
        }
        return;
    }
    if rules.is_empty() && host.as_deref() == Some(address) {
        let mut hosts = vec![address.to_string()];
        hosts.extend(websites.iter().skip(1).filter(|h| h.as_str() != address).cloned());
        object.insert("websites".into(), json!(hosts));
    } else {
        let mut first = rules.first().cloned().unwrap_or_else(|| json!({}));
        first["uri"] = json!(address);
        let mut all = vec![first];
        all.extend(rules.into_iter().skip(1));
        let hosts = hosts_of_rules(&all, &[]);
        object.insert("uris".into(), json!(all));
        if host.is_some() || !hosts.is_empty() {
            object.insert("websites".into(), json!(hosts));
        }
    }
    if let Some(urls) = object.get_mut("urls").and_then(Value::as_array_mut) {
        if urls.is_empty() {
            urls.push(json!(address));
        } else {
            urls[0] = json!(address);
        }
    }
}

/// The hosts the rules fill on, in order and once each, then the websites no rule names (a rule the app adds back at read)
fn hosts_of_rules(rules: &[Value], websites: &[String]) -> Vec<String> {
    let mut hosts: Vec<String> = Vec::new();
    for host in rules.iter().filter_map(rule_host).chain(websites.iter().cloned()) {
        if !hosts.contains(&host) {
            hosts.push(host);
        }
    }
    hosts
}

// --- Compose ------------------------------------------------------------------------------------------------------------------

/// A vault item as a Kemlock plaintext, over the one the server last had. `file_held` is the SHA-256 of the attachment the server
/// already holds for this item, so that a file that did not change is not sent again.
pub fn compose(local: &Local, base: Option<&Value>, now_ms: i64, file_held: Option<&str>, convert: &dyn Convert) -> Result<Mapped, Unmapped> {
    let kem_kind = kem_kind_for(local).ok_or(Unmapped::Unreadable)?;
    let mut object = base.and_then(Value::as_object).cloned().unwrap_or_default();
    let mut file = None;
    match local.kind.as_str() {
        KIND_PASSWORD => login(&mut object, local, now_ms)?,
        KIND_ACCOUNT | KIND_BACKUP_CODES => overlay(&mut object, local)?,
        crate::protocol::KIND_KEY if kem_kind == kind::NOTE => aes_note(&mut object, local, now_ms)?,
        crate::protocol::KIND_KEY => key_entry(&mut object, local, kem_kind, now_ms)?,
        crate::protocol::KIND_CERTIFICATE => certificate(&mut object, local, now_ms, convert)?,
        _ => file = protected(&mut object, local, now_ms, file_held)?,
    }
    Ok(Mapped { kind: kem_kind, plain: Value::Object(object), file })
}

/// The keys of an item the Vault holds as the app's own shape: set from the item, the Vault's own never sent
fn overlay(object: &mut Map<String, Value>, local: &Local) -> Result<(), Unmapped> {
    let value = local.value.as_object().ok_or(Unmapped::Unreadable)?;
    // What the Vault maps and may no longer have: removed from what the server had
    let owned: &[&str] = if local.kind == KIND_ACCOUNT { &["type", "counter", "pinned", "tags", "order", "note", "noBackupCodes"] } else { &["note", "account", "tags", "order"] };
    for name in owned {
        if !value.contains_key(*name) {
            object.remove(*name);
        }
    }
    for (name, item) in value {
        if matches!(name.as_str(), "deletedAt" | "spaceId") {
            continue;
        }
        object.insert(name.clone(), item.clone());
    }
    if local.kind == KIND_ACCOUNT {
        // The app keeps its model's defaults written
        object.entry("algorithm").or_insert(json!("SHA1"));
        object.entry("digits").or_insert(json!(6));
        object.entry("period").or_insert(json!(30));
        object.entry("issuer").or_insert(json!(""));
        object.entry("label").or_insert(json!(""));
        object.entry("secret").or_insert(json!(""));
    } else {
        let codes = object.entry("codes").or_insert(json!([]));
        if let Some(list) = codes.as_array_mut() {
            for code in list.iter_mut().filter_map(Value::as_object_mut) {
                code.entry("used").or_insert(json!(false));
            }
        }
        object.entry("serviceName").or_insert(json!(""));
    }
    object.entry("addedAt").or_insert(json!(0));
    Ok(())
}

fn login(object: &mut Map<String, Value>, local: &Local, now_ms: i64) -> Result<(), Unmapped> {
    let password: Password = serde_json::from_value(local.value.clone()).map_err(|_| Unmapped::Unreadable)?;
    object.entry("id").or_insert(json!(local.id));
    object.insert("name".into(), json!(password.title));
    set_or_remove(object, "username", (!password.username.is_empty()).then(|| json!(password.username)));
    let old_password = object.get("password").and_then(Value::as_str).unwrap_or("").to_string();
    set_or_remove(object, "password", (!password.password.is_empty()).then(|| json!(password.password.as_str())));
    let note = password.note.as_ref().map(|note| note.as_str().to_string()).filter(|note| !note.is_empty());
    set_or_remove(object, "note", note.clone().map(Value::from));
    // The web vault's own key for it, kept in step where the item has it
    if object.contains_key("notes") {
        set_or_remove(object, "notes", note.map(Value::from));
    }
    let history: Vec<Value> = password.history.iter().take(MOST_HISTORY).map(|old| json!({"password": old.password.as_str(), "until": old.changed_at})).collect();
    set_or_remove(object, "previousPasswords", Some(json!(history)).filter(|list| !list.as_array().is_some_and(Vec::is_empty)));
    set_or_remove(object, "tags", password.tags.as_ref().map(|tags| json!(tags)));
    object.insert("addedAt".into(), json!(password.added_at));
    if let Some(updated) = password.updated_at {
        object.insert("updatedAt".into(), json!(updated));
    }
    if old_password != password.password.as_str() && !old_password.is_empty() {
        object.insert("passwordChangedAt".into(), json!(password.updated_at.unwrap_or(now_ms)));
    }
    let mut amethystora = object.get("amethystora").and_then(Value::as_object).cloned().unwrap_or_default();
    set_or_remove(&mut amethystora, "order", password.order.map(Value::from));
    set_or_remove(object, "amethystora", Some(Value::Object(amethystora)).filter(|o| o.as_object().is_some_and(|o| !o.is_empty())));
    put_address(object, &password.address);
    Ok(())
}

fn algorithm_of(key_type: &str) -> (&'static str, Option<u32>, bool) {
    match key_type {
        "ed25519" => ("ed25519", None, true),
        "ecdsa-p256" => ("ecdsa-p256", None, true),
        "ecdsa-p384" => ("ecdsa-p384", None, true),
        "rsa-3072" => ("rsa", Some(3072), true),
        "rsa-4096" => ("rsa", Some(4096), true),
        "rsa" => ("rsa", None, true),
        "ml-dsa-65" => ("ml-dsa-65", None, true),
        "x25519" => ("x25519", None, true),
        "ml-kem-768" => ("ml-kem-768", None, true),
        // The app has no P-521: its curve's OID, and no public half
        "ecdsa-p521" => ("1.3.132.0.35", None, false),
        _ => ("", None, false),
    }
}

/// The key type a Kemlock algorithm is, for a key read back
fn type_of(algorithm: &str, bits: Option<u64>) -> Option<&'static str> {
    Some(match (algorithm, bits) {
        ("ed25519", _) => "ed25519",
        ("ecdsa-p256", _) => "ecdsa-p256",
        ("ecdsa-p384", _) => "ecdsa-p384",
        ("rsa", Some(3072)) => "rsa-3072",
        ("rsa", Some(4096)) => "rsa-4096",
        ("rsa", _) => "rsa",
        ("ml-dsa-65", _) => "ml-dsa-65",
        ("x25519", _) => "x25519",
        ("ml-kem-768", _) => "ml-kem-768",
        ("1.3.132.0.35", _) => "ecdsa-p521",
        _ => return None,
    })
}

fn spki_of(pem: &str) -> Option<String> {
    let body: String = pem.lines().filter(|line| !line.starts_with("-----")).collect();
    STANDARD.decode(&body).ok().map(|_| body)
}

fn amethystora_set(object: &mut Map<String, Value>, entries: Vec<(&str, Option<Value>)>) {
    let mut amethystora = object.get("amethystora").and_then(Value::as_object).cloned().unwrap_or_default();
    for (name, value) in entries {
        set_or_remove(&mut amethystora, name, value);
    }
    set_or_remove(object, "amethystora", Some(Value::Object(amethystora)).filter(|o| o.as_object().is_some_and(|o| !o.is_empty())));
}

fn key_entry(object: &mut Map<String, Value>, local: &Local, kem_kind: &str, now_ms: i64) -> Result<(), Unmapped> {
    let value = &local.value;
    let (key_type, private) = (value["type"].as_str().ok_or(Unmapped::Unreadable)?, value["key"].as_str().ok_or(Unmapped::Unreadable)?);
    let (algorithm, bits, has_public) = algorithm_of(key_type);
    if algorithm.is_empty() {
        return Err(Unmapped::Unreadable);
    }
    let kind_word = match (kem_kind, key_type) {
        (kind::SSH_KEY, _) => "ssh",
        (_, "x25519" | "ml-kem-768") => "exchange",
        (_, "ecdsa-p521") => "other",
        _ => "signing",
    };
    let fresh = object.is_empty();
    object.entry("id").or_insert(json!(local.id));
    object.insert("name".into(), json!(local.name));
    object.insert("kind".into(), json!(kind_word));
    object.insert("algorithm".into(), json!(algorithm));
    set_or_remove(object, "bits", bits.map(Value::from));
    object.insert("private".into(), json!(private));
    set_or_remove(object, "public", value["public"]["pem"].as_str().and_then(spki_of).filter(|_| has_public).map(Value::from));
    object.entry("origin").or_insert(json!("imported"));
    object.entry("addedAt").or_insert(json!(now_ms));
    if !fresh && object.get("name").is_some() {
        object.insert("updatedAt".into(), json!(now_ms));
    }
    let key_kind = (value["key_kind"] == json!("ssh") && kem_kind != kind::SSH_KEY).then(|| json!("ssh"));
    amethystora_set(object, vec![("comment", value["comment"].as_str().filter(|c| !c.is_empty()).map(Value::from)), ("key_kind", key_kind)]);
    Ok(())
}

fn aes_note(object: &mut Map<String, Value>, local: &Local, now_ms: i64) -> Result<(), Unmapped> {
    let value = &local.value;
    let key = value["key"].as_str().ok_or(Unmapped::Unreadable)?;
    object.entry("id").or_insert(json!(local.id));
    object.insert("title".into(), json!(local.name));
    object.insert("name".into(), json!(local.name));
    object.insert("text".into(), json!(format!("{key}\n")));
    object.entry("addedAt").or_insert(json!(now_ms));
    amethystora_set(object, vec![("kind", Some(json!("key"))), ("key_kind", Some(json!("symmetric"))), ("type", Some(json!("aes-256"))), ("comment", value["comment"].as_str().filter(|c| !c.is_empty()).map(Value::from))]);
    Ok(())
}

fn certificate(object: &mut Map<String, Value>, local: &Local, now_ms: i64, convert: &dyn Convert) -> Result<(), Unmapped> {
    let value = &local.value;
    let (key_type, private, cert) = (value["type"].as_str().ok_or(Unmapped::Unreadable)?, value["key"].as_str().ok_or(Unmapped::Unreadable)?, value["cert"].as_str().ok_or(Unmapped::Unreadable)?);
    let (algorithm, bits, _) = algorithm_of(key_type);
    if algorithm.is_empty() {
        return Err(Unmapped::Unreadable);
    }
    let der = STANDARD.decode(cert).map_err(|_| Unmapped::Unreadable)?;
    let key_der = STANDARD.decode(private).map_err(|_| Unmapped::Unreadable)?;
    // The key's own public half is worked out by libcrypto's side, never taken from the certificate's text
    let read = convert.key_from_text(&crate::keys::pem("PRIVATE KEY", &key_der)).ok_or(Unmapped::Unreadable)?;
    object.entry("id").or_insert(json!(local.id));
    object.insert("name".into(), json!(local.name));
    object.insert("kind".into(), json!("signing"));
    object.insert("algorithm".into(), json!(algorithm));
    set_or_remove(object, "bits", bits.map(Value::from));
    object.insert("private".into(), json!(private));
    set_or_remove(object, "public", read.public["pem"].as_str().and_then(spki_of).map(Value::from));
    object.entry("origin").or_insert(json!("imported"));
    object.insert("certificate".into(), json!(crate::keys::pem("CERTIFICATE", &der)));
    object.entry("addedAt").or_insert(json!(now_ms));
    let chain = value["chain"].as_array().cloned().unwrap_or_default();
    let meta = &local.meta;
    amethystora_set(
        object,
        vec![
            ("kind", Some(json!("certificate"))),
            ("profile", value["profile"].as_str().map(Value::from)),
            ("fields", Some(value["fields"].clone()).filter(|fields| !fields.is_null())),
            ("chain", Some(json!(chain)).filter(|chain| !chain.as_array().is_some_and(Vec::is_empty))),
            ("renews", meta.get("renews").cloned().filter(|v| !v.is_null())),
            ("renewed_by", meta.get("renewed_by").cloned().filter(|v| !v.is_null())),
        ],
    );
    Ok(())
}

fn protected(object: &mut Map<String, Value>, local: &Local, now_ms: i64, file_held: Option<&str>) -> Result<Option<FileOut>, Unmapped> {
    use sha2::Digest;
    let made = plain::file_made(local)?;
    let file = made.file.ok_or(Unmapped::Unreadable)?;
    let sha256 = crate::seal::hex(&sha2::Sha256::digest(&file.bytes[..]));
    let what = local.value["what"].as_str().ok_or(Unmapped::Unreadable)?;
    object.entry("id").or_insert(json!(local.id));
    object.insert("title".into(), json!(local.name));
    object.insert("name".into(), json!(local.name));
    object.entry("text").or_insert(json!(""));
    object.entry("addedAt").or_insert(json!(now_ms));
    let held_id = object.get("amethystora").and_then(|a| s(a, "attachment"));
    let attachments = object.get("attachments").and_then(Value::as_array).cloned().unwrap_or_default();
    let keep = file_held == Some(sha256.as_str()) && held_id.as_deref().is_some_and(|id| attachments.iter().any(|a| s(a, "id").as_deref() == Some(id)));
    let mode = local.value["files"][0]["mode"].as_u64().or_else(|| local.value["mode"].as_u64());
    if keep {
        amethystora_set(object, vec![("kind", Some(json!("protected"))), ("what", Some(json!(what))), ("mode", mode.map(Value::from))]);
        return Ok(None);
    }
    // A changed file is a new attachment: the old one goes once the new is named, never written over
    let id: [u8; 16] = crate::seal::random_array();
    let id = crate::kemlock::conv::b64_encode(&id);
    let key = crate::kemlock::Key::random();
    let media = (what == "folder").then_some("application/x-tar");
    let mut attachment = json!({"id": id, "name": file.name, "size": file.bytes.len(), "key": STANDARD.encode(key.as_bytes()), "addedAt": now_ms});
    if let Some(media) = media {
        attachment["type"] = json!(media);
    }
    // The key goes into the note and nowhere else: the note's own seal is what protects it
    let kept: Vec<Value> = attachments.into_iter().filter(|a| s(a, "id") != held_id).collect();
    let mut all = vec![attachment];
    all.extend(kept);
    object.insert("attachments".into(), json!(all));
    amethystora_set(object, vec![("kind", Some(json!("protected"))), ("what", Some(json!(what))), ("attachment", Some(json!(id))), ("mode", mode.map(Value::from))]);
    Ok(Some(FileOut { name: file.name, media, bytes: file.bytes, sha256 }))
}

/// The attachment a protected note names, as the note holds it
pub fn attachment_of(plain: &Value) -> Option<Value> {
    let id = plain.get("amethystora").and_then(|a| s(a, "attachment"))?;
    plain.get("attachments")?.as_array()?.iter().find(|a| s(a, "id").as_deref() == Some(id.as_str())).cloned()
}

/// A file's key as the note holds it: 32 bytes
pub fn attachment_key(attachment: &Value) -> Option<crate::kemlock::Key> {
    let bytes = Zeroizing::new(STANDARD.decode(attachment.get("key")?.as_str()?).ok()?);
    crate::kemlock::Key::from_slice(&bytes)
}

/// The note, once its file is on the server: the attachment names the server's file id
pub fn name_file(plain: &mut Value, server_file: &str) {
    let Some(id) = plain.get("amethystora").and_then(|a| s(a, "attachment")) else { return };
    if let Some(list) = plain.get_mut("attachments").and_then(Value::as_array_mut) {
        for attachment in list.iter_mut().filter(|a| s(a, "id").as_deref() == Some(id.as_str())) {
            attachment["kemlockFile"] = json!(server_file);
        }
    }
}

/// The server's files a note names, other than the one it still needs: what an edit leaves behind
pub fn files_named(plain: &Value) -> Vec<String> {
    plain.get("attachments").and_then(Value::as_array).into_iter().flatten().filter_map(|a| s(a, "kemlockFile")).collect()
}

// --- Take ---------------------------------------------------------------------------------------------------------------------

/// What an item read from the server is to the vault
pub enum Taken {
    /// An item for the vault: written over the one it is, or new
    Item(Box<Read>),
    /// Not one of this client's: left as it is on the server, never written, never deleted
    Untouched,
    /// It no longer reads as the item it was (another key, a certificate whose leaf changed): the vault's stays, both are kept
    Conflict,
}

pub struct Read {
    pub kind: &'static str,
    pub id: String,
    pub name: String,
    pub meta: Value,
    pub value: Value,
    /// The attachment a protected note names, to be fetched before the item is whole
    pub needs_file: bool,
}

fn vault_kind_of(kem_kind: &str, plain: &Value) -> Option<&'static str> {
    match kem_kind {
        kind::LOGIN => Some(KIND_PASSWORD),
        kind::OTP => Some(KIND_ACCOUNT),
        kind::BACKUP_CODES => Some(KIND_BACKUP_CODES),
        kind::SSH_KEY | kind::KEY => Some(crate::protocol::KIND_KEY),
        kind::CERTIFICATE => Some(crate::protocol::KIND_CERTIFICATE),
        kind::NOTE => match plain.get("amethystora").and_then(|a| a.get("kind")).and_then(Value::as_str) {
            Some("protected") => Some("protected"),
            Some("key") => Some(crate::protocol::KIND_KEY),
            _ => None,
        },
        _ => None,
    }
}

/// Which vault kind an item of the server is, if this client reads it: otherwise it is left alone
pub fn reads(kem_kind: &str, plain: &Value) -> Option<&'static str> {
    if plain.get("spaceId").is_some_and(|space| !space.is_null()) {
        return None;
    }
    vault_kind_of(kem_kind, plain)
}

/// An item of the server for the vault. `existing` is the vault item it pairs with, if there is one; `file` the attachment's bytes,
/// when this note's file was fetched.
pub fn take(kem_kind: &str, plain: &Value, existing: Option<&Local>, file: Option<&[u8]>, _now_ms: i64, convert: &dyn Convert) -> Taken {
    let Some(vault_kind) = reads(kem_kind, plain) else { return Taken::Untouched };
    let id = existing.map(|local| local.id.clone()).or_else(|| s(plain, "id")).filter(|id| crate::protocol::valid_id(id));
    let Some(id) = id else { return Taken::Untouched };
    match vault_kind {
        KIND_PASSWORD => take_login(plain, existing, id),
        KIND_ACCOUNT => take_overlaid::<Account>(KIND_ACCOUNT, plain, existing, id),
        KIND_BACKUP_CODES => take_overlaid::<BackupService>(KIND_BACKUP_CODES, plain, existing, id),
        crate::protocol::KIND_KEY if kem_kind == kind::NOTE => take_aes(plain, existing, id, convert),
        crate::protocol::KIND_KEY => take_key(plain, existing, id, convert),
        crate::protocol::KIND_CERTIFICATE => take_certificate(plain, existing, convert),
        _ => take_protected(plain, existing, id, file, convert),
    }
    .map_or(Taken::Untouched, |taken| match taken {
        Ok(read) => Taken::Item(Box::new(read)),
        Err(()) => Taken::Conflict,
    })
}

type Taking = Option<Result<Read, ()>>;

fn take_login(plain: &Value, existing: Option<&Local>, id: String) -> Taking {
    let name = s(plain, "name").or_else(|| s(plain, "title")).unwrap_or_default();
    let mut password = match existing.and_then(map::password) {
        Some(held) => held,
        None => Password { id: id.clone(), ..Password::default() },
    };
    password.id = id.clone();
    password.title = name.clone();
    password.username = s(plain, "username").unwrap_or_default();
    password.password = Secret::new(s(plain, "password").unwrap_or_default());
    password.address = address_of(plain);
    password.note = s(plain, "note").or_else(|| s(plain, "notes")).filter(|note| !note.is_empty()).map(Secret::new);
    password.history = plain
        .get("previousPasswords")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|old| Some(OldPassword { password: Secret::new(old.get("password")?.as_str()?), changed_at: old.get("until").and_then(Value::as_i64).unwrap_or(0) }))
        .take(MOST_HISTORY)
        .collect();
    password.tags = plain.get("tags").and_then(Value::as_array).filter(|tags| tags.iter().all(Value::is_string)).map(|tags| tags.iter().filter_map(|t| t.as_str().map(str::to_string)).collect());
    password.order = plain.get("amethystora").and_then(|a| a.get("order")).and_then(Value::as_i64);
    password.added_at = plain.get("addedAt").and_then(number).unwrap_or(0);
    password.updated_at = plain.get("updatedAt").and_then(number);
    password.deleted_at = None;
    let value = serde_json::to_value(&password).ok()?;
    let meta = map::meta_of(KIND_PASSWORD, &value);
    Some(Ok(Read { kind: KIND_PASSWORD, name: map::name_of(KIND_PASSWORD, &value), id, meta, value, needs_file: false }))
}

/// Times are whole numbers of milliseconds; the app also takes a fraction and rounds it
fn number(value: &Value) -> Option<i64> {
    value.as_i64().or_else(|| value.as_f64().filter(|f| f.is_finite()).map(|f| f.round() as i64))
}

/// An authenticator account or a backup service: the app's own shape, which the Vault's structs read as they are
fn take_overlaid<T: serde::de::DeserializeOwned + serde::Serialize>(kind: &'static str, plain: &Value, existing: Option<&Local>, id: String) -> Taking {
    let mut value = plain.clone();
    let object = value.as_object_mut()?;
    object.insert("id".into(), json!(id));
    object.remove("amethystora");
    if kind == KIND_BACKUP_CODES && object.get("codes").is_some_and(|codes| codes.as_array().is_none_or(|list| list.iter().any(|c| !c.is_object()))) {
        // The app itself fails on such a list: it is not an item to take
        return Some(Err(()));
    }
    let typed: T = serde_json::from_value(value).ok()?;
    let mut value = serde_json::to_value(&typed).ok()?;
    if let Some(held) = existing {
        // A counter never goes back, and a code used here stays used
        if kind == KIND_ACCOUNT {
            let (ours, theirs) = (held.value.get("counter").and_then(Value::as_i64), value.get("counter").and_then(Value::as_i64));
            if ours > theirs {
                value["counter"] = json!(ours);
            }
        } else if let (Some(held_codes), Some(codes)) = (held.value.get("codes").and_then(Value::as_array), value.get_mut("codes").and_then(Value::as_array_mut)) {
            for code in codes.iter_mut() {
                let used_here = held_codes.iter().any(|h| h.get("code") == code.get("code") && h.get("used") == Some(&json!(true)));
                if used_here && code.get("used") != Some(&json!(true)) {
                    code["used"] = json!(true);
                }
            }
        }
    }
    let meta = map::meta_of(kind, &value);
    Some(Ok(Read { kind, name: map::name_of(kind, &value), id, meta, value, needs_file: false }))
}

fn take_key(plain: &Value, existing: Option<&Local>, id: String, convert: &dyn Convert) -> Taking {
    let (algorithm, private) = (plain.get("algorithm")?.as_str()?, plain.get("private")?.as_str()?);
    let key_type = type_of(algorithm, plain.get("bits").and_then(Value::as_u64))?;
    let der = Zeroizing::new(STANDARD.decode(private).ok()?);
    let read = convert.key_from_text(&crate::keys::pem("PRIVATE KEY", &der))?;
    // The key says which type it is: the algorithm a server wrote on it is a claim, held to what it opens as
    let same_family = |a: &str, b: &str| a == b || (a.starts_with("rsa") && b.starts_with("rsa"));
    if !read.agree || !same_family(&read.key_type, key_type) {
        return Some(Err(()));
    }
    if let Some(public) = plain.get("public").and_then(Value::as_str) {
        // A public half that is not the key's own is not this key
        let derived = read.public["pem"].as_str().and_then(spki_of);
        if derived.as_deref() != Some(public) {
            return Some(Err(()));
        }
    }
    let name = s(plain, "name").unwrap_or_default();
    let comment = plain.get("amethystora").and_then(|a| s(a, "comment"));
    let (mut value, mut meta) = match existing {
        Some(local) => {
            // Only the same key is taken back: its type and its public key, else its bytes
            let same = match (local.value["public"]["sha256"].as_str(), read.public["sha256"].as_str()) {
                (Some(held), Some(read)) => held == read,
                _ => local.value["key"].as_str().and_then(|k| STANDARD.decode(k).ok()).is_some_and(|held| crate::seal::same(&held, &read.key)),
            };
            if local.value["type"].as_str() != Some(read.key_type.as_str()) || !same {
                return Some(Err(()));
            }
            (local.value.clone(), local.meta.clone())
        }
        None => {
            let kind_word = plain.get("amethystora").and_then(|a| s(a, "key_kind")).or_else(|| s(plain, "kind"));
            let key_kind = match kind_word.as_deref() {
                Some("ssh") => "ssh",
                Some("exchange") => "exchange",
                _ => "signing",
            };
            (json!({"key_kind": key_kind, "type": read.key_type, "exportable": true, "comment": comment}), json!({"key_kind": key_kind, "type": read.key_type, "exportable": true}))
        }
    };
    value["key"] = json!(STANDARD.encode(&*read.key));
    value["public"] = read.public.clone();
    for field in ["sha256", "ssh_sha256", "openssh"] {
        match read.public.get(field).filter(|found| !found.is_null()) {
            Some(found) => meta[field] = found.clone(),
            None => {
                if let Some(object) = meta.as_object_mut() {
                    object.remove(field);
                }
            }
        }
    }
    if existing.is_some() && comment.is_some() {
        value["comment"] = json!(comment);
    }
    Some(Ok(Read { kind: crate::protocol::KIND_KEY, id, name: if name.is_empty() { existing.map(|l| l.name.clone()).unwrap_or_else(|| "-".into()) } else { name }, meta, value, needs_file: false }))
}

fn take_aes(plain: &Value, existing: Option<&Local>, id: String, convert: &dyn Convert) -> Taking {
    let text = plain.get("text")?.as_str()?;
    let read = convert.key_from_text(text.trim())?;
    if read.key_type != "aes-256" || read.key.len() != 32 {
        return Some(Err(()));
    }
    let name = s(plain, "title").or_else(|| s(plain, "name")).unwrap_or_default();
    let comment = plain.get("amethystora").and_then(|a| s(a, "comment"));
    let (mut value, meta) = match existing {
        Some(local) => {
            if local.value["type"].as_str() != Some("aes-256") || !local.value["key"].as_str().and_then(|k| STANDARD.decode(k).ok()).is_some_and(|held| crate::seal::same(&held, &read.key)) {
                return Some(Err(()));
            }
            (local.value.clone(), local.meta.clone())
        }
        None => (json!({"key_kind": "symmetric", "type": "aes-256", "exportable": true, "comment": comment, "public": null}), json!({"key_kind": "symmetric", "type": "aes-256", "exportable": true})),
    };
    value["key"] = json!(STANDARD.encode(&*read.key));
    Some(Ok(Read { kind: crate::protocol::KIND_KEY, id, name: if name.is_empty() { "-".into() } else { name }, meta, value, needs_file: false }))
}

/// A certificate back: only an existing one, and only its chain may change (`plain::cert_read`'s rules)
fn take_certificate(plain: &Value, existing: Option<&Local>, convert: &dyn Convert) -> Taking {
    let held = existing?;
    let pem = plain.get("certificate")?.as_str()?;
    let blocks = plain::pem_blocks(pem);
    let certs: Vec<Vec<u8>> = blocks.into_iter().filter(|(label, _)| matches!(label.as_str(), "CERTIFICATE" | "TRUSTED CERTIFICATE" | "X509 CERTIFICATE")).map(|(_, der)| der).collect();
    let (leaf, further) = certs.split_first()?;
    let mut chain: Vec<Vec<u8>> = plain.get("amethystora").and_then(|a| a.get("chain")).and_then(Value::as_array).into_iter().flatten().filter_map(|c| STANDARD.decode(c.as_str()?).ok()).collect();
    chain.extend(further.iter().cloned());
    let mut all = vec![leaf.clone()];
    all.extend(chain.iter().cloned());
    if all.len() > 16 {
        return Some(Err(()));
    }
    let key_der = Zeroizing::new(STANDARD.decode(plain.get("private")?.as_str()?).ok()?);
    let key = convert.key_from_text(&crate::keys::pem("PRIVATE KEY", &key_der))?;
    let (held_type, held_key) = (held.value["type"].as_str()?, held.value["key"].as_str().and_then(|k| STANDARD.decode(k).ok())?);
    if key.key_type != held_type || !crate::seal::same(&key.key, &held_key) {
        return Some(Err(()));
    }
    let facts = convert.cert_facts(&all, Some((held_type, &key.key)))?;
    if !facts.key_matches || !facts.chain_ok || held.meta["sha256"].as_str() != Some(facts.leaf_sha256.as_str()) || held.meta["spki_sha256"].as_str() != Some(facts.spki_sha256.as_str()) {
        return Some(Err(()));
    }
    let mut value = held.value.clone();
    value["cert"] = json!(STANDARD.encode(leaf));
    value["chain"] = json!(chain.iter().map(|der| STANDARD.encode(der)).collect::<Vec<_>>());
    let name = s(plain, "name").unwrap_or_else(|| held.name.clone());
    Some(Ok(Read { kind: crate::protocol::KIND_CERTIFICATE, id: held.id.clone(), name, meta: held.meta.clone(), value, needs_file: false }))
}

/// A protected note back: an existing item only, its file read with `plain::file_read`'s checks
fn take_protected(plain: &Value, existing: Option<&Local>, id: String, file: Option<&[u8]>, convert: &dyn Convert) -> Taking {
    let held = existing?;
    let attachment = attachment_of(plain)?;
    let _ = attachment;
    let Some(bytes) = file else {
        // The file has not been fetched: the item is whole only with it
        return Some(Ok(Read { kind: "protected", id, name: s(plain, "title").or_else(|| s(plain, "name")).unwrap_or_else(|| held.name.clone()), meta: held.meta.clone(), value: held.value.clone(), needs_file: true }));
    };
    let value = plain::file_read(held, bytes, convert)?;
    let name = s(plain, "title").or_else(|| s(plain, "name")).unwrap_or_else(|| held.name.clone());
    Some(Ok(Read { kind: "protected", id, name, meta: held.meta.clone(), value, needs_file: false }))
}

/// The plaintext's own canonical form, for two of them to be compared as data and never as bytes
pub fn canonical(value: &Value) -> Vec<u8> {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(object) => {
                let mut keys: Vec<&String> = object.keys().collect();
                keys.sort();
                Value::Object(keys.into_iter().map(|key| (key.clone(), sorted(&object[key]))).collect())
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_vec(&sorted(value)).unwrap_or_default()
}
