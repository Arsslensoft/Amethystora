//! DPoP end to end against a server that checks every rule of a proof, the nonce, the clock, and the tokens: bound to the proof's key,
//! rotating at every refresh, ended by a refresh token used twice (`spec-protocol.md` 2.6, 2.8, 3).

use ed25519_dalek::{Signer, SigningKey};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::common::*;
use crate::kemlock::conv::b64_encode;
use crate::kemlock::sync::dpop::{self, DpopKey};
use crate::kemlock::sync::fake::FakeKemlock;
use crate::sync::api::{Http, Request};

fn nonce_of(fake: &mut FakeKemlock) -> String {
    let request = Request { method: "GET", url: format!("{}/kem/v1/config", fake.server().address), headers: Vec::new(), body: Zeroizing::new(Vec::new()) };
    let response = fake.call(request).unwrap();
    response.headers.iter().find(|(name, _)| name == "dpop-nonce").map(|(_, value)| value.clone()).expect("every answer carries a nonce")
}

/// A hand-made proof: header and claims as given, signed by `key`
fn forged(key: &SigningKey, header: Value, claims: Value) -> String {
    let signing_input = format!("{}.{}", b64_encode(header.to_string().as_bytes()), b64_encode(claims.to_string().as_bytes()));
    format!("{signing_input}.{}", b64_encode(&key.sign(signing_input.as_bytes()).to_bytes()))
}

fn jwk_of(key: &SigningKey) -> Value {
    json!({"kty": "OKP", "crv": "Ed25519", "x": b64_encode(&key.verifying_key().to_bytes())})
}

fn token_request(fake: &FakeKemlock, proofs: &[String], body: &Value) -> Request {
    let mut headers: Vec<(&'static str, String)> = proofs.iter().map(|proof| ("DPoP", proof.clone())).collect();
    headers.push(("Content-Type", "application/json".into()));
    Request { method: "POST", url: format!("{}/kem/v1/auth/token", fake.server().address), headers, body: Zeroizing::new(serde_json::to_vec(body).unwrap()) }
}

fn token_slug(fake: &mut FakeKemlock, proofs: &[String], body: &Value) -> (u16, String) {
    let request = token_request(fake, proofs, body);
    slug_of(fake, request)
}

fn slug_of(fake: &mut FakeKemlock, request: Request) -> (u16, String) {
    let response = fake.call(request).unwrap();
    let body: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
    (response.status, body["type"].as_str().unwrap_or("").trim_start_matches("urn:kemlock:problem:").to_string())
}

#[test]
fn the_fake_refuses_every_proof_that_breaks_a_rule() {
    let mut fake = server();
    let nonce = nonce_of(&mut fake);
    let signing = SigningKey::from_bytes(&[7u8; 32]);
    let other = SigningKey::from_bytes(&[8u8; 32]);
    let url = format!("{}/kem/v1/auth/token", fake.server().address);
    let body = json!({"grantType": "refresh_token", "refreshToken": "rt.unknown"});
    let now = fake.now();
    let header = json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": jwk_of(&signing)});
    let claims = |jti: &str| json!({"jti": jti, "htm": "POST", "htu": dpop::htu(&url), "iat": now, "nonce": nonce});

    // The honest proof passes the proof checks and is refused only as a refresh token nobody holds
    let good = forged(&signing, header.clone(), claims("a"));
    assert_eq!(token_slug(&mut fake, std::slice::from_ref(&good), &body), (401, "unauthorized".into()));
    // The same proof again: its jti was used
    assert_eq!(token_slug(&mut fake, std::slice::from_ref(&good), &body), (401, "invalid-dpop-proof".into()));

    let bad: Vec<(&str, Vec<String>)> = vec![
        ("no proof", vec![]),
        ("two proofs", vec![forged(&signing, header.clone(), claims("b")), forged(&signing, header.clone(), claims("c"))]),
        ("not three parts", vec!["a.b".into()]),
        ("typ", vec![forged(&signing, json!({"typ": "JWT", "alg": "EdDSA", "jwk": jwk_of(&signing)}), claims("d"))]),
        ("alg", vec![forged(&signing, json!({"typ": "dpop+jwt", "alg": "none", "jwk": jwk_of(&signing)}), claims("e"))]),
        ("a private member in the jwk", vec![forged(&signing, json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": {"kty": "OKP", "crv": "Ed25519", "x": b64_encode(&signing.verifying_key().to_bytes()), "d": b64_encode(&[7u8; 32])}}), claims("f"))]),
        ("a signature of another key", vec![forged(&other, header.clone(), claims("g"))]),
        ("htm", vec![forged(&signing, header.clone(), json!({"jti": "h", "htm": "GET", "htu": dpop::htu(&url), "iat": now, "nonce": nonce}))]),
        ("htu", vec![forged(&signing, header.clone(), json!({"jti": "i", "htm": "POST", "htu": "https://kemlock.example.test/kem/v1/auth/prelogin", "iat": now, "nonce": nonce}))]),
        ("iat a minute and a half ahead", vec![forged(&signing, header.clone(), json!({"jti": "j", "htm": "POST", "htu": dpop::htu(&url), "iat": now + 90, "nonce": nonce}))]),
        ("iat a minute and a half behind", vec![forged(&signing, header.clone(), json!({"jti": "k", "htm": "POST", "htu": dpop::htu(&url), "iat": now - 90, "nonce": nonce}))]),
        ("no jti", vec![forged(&signing, header.clone(), json!({"htm": "POST", "htu": dpop::htu(&url), "iat": now, "nonce": nonce}))]),
    ];
    for (why, proofs) in bad {
        assert_eq!(token_slug(&mut fake, &proofs, &body), (401, "invalid-dpop-proof".into()), "{why}");
    }
    // A missing or wrong nonce is its own answer, with the nonce to use
    let no_nonce = forged(&signing, header.clone(), json!({"jti": "l", "htm": "POST", "htu": dpop::htu(&url), "iat": now}));
    assert_eq!(token_slug(&mut fake, &[no_nonce], &body), (401, "use-dpop-nonce".into()));
    let wrong = forged(&signing, header, json!({"jti": "m", "htm": "POST", "htu": dpop::htu(&url), "iat": now, "nonce": "not-the-nonce"}));
    assert_eq!(token_slug(&mut fake, &[wrong], &body), (401, "use-dpop-nonce".into()));
}

#[test]
fn the_fake_wants_the_dpop_scheme_and_a_proof_that_names_the_token() {
    let mut fake = server();
    let client = Client::connect(&mut fake, EMAIL);
    let access = {
        // A fresh session of our own, to hold a token and its key
        let key = DpopKey::generate();
        let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
        (done.tokens.access.to_string(), key)
    };
    drop(client);
    let url = format!("{}/kem/v1/account/keys", fake.server().address);
    let call = |fake: &mut FakeKemlock, scheme_token: &str, proof_for: Option<&str>| {
        let nonce = nonce_of(fake);
        let proof = access.1.proof("GET", &url, proof_for, Some(&nonce), fake.now());
        let request = Request { method: "GET", url: url.clone(), headers: vec![("DPoP", proof), ("Authorization", scheme_token.to_string())], body: Zeroizing::new(Vec::new()) };
        slug_of(fake, request)
    };
    assert_eq!(call(&mut fake, &format!("DPoP {}", access.0), Some(&access.0)).0, 200);
    // A bearer token is refused, a proof without `ath` is, and one that names another token is
    assert_eq!(call(&mut fake, &format!("Bearer {}", access.0), Some(&access.0)), (401, "unauthorized".into()));
    assert_eq!(call(&mut fake, &format!("DPoP {}", access.0), None), (401, "invalid-dpop-proof".into()));
    assert_eq!(call(&mut fake, &format!("DPoP {}", access.0), Some("another token")), (401, "invalid-dpop-proof".into()));
    // A token made up, and the real one under a proof of another key: not good
    assert_eq!(call(&mut fake, "DPoP at.made-up", Some("at.made-up")), (401, "unauthorized".into()));
    let thief = DpopKey::generate();
    let nonce = nonce_of(&mut fake);
    let proof = thief.proof("GET", &url, Some(&access.0), Some(&nonce), fake.now());
    let request = Request { method: "GET", url, headers: vec![("DPoP", proof), ("Authorization", format!("DPoP {}", access.0))], body: Zeroizing::new(Vec::new()) };
    assert_eq!(slug_of(&mut fake, request), (401, "unauthorized".into()));
}

