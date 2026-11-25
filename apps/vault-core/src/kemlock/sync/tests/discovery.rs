//! Telling a Kemlock Server from anything else, from its own `/kem/v1/config` alone (`spec-protocol.md` 1).

use serde_json::json;

use super::common::*;
use crate::kemlock::sync::api::{KemApi, hints_kemlock, read_config};
use crate::kemlock::sync::dpop::DpopKey;
use crate::kemlock::sync::fake::{self, FakeKemlock};
use crate::kemlock::sync::word;
use crate::sync::api::Problem;

#[test]
fn a_kemlock_servers_config_is_read_and_says_what_it_can_do() {
    let mut fake = server();
    let key = DpopKey::generate();
    let address = fake.server();
    let mut api = KemApi::new(&mut fake, &address, &key);
    let config = read_config(&api.config().unwrap()).expect("a Kemlock Server");
    assert_eq!(config.domain, fake::BASE);
    assert_eq!(config.version, "0.1.2");
    for feature in ["opaque", "dpop", "sync", "manifest", "bitwarden-enrol"] {
        assert!(config.has(feature), "{feature}");
    }
    // The config is the one call with no proof, and its answer already carries the nonce
    let seen = &fake.seen[0];
    assert!(seen.header("dpop").is_none() && seen.header("authorization").is_none());
    assert!(!fake.seen.is_empty());
}

#[test]
fn a_vaultwarden_shaped_answer_is_not_kemlock() {
    let mut fake = server();
    fake.config_override = Some((200, json!({"version": "2026.6.0", "server": {"name": "Vaultwarden"}, "kemlock": {"api": "https://x/kem/v1", "versions": ["v1"]}})));
    let key = DpopKey::generate();
    let address = fake.server();
    // Even with the Bitwarden config's hint, only `/kem/v1/config` decides
    let answer = KemApi::new(&mut fake, &address, &key).config().unwrap();
    assert!(read_config(&answer).is_none());
    assert!(hints_kemlock(&json!({"kemlock": {"versions": ["v1"]}})));
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::NOT_KEMLOCK)));
    // Nothing but the config was asked
    assert_eq!(fake.seen.len(), 2);
}

#[test]
fn a_server_that_answers_404_or_another_api_version_is_not_kemlock() {
    let key = DpopKey::generate();
    for (status, body) in [(404, json!({})), (200, json!({"server": "kemlock-server", "apiVersions": ["v2"]})), (200, json!("<html>web vault</html>")), (200, json!({"server": "something-else", "apiVersions": ["v1"]}))] {
        let mut fake = server();
        fake.config_override = Some((status, body));
        let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
        assert_eq!(attempted.err(), Some(Problem::Kemlock(word::NOT_KEMLOCK)), "{status}");
    }
}

#[test]
fn a_server_set_up_under_another_address_is_said_so_before_any_proof_is_made() {
    // Proofs are checked against the server's own DOMAIN: this one would refuse every one of them
    let mut fake = FakeKemlock::new("http://127.0.0.1:18299");
    fake.make_account(EMAIL, PASSWORD);
    fake.reachable_at("http://localhost:18299");
    let key = DpopKey::generate();
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::DOMAIN_DIFFERS)));
    assert_eq!(fake.seen.len(), 1, "only the config was asked");
    assert!(fake.seen.iter().all(|seen| seen.header("dpop").is_none()));
}

#[test]
fn the_same_address_written_another_way_is_the_same_address() {
    let mut fake = FakeKemlock::new("https://Kemlock.Example.test:443/");
    fake.make_account(EMAIL, PASSWORD);
    fake.reachable_at("https://kemlock.example.test");
    let key = DpopKey::generate();
    connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
}

#[test]
fn a_server_too_old_for_what_the_vault_needs_is_refused() {
    for lacking in ["opaque", "dpop", "sync"] {
        let mut fake = server();
        fake.features.retain(|feature| feature != lacking);
        let key = DpopKey::generate();
        let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
        assert_eq!(attempted.err(), Some(Problem::Kemlock(word::SERVER_TOO_OLD)), "{lacking}");
        assert_eq!(fake.seen.len(), 1);
    }
}

#[test]
fn an_account_that_signs_in_with_single_sign_on_is_said_so() {
    let mut fake = server();
    fake.sso_only = true;
    let key = DpopKey::generate();
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::SSO_ONLY)));
    // No password-derived byte went anywhere
    assert!(fake.seen.iter().all(|seen| !seen.path().contains("opaque")));
}

#[test]
fn a_domain_the_address_cannot_reach_never_becomes_the_address() {
    // The server says it is somewhere else: the client goes on asking where it was told to, and says so
    let mut fake = server();
    fake.config_override = Some((
        200,
        json!({"server": "kemlock-server", "apiVersions": ["v1"], "version": "1", "domain": "https://evil.example", "features": ["opaque", "dpop", "sync"]}),
    ));
    let key = DpopKey::generate();
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::DOMAIN_DIFFERS)));
    assert!(fake.seen.iter().all(|seen| seen.url.starts_with(fake::BASE)));
}
