//! The nonce, the clock, and the tokens: a refresh token that rotates and ends the session when it is used twice, kept before it is used
//! (`spec-protocol.md` 2.6, 2.8, 3.5, 3.6).

use super::common::*;
use crate::kemlock::sync::api::KemApi;
use crate::kemlock::sync::dpop::DpopKey;
use crate::kemlock::sync::fake::{Attack, FakeKemlock};
use crate::kemlock::sync::word;
use crate::sync::api::{Expired, NetFailure, Problem};

fn claims_of(proof: &str) -> serde_json::Value {
    serde_json::from_slice(&crate::kemlock::conv::b64_decode(proof.split('.').nth(1).unwrap()).unwrap()).unwrap()
}

fn token_calls(fake: &FakeKemlock) -> Vec<&crate::kemlock::sync::fake::Seen> {
    fake.seen.iter().filter(|seen| seen.path().ends_with("/auth/token")).collect()
}

#[test]
fn a_missing_nonce_is_asked_for_once_and_the_retry_carries_it_in_a_new_proof() {
    let mut fake = server();
    let key = DpopKey::generate();
    let address = fake.server();
    // The very first proof of a server has no nonce to carry: the answer gives it, and the same request goes again
    let refused = KemApi::new(&mut fake, &address, &key).refresh("rt.nobody").err();
    assert_eq!(refused, Some(Problem::LoginExpired));
    let calls = token_calls(&fake);
    assert_eq!(calls.len(), 2);
    let (first, second) = (claims_of(calls[0].header("dpop").unwrap()), claims_of(calls[1].header("dpop").unwrap()));
    assert!(first.get("nonce").is_none());
    assert!(second["nonce"].as_str().is_some_and(|nonce| !nonce.is_empty()));
    assert_ne!(first["jti"], second["jti"], "a new proof, not the old one sent again");
}

#[test]
fn a_nonce_the_server_moved_on_from_is_taken_once_and_a_second_refusal_stops() {
    let mut fake = server();
    let key = DpopKey::generate();
    let address = fake.server();
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.config().unwrap();
    // One stale answer: the retry passes
    drop(api);
    fake.attack(Attack::StaleNonce(1));
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.config().unwrap();
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::LoginExpired));
    drop(api);
    // Two in a row are not a nonce to catch up with
    fake.attack(Attack::StaleNonce(2));
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.config().unwrap();
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::Kemlock(word::DPOP_NONCE)));
    drop(api);
    fake.clear_attacks();
    fake.attack(Attack::NonceNeverAccepted);
    let mut api = KemApi::new(&mut fake, &address, &key);
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::Kemlock(word::DPOP_NONCE)));
}

#[test]
fn the_previous_nonce_is_still_accepted_and_an_older_one_is_asked_again() {
    let mut fake = server();
    let key = DpopKey::generate();
    let address = fake.server();
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.config().unwrap();
    let learned = api.nonce.clone();
    drop(api);
    fake.rotate_nonce();
    // Learned before the change: accepted at once, in one request
    let before = fake.seen.len();
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.nonce = learned.clone();
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::LoginExpired));
    drop(api);
    assert_eq!(fake.seen.len() - before, 1);
    // Held across two changes: too old, asked again once, then through
    fake.rotate_nonce();
    let before = fake.seen.len();
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.nonce = learned;
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::LoginExpired));
    drop(api);
    assert_eq!(fake.seen.len() - before, 2);
}

#[test]
fn a_clock_that_is_off_is_learned_from_the_servers_date_and_never_read_as_a_wrong_login() {
    let mut fake = server();
    fake.clock_offset = 3600;
    let key = DpopKey::generate();
    let address = fake.server();
    // The first proof is an hour out: refused for it, the answer's Date says how far, and the request goes again at the right time
    let mut api = KemApi::new(&mut fake, &address, &key);
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::LoginExpired));
    assert!((api.skew - 3600).abs() < 5, "{}", api.skew);
    drop(api);
    assert_eq!(token_calls(&fake).len(), 2);
    // A run does the same without reading the config first
    let mut client = Client::connect(&mut fake, EMAIL);
    client.put("password", PASSWORD_ID, with_id(password("A", "u", "p", "https://a.example"), PASSWORD_ID));
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(fake.live_ids(EMAIL).len(), 1);
    // The same server, whose Date is right but whose DOMAIN is not what the client signs: that is refused, not retried
    let mut fake = server();
    fake.reachable_at("http://localhost:18299");
    fake.domain = "http://127.0.0.1:18299".into();
    let address = fake.server();
    let mut api = KemApi::new(&mut fake, &address, &key);
    assert_eq!(api.refresh("rt.nobody").err(), Some(Problem::Kemlock(word::DPOP_REFUSED)));
    drop(api);
    assert_eq!(token_calls(&fake).len(), 1);
}

#[test]
fn a_refresh_rotates_the_token_and_a_spent_one_ends_the_whole_session() {
    let mut fake = server();
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
    let address = fake.server();
    let old = done.tokens.refresh.to_string();
    let mut api = KemApi::new(&mut fake, &address, &key);
    let renewed = api.refresh(&old).unwrap();
    assert_ne!(renewed.refresh.as_str(), old);
    assert_ne!(renewed.access.as_str(), done.tokens.access.as_str());
    assert_eq!(renewed.device_id, done.tokens.device_id, "one device");
    api.access = Some(renewed.access.clone());
    assert!(api.account_keys().is_ok());
    // The spent token used again: whoever has it is not the one given the new one
    assert_eq!(api.refresh(&old).err(), Some(Problem::Kemlock(word::SESSION_ENDED)));
    // The new token is dead with it, and so are the access tokens of the session
    assert_eq!(api.refresh(renewed.refresh.as_str()).err(), Some(Problem::Kemlock(word::SESSION_ENDED)));
    assert!(matches!(api.account_keys(), Err(Expired::Token)));
    drop(api);
    assert_eq!(fake.session_count(EMAIL), 0);
}

#[test]
fn a_refresh_token_is_good_only_under_the_key_it_was_given_to() {
    let mut fake = server();
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
    let address = fake.server();
    let thief = DpopKey::generate();
    let mut api = KemApi::new(&mut fake, &address, &thief);
    assert_eq!(api.refresh(done.tokens.refresh.as_str()).err(), Some(Problem::LoginExpired));
    drop(api);
    // Nothing was spent by the attempt
    assert!(KemApi::new(&mut fake, &address, &key).refresh(done.tokens.refresh.as_str()).is_ok());
}

#[test]
fn the_new_refresh_token_is_kept_before_anything_uses_it() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let before = fake.seen.len();
    client.put("password", PASSWORD_ID, with_id(password("A", "u", "p", "https://a.example"), PASSWORD_ID));
    // The service could not keep it: the run stops at once, with no request made under the new access token
    client.refuse_persist = true;
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Net(NetFailure::Cancelled)));
    assert_eq!(client.persisted.len(), 1);
    let last = fake.seen.last().unwrap();
    assert!(last.path().ends_with("/auth/token"), "the refresh was the last request: {}", last.path());
    assert!(fake.seen[before..].iter().all(|seen| seen.header("authorization").is_none()), "the new access token was never sent");
    assert!(client.locals.contains_key(&("password".to_string(), PASSWORD_ID.to_string())));
    assert!(fake.live_ids(EMAIL).is_empty(), "nothing was written");
}

#[test]
fn a_run_hands_over_each_new_token_in_order_and_the_next_run_goes_on_from_it() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let first = client.connection.refresh.clone().unwrap();
    client.put("password", PASSWORD_ID, with_id(password("A", "u", "p", "https://a.example"), PASSWORD_ID));
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.persisted.len(), 1);
    assert_ne!(client.persisted[0], first);
    assert_eq!(client.connection.refresh.as_deref(), Some(client.persisted[0].as_str()));
    // The access token is kept: the next run does not refresh
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.persisted.len(), 1);
    // Without it, it does, once, from the token kept
    client.access = None;
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.persisted.len(), 2);
    assert_ne!(client.persisted[1], client.persisted[0]);
}

#[test]
fn a_replayed_refresh_token_ends_the_run_and_the_session() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let spent = client.connection.refresh.clone().unwrap();
    assert_clean(&client.sync(&mut fake).problem);
    // Another copy of the connection, with the token it had before, runs again
    client.connection.refresh = Some(spent);
    client.access = None;
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Kemlock(word::SESSION_ENDED)));
    assert_eq!(fake.session_count(EMAIL), 0);
    // And the session of the right token is over too: sign in again
    client.connection.refresh = Some(client.persisted[0].clone());
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::SESSION_ENDED)));
}

#[test]
fn a_server_that_ends_the_session_is_said_so_whatever_its_reason() {
    for reason in ["refresh-token-reuse", "security-stamp-changed"] {
        let mut fake = server();
        let mut client = Client::connect(&mut fake, EMAIL);
        fake.attack(Attack::SessionEnds(reason));
        let outcome = client.sync(&mut fake);
        assert_eq!(outcome.problem, Some(Problem::Kemlock(word::SESSION_ENDED)), "{reason}");
        assert!(!outcome.problem.as_ref().unwrap().passes(), "a person has to connect again");
    }
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    assert_clean(&client.sync(&mut fake).problem);
    fake.change_security_stamp(EMAIL);
    client.access = None;
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::Kemlock(word::SESSION_ENDED)));
}

#[test]
fn an_access_token_that_ran_out_is_renewed_once_and_a_dead_login_asks_the_person() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    assert_clean(&client.sync(&mut fake).problem);
    let renewals = client.persisted.len();
    // The server stopped honouring the token this client still thinks is good
    fake.expire_access_tokens();
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(client.persisted.len(), renewals + 1);
    // A refresh token nobody issued: the login is over, and the person is asked
    client.connection.refresh = Some("rt.never-issued".into());
    client.access = None;
    assert_eq!(client.sync(&mut fake).problem, Some(Problem::LoginExpired));
}

#[test]
fn signing_out_forgets_the_device_and_its_refresh_token_but_not_the_access_token_yet() {
    let mut fake = server();
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
    let address = fake.server();
    let mut api = KemApi::new(&mut fake, &address, &key);
    api.access = Some(done.tokens.access.clone());
    let devices = api.devices().ok().unwrap();
    assert_eq!(devices["devices"][0]["name"], "Amethystora Vault");
    assert_eq!(devices["devices"][0]["kind"], "amethystora");
    assert_eq!(devices["devices"][0]["current"], true);
    assert!(api.sign_out(&done.tokens.device_id).is_ok());
    // The same call again: the device is not the account's any more, which is not an error to a client that signs out
    assert!(api.sign_out(&done.tokens.device_id).is_ok());
    assert_eq!(api.devices().ok().unwrap()["devices"].as_array().unwrap().len(), 0);
    assert_eq!(api.refresh(done.tokens.refresh.as_str()).err(), Some(Problem::LoginExpired));
}

#[test]
fn a_refresh_token_the_service_could_not_keep_is_the_one_the_run_hands_back_not_the_spent_one() {
    let mut fake = server();
    let mut client = Client::connect(&mut fake, EMAIL);
    let spent = client.connection.refresh.clone().unwrap();
    client.put("password", PASSWORD_ID, with_id(password("A", "u", "p", "https://a.example"), PASSWORD_ID));
    // The vault closes between the server's answer and the keeping of it: the new token is all there is of the session
    client.refuse_persist = true;
    let outcome = client.sync(&mut fake);
    assert_eq!(outcome.problem, Some(Problem::Net(NetFailure::Cancelled)));
    let new = client.persisted.last().cloned().unwrap();
    assert_ne!(new, spent);
    assert_eq!(client.connection.refresh.as_deref(), Some(new.as_str()), "the connection ends up holding the new token, never the spent one");
    // The next run goes on from it: the session is alive
    client.refuse_persist = false;
    assert_clean(&client.sync(&mut fake).problem);
    assert_eq!(fake.session_count(EMAIL), 1);
}
