//! Signing in (`spec-protocol.md` 2): a Kemlock-only account by OPAQUE, a Compatible one through the Bitwarden hash once, the no-downgrade
//! record, the second steps, the Argon2id bounds and the person's confirmation, and the account's keys opened and checked.

use serde_json::Value;

use super::common::*;
use crate::kemlock::conv::b64_decode;
use crate::kemlock::master::{self, Confirm, DEFAULT_PARAMS, KdfParams};
use crate::kemlock::sync::dpop::DpopKey;
use crate::kemlock::sync::fake::{self, Attack, BASE, EMAIL_CODE, FakeKemlock, RECOVERY_CODE, TOTP_CODE};
use crate::kemlock::sync::signin::{self, Attempt, Step, confirm_token, finish_email};
use crate::kemlock::sync::word;
use crate::sync::api::Problem;
use crate::sync::crypto::KdfProblem;

fn compatible() -> FakeKemlock {
    let mut fake = FakeKemlock::new(BASE);
    fake.make_compatible_account(EMAIL, PASSWORD);
    fake
}

fn totp(code: &str) -> impl FnOnce(&mut Tweak) + '_ {
    move |t| t.second = Some(("totp".into(), code.into()))
}

/// A sign-in that must not derive a key: the settings were refused before any work
fn refuses_before_deriving(fake: &mut FakeKemlock, tweak: impl FnOnce(&mut Tweak)) -> Problem {
    let address = fake.server();
    let key = DpopKey::generate();
    let mut tweaked = Tweak::default();
    tweak(&mut tweaked);
    let attempt = tweaked.attempt(&address, EMAIL, PASSWORD, &key);
    match signin::sign_in(fake, &attempt, &|_, _, _| panic!("a key was made under settings that were refused"), &fake::bitwarden_derive) {
        Err(problem) => problem,
        Ok(_) => panic!("signed in"),
    }
}

fn everything_sent(fake: &FakeKemlock) -> String {
    fake.seen.iter().map(|seen| format!("{} {} {}\n", seen.method, seen.url, seen.body)).collect()
}

fn jwk_x(proof: &str) -> String {
    let header: Value = serde_json::from_slice(&b64_decode(proof.split('.').next().unwrap()).unwrap()).unwrap();
    header["jwk"]["x"].as_str().unwrap().to_string()
}

// --- Kemlock-only ---------------------------------------------------------------------------------------------------------------

#[test]
fn a_kemlock_only_account_signs_in_by_opaque_and_opens_its_keys() {
    let mut fake = server();
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
    assert!(!done.enrolled);
    assert!(done.state.opaque_seen, "OPAQUE worked: the Bitwarden route is closed from now on");
    assert_eq!(done.state.key_version, 1);
    assert_eq!(done.state.params(), DEFAULT_PARAMS);
    assert_eq!(done.state.dpop_key, key.to_hex().as_str());
    assert_eq!(done.state.device_id, done.tokens.device_id);
    let account = fake.account(EMAIL);
    assert_eq!(done.root.as_bytes(), account.root.as_ref().unwrap().as_bytes(), "the root key the wrap held");
    assert_eq!(done.tokens.user_id, account.id.to_string());
    assert_eq!(done.state.public_bundle, crate::kemlock::conv::b64_encode(&account.public_bundle));
    assert!(done.nonce.is_some());
    // The device is named for what it is
    assert_eq!(account.devices.len(), 1);
    assert_eq!((account.devices[0].name.as_str(), account.devices[0].kind.as_str()), ("Amethystora Vault", "amethystora"));
    // The password and its Bitwarden hash never went anywhere, and neither did the Bitwarden API
    let sent = everything_sent(&fake);
    assert!(!sent.contains(PASSWORD) && !sent.contains("masterPasswordHash") && !sent.contains("/identity"));
    // Every call that needs a proof carried one, all under one key
    let proofs: Vec<String> = fake.seen.iter().filter_map(|seen| seen.header("dpop").map(jwk_x)).collect();
    assert!(proofs.len() >= 3 && proofs.iter().all(|x| *x == proofs[0]));
    // The opened account signs and unseals what a run needs
    let keys = fake.account(EMAIL).keys();
    assert_eq!(keys.key_version, 1);
}

#[test]
fn a_second_sign_in_is_the_same_device_and_the_bitwarden_identifier_joins_the_row() {
    let mut fake = server();
    let first = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}));
    let id = first.tokens.device_id.clone();
    let again = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.device_id = Some(id.clone())));
    assert_eq!(again.tokens.device_id, id);
    assert_eq!(fake.account(EMAIL).devices.len(), 1);
    // One row on both APIs when the connection used the Bitwarden one too; the id is then ignored
    let joined = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.bitwarden_device = Some("bw-device-1".into())));
    assert_eq!(fake.account(EMAIL).devices.iter().filter(|d| d.bitwarden.as_deref() == Some("bw-device-1")).count(), 1);
    let again = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.bitwarden_device = Some("bw-device-1".into())));
    assert_eq!(again.tokens.device_id, joined.tokens.device_id);
    assert_eq!(joined.state.bitwarden_device.as_deref(), Some("bw-device-1"));
}

#[test]
fn a_wrong_password_is_not_told_from_a_server_that_is_not_the_one_set_up() {
    let mut fake = server();
    let attempted = sign(&mut fake, EMAIL, "not the password", &DpopKey::generate(), |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert_eq!(fake.account(EMAIL).bitwarden_hash_received, 0);
    // An email the server does not know is answered the same way
    let attempted = sign(&mut fake, "nobody@example.test", PASSWORD, &DpopKey::generate(), |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
}

#[test]
fn a_vault_that_saw_opaque_work_never_sends_the_bitwarden_hash() {
    let mut fake = compatible();
    fake.seen.clear();
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.opaque_seen = true);
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert_eq!(fake.account(EMAIL).bitwarden_hash_received, 0);
    let sent = everything_sent(&fake);
    assert!(!sent.contains("/identity") && !sent.contains("bitwarden"), "{sent}");
    // Nor does a server that does not offer the route
    let mut fake = compatible();
    fake.features.retain(|feature| feature != "bitwarden-enrol");
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert!(!everything_sent(&fake).contains("masterPasswordHash"));
}

// --- A Compatible account ------------------------------------------------------------------------------------------------------

#[test]
fn a_compatible_account_is_enrolled_once_with_the_bitwarden_hash_and_keeps_its_key() {
    let mut fake = compatible();
    assert_eq!(fake.account(EMAIL).key_version, 0);
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}));
    assert!(done.enrolled && done.state.opaque_seen);
    let account = fake.account(EMAIL);
    assert_eq!(account.bitwarden_hash_received, 1, "the hash went once");
    assert_eq!(account.key_version, 1);
    // The Kemlock keys are made around the key the account already had: the same 64 bytes open both
    assert_eq!(done.root.as_bytes(), account.bw.as_ref().unwrap().user.bytes());
    assert_eq!(done.root.as_bytes(), account.root.as_ref().unwrap().as_bytes());
    assert_eq!(account.kdf, DEFAULT_PARAMS);
    assert_eq!(account.salt.len(), 16);
    account.keys();
    // One request of each, under one DPoP key, and what went to the Bitwarden API was its prelogin alone
    for part in ["/auth/bitwarden/start", "/auth/bitwarden/finish"] {
        assert_eq!(fake.requests_to(part), 1, "{part}");
    }
    assert_eq!(fake.requests_to("/identity/"), 1);
    let proofs: Vec<String> = fake.seen.iter().filter_map(|seen| seen.header("dpop").map(jwk_x)).collect();
    assert!(proofs.iter().all(|x| *x == proofs[0]));
    // The master password itself is never sent, only its Bitwarden hash
    assert!(!everything_sent(&fake).contains(PASSWORD));
    // The next sign-in, from another device, is OPAQUE's and sends nothing to Bitwarden
    let seen_before = fake.seen.len();
    let next = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}));
    assert!(!next.enrolled);
    assert_eq!(fake.account(EMAIL).bitwarden_hash_received, 1);
    assert!(fake.seen[seen_before..].iter().all(|seen| !seen.path().contains("/identity") && !seen.path().contains("bitwarden")));
}

#[test]
fn a_wrong_password_against_an_enrolled_account_is_refused_and_the_hash_of_it_is_the_only_thing_sent() {
    let mut fake = compatible();
    connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}));
    let attempted = sign(&mut fake, EMAIL, "not the password", &DpopKey::generate(), |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::WRONG_PASSWORD_OR_SERVER)));
    assert_eq!(fake.account(EMAIL).bitwarden_hash_received, 2);
}

#[test]
fn a_compatible_account_with_an_authenticator_needs_its_code_and_then_the_next_one() {
    let mut fake = compatible();
    fake.require_totp(EMAIL, TOTP_CODE);
    let key = DpopKey::generate();
    // No code given: the person is asked (an authenticator, 0)
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}).err(), Some(Problem::TwoFactor(vec![0])));
    assert_eq!(fake.account(EMAIL).key_version, 0, "nothing enrolled without it");
    // A wrong code refuses the enrolment and enrols nothing
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp("000000")).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    assert_eq!(fake.account(EMAIL).key_version, 0);
    // The right one enrols; the sign-in after it asks for a second step again, and a code is used once, so the person gives the next
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp(TOTP_CODE)).err(), Some(Problem::TwoFactor(vec![0])));
    assert_eq!(fake.account(EMAIL).key_version, 1, "enrolled");
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp(TOTP_CODE)).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)), "a code is single use");
    fake.require_totp(EMAIL, "654321");
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, totp("654321")));
    assert!(done.state.opaque_seen);
}

#[test]
fn a_compatible_account_whose_only_second_step_is_a_security_key_cannot_be_enrolled_here() {
    let mut fake = compatible();
    fake.account_mut(EMAIL).bw_two_factor = Some(vec!["webauthn".into()]);
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {});
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::ENROL_NEEDS_TOTP)));
    assert_eq!(fake.account(EMAIL).key_version, 0);
    assert_eq!(fake.requests_to("/auth/bitwarden/finish"), 0);
}

// --- Second steps ---------------------------------------------------------------------------------------------------------------

#[test]
fn an_authenticator_code_is_asked_given_and_used_once() {
    let mut fake = server();
    fake.require_totp(EMAIL, TOTP_CODE);
    let key = DpopKey::generate();
    // Authenticator (0) and the recovery code (8, which the server takes whatever the account has)
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}).err(), Some(Problem::TwoFactor(vec![0, 8])));
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp("000000")).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, totp(TOTP_CODE)));
    assert_eq!(done.state.key_version, 1);
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp(TOTP_CODE)).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    // A method this client does not do
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.second = Some(("webauthn".into(), "x".into())));
    assert_eq!(attempted.err(), Some(Problem::Unsupported));
}

#[test]
fn too_many_wrong_codes_are_a_rate_limit_not_another_refusal() {
    let mut fake = server();
    fake.require_totp(EMAIL, TOTP_CODE);
    let key = DpopKey::generate();
    for _ in 0..5 {
        assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, totp("000000")).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    }
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, totp(TOTP_CODE));
    assert_eq!(attempted.err(), Some(Problem::RateLimited));
}

#[test]
fn the_codes_email_is_asked_for_kept_for_five_minutes_and_given() {
    let mut fake = server();
    fake.require_email_code(EMAIL, EMAIL_CODE);
    let key = DpopKey::generate();
    // Asked: the person chooses an email (1) or a recovery code (8)
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &key, |_| {}).err(), Some(Problem::TwoFactor(vec![1, 8])));
    // A code before one was sent is no code
    let attempted = sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.second = Some(("email".into(), EMAIL_CODE.into())));
    assert_eq!(attempted.err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    // Sent: what the login holds comes back to be finished with the code
    let Ok(Step::EmailSent(pending)) = sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.send_email = true) else { panic!("an email was to be sent") };
    assert_eq!(fake.account(EMAIL).email_sent, 1);
    let address = fake.server();
    let done = match finish_email(&mut fake, &address, *pending, EMAIL_CODE, None) {
        Ok(Step::Connected(done)) => done,
        _ => panic!("not connected"),
    };
    assert_eq!(done.state.key_version, 1);
    assert_eq!(done.root.as_bytes(), fake.account(EMAIL).root.as_ref().unwrap().as_bytes());
    // A wrong code, and one kept too long
    let Ok(Step::EmailSent(pending)) = sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.send_email = true) else { panic!("sent") };
    assert_eq!(finish_email(&mut fake, &address, *pending, "000000", None).err(), Some(Problem::Kemlock(word::SECOND_STEP_REFUSED)));
    let Ok(Step::EmailSent(mut pending)) = sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.send_email = true) else { panic!("sent") };
    pending.born -= 6 * 60;
    assert_eq!(finish_email(&mut fake, &address, *pending, EMAIL_CODE, None).err(), Some(Problem::LoginExpired));
    assert_eq!(fake.account(EMAIL).email_sent, 3);
}

#[test]
fn a_recovery_code_signs_in_and_turns_every_second_step_off() {
    let mut fake = server();
    fake.require_totp(EMAIL, TOTP_CODE);
    let key = DpopKey::generate();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &key, |t| t.second = Some(("recovery".into(), RECOVERY_CODE.into()))));
    assert_eq!(done.state.key_version, 1);
    assert!(fake.account(EMAIL).totp.is_none() && fake.account(EMAIL).recovery.is_none());
    // The code is spent, and the account needs no second step now
    connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}));
}

// --- The Argon2id settings ------------------------------------------------------------------------------------------------------

#[test]
fn argon2_settings_outside_the_bounds_are_refused_before_any_key_is_made() {
    let cases = [
        ("memory under 16 MiB", KdfParams { memory_kib: 4096, iterations: 3, parallelism: 4 }, KdfProblem::TooWeak),
        ("one pass", KdfParams { memory_kib: 65_536, iterations: 1, parallelism: 4 }, KdfProblem::TooWeak),
        ("no lanes", KdfParams { memory_kib: 65_536, iterations: 3, parallelism: 0 }, KdfProblem::TooWeak),
        ("memory over 1 GiB", KdfParams { memory_kib: 2 * 1024 * 1024, iterations: 3, parallelism: 4 }, KdfProblem::TooStrong),
        ("eleven passes", KdfParams { memory_kib: 65_536, iterations: 11, parallelism: 4 }, KdfProblem::TooStrong),
        ("seventeen lanes", KdfParams { memory_kib: 65_536, iterations: 3, parallelism: 17 }, KdfProblem::TooStrong),
    ];
    for (why, params, problem) in cases {
        let mut fake = server();
        fake.attack(Attack::PreloginKdf { memory_kib: params.memory_kib, iterations: params.iterations, parallelism: params.parallelism });
        assert_eq!(refuses_before_deriving(&mut fake, |_| {}), Problem::Kdf(problem), "{why}");
        assert_eq!(fake.requests_to("opaque"), 0, "{why}: nothing derived from the password was sent");
    }
}

#[test]
fn settings_below_what_an_earlier_sign_in_saw_are_refused_whatever_the_bounds_say() {
    let mut fake = server();
    // Within the bounds, but cheaper than the account was: a server lowering the cost of guessing the password
    for (memory_kib, iterations, parallelism) in [(32_768, 3, 4), (65_536, 2, 4), (65_536, 3, 2)] {
        fake.clear_attacks();
        fake.attack(Attack::PreloginKdf { memory_kib, iterations, parallelism });
        let problem = refuses_before_deriving(&mut fake, |t| t.pinned = Some(DEFAULT_PARAMS));
        assert_eq!(problem, Problem::Kdf(KdfProblem::BelowPin), "{memory_kib} {iterations} {parallelism}");
    }
    // More than it was is taken (it costs the server's user, not the password)
    fake.clear_attacks();
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.pinned = Some(DEFAULT_PARAMS)));
    assert_eq!(done.state.params(), DEFAULT_PARAMS);
}

#[test]
fn settings_under_kemlocks_defaults_or_over_256_mib_are_confirmed_by_the_person_first() {
    // Weaker than the default (32 MiB): the numbers are shown, and the sign-in goes on only with the token of those numbers
    let mut fake = FakeKemlock::new(BASE);
    fake.make_account_with(EMAIL, PASSWORD, KdfParams { memory_kib: 32_768, iterations: 3, parallelism: 4 });
    assert_eq!(refuses_before_deriving(&mut fake, |_| {}), Problem::KdfWeakConfirm { memory: 32, iterations: 3 });
    let token = confirm_token(Confirm::Weak { memory_mib: 32, iterations: 3 });
    let wrong = confirm_token(Confirm::Weak { memory_mib: 32, iterations: 2 });
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.confirmed = Some(wrong)).err(), Some(Problem::KdfWeakConfirm { memory: 32, iterations: 3 }));
    let done = connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.confirmed = Some(token)));
    assert_eq!(done.state.kdf_memory_kib, 32_768);
    // Two passes at the default memory is weaker too
    let mut fake = FakeKemlock::new(BASE);
    fake.make_account_with(EMAIL, PASSWORD, KdfParams { memory_kib: 65_536, iterations: 2, parallelism: 4 });
    assert_eq!(refuses_before_deriving(&mut fake, |_| {}), Problem::KdfWeakConfirm { memory: 64, iterations: 2 });
    // Heavy: 512 MiB is a lot of memory for a program a server asked
    let mut fake = FakeKemlock::new(BASE);
    fake.make_account_with(EMAIL, PASSWORD, KdfParams { memory_kib: 512 * 1024, iterations: 3, parallelism: 4 });
    assert_eq!(refuses_before_deriving(&mut fake, |_| {}), Problem::KdfMemoryConfirm(512));
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.confirmed = Some(256)).err(), Some(Problem::KdfMemoryConfirm(512)));
    connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |t| t.confirmed = Some(confirm_token(Confirm::Heavy { memory_mib: 512 }))));
    // The default and 256 MiB exactly need no confirmation
    let mut fake = FakeKemlock::new(BASE);
    fake.make_account_with(EMAIL, PASSWORD, KdfParams { memory_kib: 256 * 1024, iterations: 3, parallelism: 4 });
    connected(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}));
}

#[test]
fn the_bounds_and_the_confirmation_are_one_set_of_numbers() {
    let p = |memory_kib, iterations, parallelism| KdfParams { memory_kib, iterations, parallelism };
    assert!(p(16 * 1024, 2, 1).check().is_ok() && p(1024 * 1024, 10, 16).check().is_ok());
    for bad in [p(16 * 1024 - 1, 3, 4), p(1024 * 1024 + 1, 3, 4), p(65_536, 1, 4), p(65_536, 11, 4), p(65_536, 3, 0), p(65_536, 3, 17)] {
        assert!(bad.check().is_err(), "{bad:?}");
    }
    assert_eq!(DEFAULT_PARAMS.confirm(), None);
    assert_eq!(p(256 * 1024, 3, 4).confirm(), None);
    assert_eq!(p(512 * 1024, 3, 4).confirm(), Some(Confirm::Heavy { memory_mib: 512 }));
    assert_eq!(p(32_768, 3, 4).confirm(), Some(Confirm::Weak { memory_mib: 32, iterations: 3 }));
    assert_eq!(p(65_536, 2, 4).confirm(), Some(Confirm::Weak { memory_mib: 64, iterations: 2 }));
    assert!(p(32_768, 3, 4).below(&DEFAULT_PARAMS) && p(65_536, 2, 4).below(&DEFAULT_PARAMS) && p(65_536, 3, 3).below(&DEFAULT_PARAMS));
    assert!(!p(65_536, 3, 4).below(&DEFAULT_PARAMS) && !p(131_072, 4, 8).below(&DEFAULT_PARAMS));
    // A token names its numbers: the same settings the same token, another pass another one, and a heavy key's is not a weak one's
    assert_eq!(confirm_token(Confirm::Weak { memory_mib: 32, iterations: 3 }), confirm_token(Confirm::Weak { memory_mib: 32, iterations: 3 }));
    assert_ne!(confirm_token(Confirm::Weak { memory_mib: 32, iterations: 3 }), confirm_token(Confirm::Weak { memory_mib: 32, iterations: 4 }));
    assert_ne!(confirm_token(Confirm::Weak { memory_mib: 512, iterations: 2 }), confirm_token(Confirm::Heavy { memory_mib: 512 }));
    // The key itself is made only inside the bounds, and the salt is 16 to 64 bytes
    assert!(master::master_key("pw", &[0u8; 16], &p(4096, 3, 4)).is_err());
    assert!(master::master_key("pw", &[0u8; 8], &DEFAULT_PARAMS).is_err());
}

#[test]
fn the_real_argon2id_signs_in_too() {
    let mut fake = FakeKemlock::new(BASE);
    fake.real_argon2 = true;
    fake.make_account(EMAIL, PASSWORD);
    let address = fake.server();
    let key = DpopKey::generate();
    let real = |password: &str, salt: &[u8], params: &KdfParams| master::master_key(password, salt, params).map_err(|_| Problem::BadResponse);
    let attempt = Attempt { server: &address, email: EMAIL, password: PASSWORD, confirmed: None, second: None, send_email: false, pinned: None, device_id: None, bitwarden_device: None, opaque_seen: false, dpop: &key };
    let done = match signin::sign_in(&mut fake, &attempt, &real, &fake::bitwarden_derive) {
        Ok(Step::Connected(done)) => done,
        _ => panic!("not connected"),
    };
    assert_eq!(done.root.as_bytes(), fake.account(EMAIL).root.as_ref().unwrap().as_bytes());
}

// --- The account's keys ------------------------------------------------------------------------------------------------------------

#[test]
fn keys_the_server_hands_over_that_do_not_check_out_are_never_taken() {
    // A bundle that is not signed by its own key
    let mut fake = server();
    fake.account_mut(EMAIL).public_bundle[40] ^= 1;
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}).err(), Some(Problem::Kemlock(word::KEYS_INVALID)));
    // Private keys that are not the bundle's (another account's, sealed under the same root)
    let mut fake = server();
    let mut other = FakeKemlock::new(BASE);
    other.make_account(EMAIL, PASSWORD);
    let (wrapped, root) = (fake.account(EMAIL).wrapped_root_key.clone(), fake.account(EMAIL).root.clone());
    fake.account_mut(EMAIL).sealed_private_keys = other.account(EMAIL).sealed_private_keys.clone();
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}).err(), Some(Problem::Kemlock(word::KEYS_INVALID)));
    let _ = (wrapped, root);
    // A wrap that does not open under the password
    let mut fake = server();
    let last = fake.account(EMAIL).wrapped_root_key.len() - 1;
    fake.account_mut(EMAIL).wrapped_root_key[last] ^= 1;
    assert_eq!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}).err(), Some(Problem::CannotOpen));
    // A key version of zero (an account with no Kemlock keys) is not one this answers
    let mut fake = server();
    fake.account_mut(EMAIL).key_version = 0;
    assert!(sign(&mut fake, EMAIL, PASSWORD, &DpopKey::generate(), |_| {}).is_err());
}
