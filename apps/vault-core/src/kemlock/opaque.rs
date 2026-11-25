//! `opaque1`, password sign-in (`crypto.md`, "`opaque1`: OPAQUE configuration"): the client's half of OPAQUE-3DH (RFC 9807)
//! with the configuration of its appendix C test vector 1, apart from the context:
//!
//! | Parameter | Value |
//! | --- | --- |
//! | OPRF, key exchange group | ristretto255-SHA512, ristretto255 |
//! | KDF, MAC, hash | HKDF-SHA512, HMAC-SHA512, SHA-512 |
//! | KSF | Identity |
//! | Context | `"kemlock/v1/opaque"` |
//! | Client and server identity | none (the public keys) |
//! | Password input | the 32-byte Argon2id master key, not the typed password |
//!
//! The server derives the OPRF key from the credential identifier (the email, trimmed and lower-cased), so the client never
//! needs it; [`credential_identifier`] says what it is. The export key (64 bytes) and the session key (64 bytes) come out of
//! the protocol: the export key goes into the password wrap of the root key (`keys::password_wrap_key`).
//!
//! opaque-ke 4 is on digest 0.10 and rand 0.8, so this file names its SHA-512 from `sha2` 0.10 and its random source as the
//! kernel's, behind rand 0.8's traits.

use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse,
    Identifiers, RegistrationResponse, Ristretto255, TripleDh,
};

use super::{Error, Key, Result, Secret};

/// The context both sides agree on, which the key exchange binds
pub const CONTEXT: &[u8] = b"kemlock/v1/opaque";
pub const REGISTRATION_REQUEST: usize = 32;
pub const REGISTRATION_RESPONSE: usize = 64;
pub const REGISTRATION_UPLOAD: usize = 192;
pub const KE1: usize = 96;
pub const KE2: usize = 320;
pub const KE3: usize = 64;

pub(crate) struct Suite;

impl CipherSuite for Suite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, sha2_010::Sha512>;
    type Ksf = opaque_ke::ksf::Identity;
}

/// The credential identifier the server keys the account by: the email, trimmed and lower-cased, as UTF-8
pub fn credential_identifier(email: &str) -> String {
    email.trim().to_lowercase()
}

/// The kernel's random bytes, behind the traits opaque-ke asks for
pub(crate) struct Kernel;

impl RngCore for Kernel {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        crate::seal::random(&mut b);
        u32::from_le_bytes(b)
    }

    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        crate::seal::random(&mut b);
        u64::from_le_bytes(b)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        crate::seal::random(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), RandError> {
        crate::seal::random(dest);
        Ok(())
    }
}

impl CryptoRng for Kernel {}

/// Registration after its first message: what the finish needs
pub struct RegistrationState(ClientRegistration<Suite>);

/// What registration gives: the upload to send, and the export key
pub struct Registered {
    pub upload: Vec<u8>,
    pub export_key: Secret<64>,
}

/// Login after its first message
pub struct LoginState(ClientLogin<Suite>);

/// What login gives: the final message to send, the export key and the session key
pub struct LoggedIn {
    pub ke3: Vec<u8>,
    pub export_key: Secret<64>,
    pub session_key: Secret<64>,
}

fn exactly(bytes: &[u8], len: usize) -> Result<()> {
    if bytes.len() == len { Ok(()) } else { Err(Error::Malformed("an OPAQUE message's length")) }
}

fn secret64(bytes: &[u8]) -> Secret<64> {
    Secret::build(|out| out.copy_from_slice(bytes))
}

/// The registration request (32 bytes) and the state to finish it with
pub fn registration_start(master_key: &Key) -> Result<(RegistrationState, Vec<u8>)> {
    registration_start_with(&mut Kernel, master_key)
}

pub(crate) fn registration_start_with<R: RngCore + CryptoRng>(rng: &mut R, master_key: &Key) -> Result<(RegistrationState, Vec<u8>)> {
    let start = ClientRegistration::<Suite>::start(rng, master_key.as_bytes()).map_err(|_| Error::Unopened)?;
    Ok((RegistrationState(start.state), start.message.serialize().to_vec()))
}

/// Finishes registration with the server's response (64 bytes): the upload (192 bytes) and the export key
pub fn registration_finish(state: RegistrationState, master_key: &Key, response: &[u8]) -> Result<Registered> {
    registration_finish_with(&mut Kernel, state, master_key, response)
}

pub(crate) fn registration_finish_with<R: RngCore + CryptoRng>(
    rng: &mut R,
    state: RegistrationState,
    master_key: &Key,
    response: &[u8],
) -> Result<Registered> {
    exactly(response, REGISTRATION_RESPONSE)?;
    let response = RegistrationResponse::<Suite>::deserialize(response).map_err(|_| Error::Malformed("an OPAQUE registration response"))?;
    let finish = state
        .0
        .finish(rng, master_key.as_bytes(), response, ClientRegistrationFinishParameters::new(Identifiers::default(), None))
        .map_err(|_| Error::Unopened)?;
    Ok(Registered { upload: finish.message.serialize().to_vec(), export_key: secret64(&finish.export_key) })
}

/// The first login message, KE1 (96 bytes), and the state to finish it with
pub fn login_start(master_key: &Key) -> Result<(LoginState, Vec<u8>)> {
    login_start_with(&mut Kernel, master_key)
}

pub(crate) fn login_start_with<R: RngCore + CryptoRng>(rng: &mut R, master_key: &Key) -> Result<(LoginState, Vec<u8>)> {
    let start = ClientLogin::<Suite>::start(rng, master_key.as_bytes()).map_err(|_| Error::Unopened)?;
    Ok((LoginState(start.state), start.message.serialize().to_vec()))
}

/// Finishes login with the server's KE2 (320 bytes). A wrong password, a server that does not hold the record, a changed
/// message and another context all fail the same way, as `Unopened`.
pub fn login_finish(state: LoginState, master_key: &Key, ke2: &[u8]) -> Result<LoggedIn> {
    login_finish_with(&mut Kernel, state, master_key, ke2)
}

pub(crate) fn login_finish_with<R: RngCore + CryptoRng>(rng: &mut R, state: LoginState, master_key: &Key, ke2: &[u8]) -> Result<LoggedIn> {
    exactly(ke2, KE2)?;
    let response = CredentialResponse::<Suite>::deserialize(ke2).map_err(|_| Error::Malformed("an OPAQUE KE2"))?;
    let finish = state
        .0
        .finish(rng, master_key.as_bytes(), response, ClientLoginFinishParameters::new(Some(CONTEXT), Identifiers::default(), None))
        .map_err(|_| Error::Unopened)?;
    Ok(LoggedIn {
        ke3: finish.message.serialize().to_vec(),
        export_key: secret64(&finish.export_key),
        session_key: secret64(&finish.session_key),
    })
}
