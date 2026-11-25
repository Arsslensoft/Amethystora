//! The master key (`crypto.md`, "Account keys / Master key"): `Argon2id(password, salt, m, t, p, L = 32)`, version 0x13,
//! over the UTF-8 of the password's NFC form. The server hands out the settings, so they are held to bounds here: a
//! server must not be able to ask for a hash that is too weak to protect the password or too big to compute.

use argon2::{Algorithm, Argon2, Params, Version};
use zeroize::Zeroizing;

use super::{Error, Key, Result};

/// What a new account uses: 64 MiB, 3 passes, 4 lanes
pub const DEFAULT_PARAMS: KdfParams = KdfParams { memory_kib: 65_536, iterations: 3, parallelism: 4 };

/// Argon2id's settings: memory in KiB, passes, lanes
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
}

/// The bounds a server's settings must be within. The floor of memory is 19 MiB, the smallest cost OWASP calls enough
/// for Argon2id; the roof is 1 GiB, which a phone survives.
pub const MIN_MEMORY_KIB: u32 = 19_456;
pub const MAX_MEMORY_KIB: u32 = 1_048_576;
pub const MIN_ITERATIONS: u32 = 2;
pub const MAX_ITERATIONS: u32 = 16;
pub const MAX_PARALLELISM: u32 = 16;
/// The server keeps a random 16-byte salt; a salt of another length is refused rather than guessed at
pub const SALT_MIN: usize = 16;
pub const SALT_MAX: usize = 64;

impl KdfParams {
    /// Refuses settings outside the bounds
    pub fn check(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(Error::Refused("the Argon2id memory is outside 19 MiB to 1 GiB"));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::Refused("the Argon2id passes are outside 2 to 16"));
        }
        if !(1..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(Error::Refused("the Argon2id lanes are outside 1 to 16"));
        }
        Ok(())
    }
}

/// The password in its NFC form, as the bytes that are hashed
pub fn nfc(password: &str) -> Zeroizing<Vec<u8>> {
    let normal = icu_normalizer::ComposingNormalizerBorrowed::new_nfc().normalize(password);
    Zeroizing::new(normal.as_bytes().to_vec())
}

/// The master key from the typed password, the account's salt and the settings the server returned (checked first)
pub fn master_key(password: &str, salt: &[u8], params: &KdfParams) -> Result<Key> {
    params.check()?;
    if !(SALT_MIN..=SALT_MAX).contains(&salt.len()) {
        return Err(Error::Refused("the Argon2id salt is 16 to 64 bytes"));
    }
    derive(password, salt, params)
}

/// Without the bounds: the vectors use a few KiB, which no server may ask for
pub(crate) fn derive(password: &str, salt: &[u8], params: &KdfParams) -> Result<Key> {
    let params =
        Params::new(params.memory_kib, params.iterations, params.parallelism, Some(32)).map_err(|_| Error::Refused("Argon2id settings"))?;
    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let password = nfc(password);
    let mut failed = false;
    let key = Key::build(|out| failed = argon.hash_password_into(&password, salt, &mut out[..]).is_err());
    if failed { Err(Error::Refused("Argon2id settings")) } else { Ok(key) }
}
