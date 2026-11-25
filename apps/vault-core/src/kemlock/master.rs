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

/// The bounds a server's settings must be within: the Bitwarden side's, in one place (`sync::bounds`), so that a server is held to
/// the same numbers whichever API it answers on (plans/vault-kemlock, decision 8). Refused below 16 MiB or 2 passes and above 1 GiB,
/// 10 passes or 16 lanes.
pub const MIN_MEMORY_KIB: u32 = crate::sync::bounds::ARGON2_MIB.0 * 1024;
pub const MAX_MEMORY_KIB: u32 = crate::sync::bounds::ARGON2_MIB.1 * 1024;
pub const MIN_ITERATIONS: u32 = crate::sync::bounds::ARGON2_PASSES.0;
pub const MAX_ITERATIONS: u32 = crate::sync::bounds::ARGON2_PASSES.1;
pub const MAX_PARALLELISM: u32 = crate::sync::bounds::ARGON2_LANES.1;
/// The server keeps a random 16-byte salt; a salt of another length is refused rather than guessed at
pub const SALT_MIN: usize = 16;
pub const SALT_MAX: usize = 64;

/// What a person is shown, and has to agree to, before settings inside the bounds are used: below Kemlock's own default (64 MiB, 3
/// passes) a master password is easier to guess; above 256 MiB the work is a lot of memory, made in a program of its own that a
/// server asked for
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Confirm {
    /// Under the default: the memory in MiB and the passes
    Weak { memory_mib: u32, iterations: u32 },
    /// Over 256 MiB: the memory in MiB
    Heavy { memory_mib: u32 },
}

impl KdfParams {
    /// Refuses settings outside the bounds
    pub fn check(&self) -> Result<()> {
        if !(MIN_MEMORY_KIB..=MAX_MEMORY_KIB).contains(&self.memory_kib) {
            return Err(Error::Refused("the Argon2id memory is outside 16 MiB to 1 GiB"));
        }
        if !(MIN_ITERATIONS..=MAX_ITERATIONS).contains(&self.iterations) {
            return Err(Error::Refused("the Argon2id passes are outside 2 to 10"));
        }
        if !(1..=MAX_PARALLELISM).contains(&self.parallelism) {
            return Err(Error::Refused("the Argon2id lanes are outside 1 to 16"));
        }
        Ok(())
    }

    /// Whether the person has to say yes to these settings first: none that is not within the bounds gets this far
    pub fn confirm(&self) -> Option<Confirm> {
        let memory_mib = self.memory_kib / 1024;
        if self.memory_kib > crate::sync::bounds::ARGON2_CONFIRM_ABOVE_MIB * 1024 {
            Some(Confirm::Heavy { memory_mib })
        } else if self.memory_kib < DEFAULT_PARAMS.memory_kib || self.iterations < DEFAULT_PARAMS.iterations {
            Some(Confirm::Weak { memory_mib, iterations: self.iterations })
        } else {
            None
        }
    }

    /// Not lower than what an earlier sign-in saw (memory, passes and lanes each): a server that lowers them is making the
    /// password cheaper to guess
    pub fn below(&self, pinned: &KdfParams) -> bool {
        self.memory_kib < pinned.memory_kib || self.iterations < pinned.iterations || self.parallelism < pinned.parallelism
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
