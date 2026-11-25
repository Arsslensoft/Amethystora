//! The account's keys (`crypto.md`, "Account keys"): the root key, the Kemlock user key and its labelled children, the
//! password wrap of the root key, and the account's sealed private keys.

use zeroize::Zeroizing;

use super::aead::{self, hkdf};
use super::conv::Uuid;
use super::kx1::{self, Kx1PrivateKey};
use super::sig1::{self, Sig1PrivateKey};
use super::{Error, Key, Result, RootKey};

pub const LABEL_USER: &str = "kemlock/v1/user";
pub const LABEL_PASSWORD_WRAP: &str = "kemlock/v1/password-wrap";
const LABEL_ROOT_WRAP: &str = "kemlock/v1/root-wrap";
const LABEL_PRIVATE_KEYS: &str = "kemlock/v1/private-keys";

/// The children of the user key, each under its own label
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Child {
    /// Wraps the item keys of the owner
    ItemWrap,
    /// Seals the account's exchange and signing private keys
    PrivateKeys,
    /// Reserved for the signed manifest's MAC-less parts
    Manifest,
}

impl Child {
    pub fn label(self) -> &'static str {
        match self {
            Child::ItemWrap => "kemlock/v1/item-wrap",
            Child::PrivateKeys => LABEL_PRIVATE_KEYS,
            Child::Manifest => "kemlock/v1/manifest",
        }
    }
}

/// `HKDF(ikm = root, salt = absent, info = "kemlock/v1/user", L = 32)`
pub fn user_key(root: &RootKey) -> Key {
    hkdf(root.as_bytes(), LABEL_USER.as_bytes())
}

/// `HKDF(ikm = user key, salt = absent, info = label, L = 32)`
pub fn child_key(user: &Key, child: Child) -> Key {
    hkdf(user.as_bytes(), child.label().as_bytes())
}

/// The wrap key of the root key: `HKDF(ikm = master key ‖ OPAQUE export key, info = "kemlock/v1/password-wrap", L = 32)`.
/// Neither the master key nor the export key alone opens the wrap.
pub fn password_wrap_key(master: &Key, export_key: &[u8; 64]) -> Key {
    let mut ikm = Zeroizing::new(Vec::with_capacity(96));
    ikm.extend_from_slice(master.as_bytes());
    ikm.extend_from_slice(export_key);
    hkdf(&ikm, LABEL_PASSWORD_WRAP.as_bytes())
}

/// `"kemlock/v1/root-wrap" ‖ account id (16) ‖ u32be(key version)`
pub fn root_wrap_aad(account: &Uuid, key_version: u32) -> Vec<u8> {
    let mut aad = LABEL_ROOT_WRAP.as_bytes().to_vec();
    aad.extend_from_slice(account.as_bytes());
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

/// The wrapped root key's length: nonce, 64 bytes, tag
pub const WRAPPED_ROOT_KEY: usize = aead::NONCE + 64 + aead::TAG;

/// Wraps the root key under the password wrap key: `nonce(12) ‖ ciphertext(64) ‖ tag(16)`
pub fn wrap_root_key(root: &RootKey, wrap_key: &Key, account: &Uuid, key_version: u32) -> Vec<u8> {
    aead::seal(wrap_key.as_bytes(), root.as_bytes(), &root_wrap_aad(account, key_version))
}

/// With the nonce given: for the vectors
#[cfg(test)]
pub(crate) fn wrap_root_key_with_nonce(root: &RootKey, wrap_key: &Key, nonce: &[u8; 12], account: &Uuid, key_version: u32) -> Vec<u8> {
    aead::seal_with_nonce(wrap_key.as_bytes(), nonce, root.as_bytes(), &root_wrap_aad(account, key_version))
}

pub fn unwrap_root_key(wrapped: &[u8], wrap_key: &Key, account: &Uuid, key_version: u32) -> Result<RootKey> {
    if wrapped.len() != WRAPPED_ROOT_KEY {
        return Err(Error::Malformed("a wrapped root key is 92 bytes"));
    }
    let plain = aead::open(wrap_key.as_bytes(), wrapped, &root_wrap_aad(account, key_version))?;
    RootKey::from_slice(&plain).ok_or(Error::Unopened)
}

/// The account's two private keys
#[derive(Clone, Debug)]
pub struct PrivateKeys {
    pub kx1: Kx1PrivateKey,
    pub sig1: Sig1PrivateKey,
}

/// `u8(1) ‖ kx1 private key (96) ‖ sig1 private key (64)`
const PRIVATE_KEYS_PLAIN: usize = 1 + kx1::PRIVATE_KEY + sig1::PRIVATE_KEY;
/// The sealed private keys' length: nonce, 161 bytes, tag
pub const SEALED_PRIVATE_KEYS: usize = aead::NONCE + PRIVATE_KEYS_PLAIN + aead::TAG;

impl PrivateKeys {
    pub fn generate() -> PrivateKeys {
        PrivateKeys { kx1: Kx1PrivateKey::generate(), sig1: Sig1PrivateKey::generate() }
    }

    /// Sealed under the user key's `private-keys` child; the aad is
    /// `"kemlock/v1/private-keys" ‖ account id (16) ‖ u32be(key version)`, the key version being the bundle's
    pub fn seal(&self, user: &Key, account: &Uuid, key_version: u32) -> Vec<u8> {
        aead::seal(child_key(user, Child::PrivateKeys).as_bytes(), &self.plain(), &private_keys_aad(account, key_version))
    }

    #[cfg(test)]
    pub(crate) fn seal_with_nonce(&self, user: &Key, nonce: &[u8; 12], account: &Uuid, key_version: u32) -> Vec<u8> {
        aead::seal_with_nonce(child_key(user, Child::PrivateKeys).as_bytes(), nonce, &self.plain(), &private_keys_aad(account, key_version))
    }

    fn plain(&self) -> Zeroizing<Vec<u8>> {
        let mut plain = Zeroizing::new(Vec::with_capacity(PRIVATE_KEYS_PLAIN));
        plain.push(1);
        plain.extend_from_slice(self.kx1.as_bytes());
        plain.extend_from_slice(self.sig1.as_bytes());
        plain
    }

    pub fn open(sealed: &[u8], user: &Key, account: &Uuid, key_version: u32) -> Result<PrivateKeys> {
        if sealed.len() != SEALED_PRIVATE_KEYS {
            return Err(Error::Malformed("sealed private keys are 189 bytes"));
        }
        let plain = aead::open(child_key(user, Child::PrivateKeys).as_bytes(), sealed, &private_keys_aad(account, key_version))?;
        if plain.len() != PRIVATE_KEYS_PLAIN || plain[0] != 1 {
            return Err(Error::Malformed("an unknown private keys version"));
        }
        Ok(PrivateKeys {
            kx1: Kx1PrivateKey::from_bytes(&plain[1..1 + kx1::PRIVATE_KEY])?,
            sig1: Sig1PrivateKey::from_bytes(&plain[1 + kx1::PRIVATE_KEY..])?,
        })
    }
}

fn private_keys_aad(account: &Uuid, key_version: u32) -> Vec<u8> {
    let mut aad = LABEL_PRIVATE_KEYS.as_bytes().to_vec();
    aad.extend_from_slice(account.as_bytes());
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}
