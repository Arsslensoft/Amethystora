//! `aead1`: AES-256-GCM with a 12-byte random nonce and a 16-byte tag. A sealed value is `nonce(12) ‖ ciphertext ‖ tag(16)`
//! (`crypto.md`, "Conventions"). Also HKDF-SHA256, which every key here comes from.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::{Error, Result, Secret};

pub const NONCE: usize = 12;
pub const TAG: usize = 16;
/// The smallest sealed value: a nonce and a tag around nothing (the server's own floor)
pub const MIN_SEALED: usize = NONCE + TAG;

/// A fresh random nonce, then the ciphertext and tag
pub fn seal(key: &[u8; 32], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let nonce: [u8; NONCE] = crate::seal::random_array();
    seal_with_nonce(key, &nonce, plain, aad)
}

/// With the nonce given: for the vectors, which carry the nonce of every sealed value
pub fn seal_with_nonce(key: &[u8; 32], nonce: &[u8; NONCE], plain: &[u8], aad: &[u8]) -> Vec<u8> {
    let cipher = Aes256Gcm::new_from_slice(key).expect("a 256-bit key");
    let iv = Nonce::try_from(&nonce[..]).expect("a 96-bit nonce");
    let sealed = cipher.encrypt(&iv, Payload { msg: plain, aad }).expect("AES-GCM seals anything that fits in memory");
    let mut out = Vec::with_capacity(NONCE + sealed.len());
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    out
}

/// Opens `nonce ‖ ciphertext ‖ tag`. A value shorter than a nonce and a tag is refused before anything is decrypted.
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() < MIN_SEALED {
        return Err(Error::Malformed("a sealed value is at least 28 bytes"));
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| Error::Unopened)?;
    let iv = Nonce::try_from(&sealed[..NONCE]).map_err(|_| Error::Unopened)?;
    cipher.decrypt(&iv, Payload { msg: &sealed[NONCE..], aad }).map(Zeroizing::new).map_err(|_| Error::Unopened)
}

/// HKDF-SHA256 with an absent salt (32 zero bytes, as RFC 5869 says): `N` bytes under `info`
pub fn hkdf<const N: usize>(ikm: &[u8], info: &[u8]) -> Secret<N> {
    Secret::build(|out| Hkdf::<Sha256>::new(None, ikm).expand(info, &mut out[..]).expect("N is far below 255 hashes"))
}
