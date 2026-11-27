//! The sealed box (`crypto.md`, "`kx1` / Sealed box"): a short secret sealed to an exchange public key under a context
//! label.
//!
//! ```text
//! (ct, ss) = kx1.Encaps(pk)
//! key      = HKDF(ikm = ss, salt = absent, info = "kemlock/v1/seal" ‖ lp(context), L = 32)
//! box      = u8(1) ‖ ct (1600) ‖ AES-256-GCM(key, nonce, secret, aad = lp(context) ‖ lp(aad))
//! ```
//!
//! `aad` is the caller's extra binding and is not stored in the box.

use zeroize::Zeroizing;

use super::aead::{self, hkdf};
use super::conv::{Uuid, put_lp};
use super::kx1::{CIPHERTEXT, Kx1PrivateKey, Kx1PublicKey};
use super::{Error, Key, Result};

/// The context of the root key sealed to a new device's one-time key pair
pub const CONTEXT_DEVICE_APPROVAL: &str = "device-approval";
const SEAL_LABEL: &[u8] = b"kemlock/v1/seal";
/// What a box may hold. The format means a short secret, a key; a box that claims more is refused before it is opened.
pub const MAX_SECRET: usize = 4096;

/// `account id (16) ‖ approval request id (16)`, 32 bytes, so an answer cannot be replayed onto another request. The
/// account id must be the sealing account's own.
pub fn device_approval_aad(account: &Uuid, request: &Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(32);
    aad.extend_from_slice(account.as_bytes());
    aad.extend_from_slice(request.as_bytes());
    aad
}

fn box_key(shared: &Key, context: &str) -> Key {
    let mut info = SEAL_LABEL.to_vec();
    put_lp(&mut info, context.as_bytes());
    hkdf(shared.as_bytes(), &info)
}

fn box_aad(context: &str, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len() + aad.len());
    put_lp(&mut out, context.as_bytes());
    put_lp(&mut out, aad);
    out
}

pub fn seal(recipient: &Kx1PublicKey, context: &str, aad: &[u8], secret: &[u8]) -> Result<Vec<u8>> {
    if secret.len() > MAX_SECRET {
        return Err(Error::Refused("a sealed box holds a short secret"));
    }
    let (ct, shared) = recipient.encapsulate()?;
    Ok(finish(ct, &shared, context, aad, secret, None))
}

/// With the nonce given and the key exchange done: for the vectors
#[cfg(test)]
pub(crate) fn seal_with(ct: Vec<u8>, shared: &Key, nonce: &[u8; 12], context: &str, aad: &[u8], secret: &[u8]) -> Vec<u8> {
    finish(ct, shared, context, aad, secret, Some(nonce))
}

fn finish(ct: Vec<u8>, shared: &Key, context: &str, aad: &[u8], secret: &[u8], nonce: Option<&[u8; 12]>) -> Vec<u8> {
    let key = box_key(shared, context);
    let aad = box_aad(context, aad);
    let sealed = match nonce {
        Some(nonce) => aead::seal_with_nonce(key.as_bytes(), nonce, secret, &aad),
        None => aead::seal(key.as_bytes(), secret, &aad),
    };
    let mut out = Vec::with_capacity(1 + ct.len() + sealed.len());
    out.push(1);
    out.extend_from_slice(&ct);
    out.extend_from_slice(&sealed);
    out
}

/// Opens a box. Under another context or aad, or with another key, it fails, and says no more than that.
pub fn open(key: &Kx1PrivateKey, context: &str, aad: &[u8], boxed: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if boxed.len() < 1 + CIPHERTEXT + aead::MIN_SEALED || boxed.len() > 1 + CIPHERTEXT + aead::MIN_SEALED + MAX_SECRET {
        return Err(Error::Malformed("a sealed box's length"));
    }
    if boxed[0] != 1 {
        return Err(Error::Malformed("an unknown sealed box version"));
    }
    let shared = key.decapsulate(&boxed[1..1 + CIPHERTEXT])?;
    aead::open(box_key(&shared, context).as_bytes(), &boxed[1 + CIPHERTEXT..], &box_aad(context, aad))
}
