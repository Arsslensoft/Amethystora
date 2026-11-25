//! `KMA1`, the file format of attachments (`crypto.md`, "Sends / Files": the one place it is written down).
//!
//! ```text
//! "KMA1" ‖ nonce prefix (8 random bytes) ‖ chunk 0 ‖ chunk 1 ‖ … ‖ last chunk
//! chunk = AES-256-GCM(key, nonce = prefix ‖ u32be(counter), aad = 0x00, or 0x01 for the last chunk,
//!                     up to 65536 bytes of plaintext) ‖ tag(16)
//! ```
//!
//! The counter starts at 0. Every chunk but the last holds exactly 65,536 bytes of plaintext (65,552 sealed); the last
//! holds the rest, so a file ends in exactly one last chunk (which this writer leaves empty only for an empty file, and this reader accepts
//! empty after other chunks too: the length check of a size the server is told allows it). Reordered or cut chunks fail.
//! The file is `12 + plain + 16 × max(1, ⌈plain / 65536⌉)` bytes long.
//!
//! What `crypto.md` leaves unsaid, and this module settles: which key an attachment of an item is sealed under (the key is
//! the caller's: a Send's file uses the payload key), what a last chunk of exactly 65,536 bytes is (the last one, by the
//! length formula), a file whose length no plaintext makes (refused before anything is decrypted), and a size bound (the
//! caller's `max_plain`).

use zeroize::Zeroizing;

use super::aead::{self, TAG};
use super::{Error, Key, Result};

pub const MAGIC: &[u8; 4] = b"KMA1";
pub const HEADER: usize = 12;
pub const CHUNK: usize = 65_536;
const SEALED_CHUNK: usize = CHUNK + TAG;

/// The sealed file's length for a plaintext of `plain` bytes
pub fn sealed_len(plain: usize) -> usize {
    HEADER + plain + TAG * plain.div_ceil(CHUNK).max(1)
}

/// Encrypts `plain`, which may not be longer than `max_plain`
pub fn encrypt(key: &Key, plain: &[u8], max_plain: usize) -> Result<Vec<u8>> {
    let mut prefix = [0u8; 8];
    crate::seal::random(&mut prefix);
    encrypt_with_prefix(key, &prefix, plain, max_plain)
}

pub(crate) fn encrypt_with_prefix(key: &Key, prefix: &[u8; 8], plain: &[u8], max_plain: usize) -> Result<Vec<u8>> {
    if plain.len() > max_plain {
        return Err(Error::Refused("the file is longer than the limit"));
    }
    let chunks = plain.len().div_ceil(CHUNK).max(1);
    // A counter is a u32: far past any limit a caller sets, but the format ends there
    if u32::try_from(chunks).is_err() {
        return Err(Error::Refused("the file has more chunks than a counter counts"));
    }
    let mut out = Vec::with_capacity(sealed_len(plain.len()));
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(prefix);
    for counter in 0..chunks {
        let part = &plain[(counter * CHUNK).min(plain.len())..((counter + 1) * CHUNK).min(plain.len())];
        let last = counter + 1 == chunks;
        // The file's random prefix, then the chunk's counter, big-endian
        let c = (counter as u32).to_be_bytes();
        let p = prefix;
        let nonce = [p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7], c[0], c[1], c[2], c[3]];
        let sealed = aead::seal_with_nonce(key.as_bytes(), &nonce, part, &[u8::from(last)]);
        // The nonce is implied by the prefix and the counter, so it is not written again
        out.extend_from_slice(&sealed[12..]);
    }
    Ok(out)
}

/// Decrypts a file. The magic and the length are checked, and the plaintext's size against `max_plain`, before anything is
/// decrypted; a chunk cut, added, reordered or changed fails.
pub fn decrypt(key: &Key, file: &[u8], max_plain: usize) -> Result<Zeroizing<Vec<u8>>> {
    if file.len() < HEADER + TAG || &file[..4] != MAGIC {
        return Err(Error::Malformed("a KMA1 file starts with KMA1 and holds a chunk"));
    }
    let body = file.len() - HEADER;
    let chunks = body.div_ceil(SEALED_CHUNK);
    let last_len = body - (chunks - 1) * SEALED_CHUNK;
    // The last chunk is 16 to 65,552 bytes, as the server's own check of an announced size says: our writer never ends a
    // file in an empty chunk after others, but a file that does is a file of the format, and opens
    if last_len < TAG {
        return Err(Error::Malformed("a KMA1 file's last chunk"));
    }
    let plain_len = body - chunks * TAG;
    if plain_len > max_plain {
        return Err(Error::Refused("the file is longer than the limit"));
    }
    if u32::try_from(chunks).is_err() {
        return Err(Error::Refused("the file has more chunks than a counter counts"));
    }
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&file[4..HEADER]);
    let mut out = Zeroizing::new(Vec::with_capacity(plain_len));
    for (counter, chunk) in file[HEADER..].chunks(SEALED_CHUNK).enumerate() {
        let last = counter + 1 == chunks;
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&prefix);
        nonce[8..].copy_from_slice(&(counter as u32).to_be_bytes());
        let mut sealed = Vec::with_capacity(12 + chunk.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(chunk);
        out.extend_from_slice(&aead::open(key.as_bytes(), &sealed, &[u8::from(last)])?);
    }
    Ok(out)
}
