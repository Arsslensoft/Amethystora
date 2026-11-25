//! The device-approval phrase (`crypto.md`, "`kx1` / Device-approval phrase"): five words that a new device and the device
//! approving it both show, so that a person can see that the key about to receive the root key is the one the new device made.
//!
//! ```text
//! digest = SHA-256("kemlock approval v1" ‖ the new device's one-time kx1 public key (1600))
//! bits   = the first 65 bits of digest, most significant first
//! word i = list[(bits[13i .. 13i+13] as a big-endian 13-bit number) mod 7776],  i = 0 .. 4
//! ```
//!
//! Each client computes the phrase itself, from the key it made or the key it is about to seal to. The server's `phrase`
//! field is a cross-check and is never shown.

use std::sync::OnceLock;

use sha2::{Digest, Sha256};

use super::kx1::{Kx1PublicKey, PUBLIC_KEY};
use super::{Error, Result};

const LABEL: &[u8] = b"kemlock approval v1";
/// EFF's large list as the Vault already ships it (CC-BY 3.0 US): five dice, a tab and the word on each line
const WORD_LIST: &str = include_str!("../../assets/eff_large_wordlist.txt");
pub const WORDS: usize = 7776;
/// The SHA-256 of the list as `crypto.md` fixes it: the 7,776 words alone, one a line, LF endings, `abacus` first
pub const LIST_SHA256: &str = "6d557f0693958fb5e650b68b5bee585eb82cf4da32965505c789e924743bc522";

pub(crate) fn list() -> &'static [&'static str] {
    static LIST: OnceLock<Vec<&'static str>> = OnceLock::new();
    LIST.get_or_init(|| WORD_LIST.lines().filter_map(|line| line.split_once('\t').map(|(_, word)| word.trim())).collect())
}

/// `SHA-256("kemlock approval v1" ‖ public key)`
pub fn digest(public_key: &[u8; PUBLIC_KEY]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(LABEL);
    hash.update(public_key);
    hash.finalize().into()
}

/// The five 13-bit groups of the first 65 bits
pub fn groups(digest: &[u8; 32]) -> [u16; 5] {
    let mut out = [0u16; 5];
    for (i, group) in out.iter_mut().enumerate() {
        let mut n = 0u16;
        for bit in 13 * i..13 * i + 13 {
            n = n << 1 | u16::from(digest[bit / 8] >> (7 - bit % 8) & 1);
        }
        *group = n;
    }
    out
}

/// The five words, lower case, joined by single spaces
pub fn phrase(public_key: &Kx1PublicKey) -> String {
    words(&digest(public_key.as_bytes()))
}

/// The phrase of the 1600 bytes as they came off the wire, which are hashed as they are, whether or not the ML-KEM half
/// is a valid key (the phrase only has to make two keys differ)
pub fn phrase_of_bytes(public_key: &[u8]) -> Result<String> {
    let public_key: &[u8; PUBLIC_KEY] = public_key.try_into().map_err(|_| Error::Malformed("a kx1 public key is 1600 bytes"))?;
    Ok(words(&digest(public_key)))
}

fn words(digest: &[u8; 32]) -> String {
    let words = list();
    groups(digest).iter().map(|g| words[usize::from(*g) % WORDS]).collect::<Vec<_>>().join(" ")
}
