//! The public-key bundle and its fingerprint (`crypto.md`, "Public-key bundle and fingerprint").
//!
//! ```text
//! bundle      = "kemlock/v1/bundle" ‖ account id (16) ‖ u32be(key version) ‖ kx1 public key (1600) ‖ sig1 public key (1984)
//! fingerprint = SHA-512("kemlock/v1/fingerprint" ‖ bundle)
//! ```
//!
//! The bundle is signed with the account's own `sig1` key under context `"bundle"`, and travels as its exact bytes.

use sha2::{Digest, Sha512};

use super::conv::Uuid;
use super::kx1::{self, Kx1PublicKey};
use super::sig1::{self, CONTEXT_BUNDLE, Sig1PrivateKey, Sig1PublicKey};
use super::{Error, Result};

const LABEL: &[u8] = b"kemlock/v1/bundle";
const FINGERPRINT_LABEL: &[u8] = b"kemlock/v1/fingerprint";
/// The bundle's length: label, account id, key version and the two public keys
pub const BUNDLE_LEN: usize = 17 + 16 + 4 + kx1::PUBLIC_KEY + sig1::PUBLIC_KEY;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Bundle {
    pub account_id: Uuid,
    pub key_version: u32,
    pub kx1: Kx1PublicKey,
    pub sig1: Sig1PublicKey,
}

impl Bundle {
    /// The bytes that are signed and sent
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(BUNDLE_LEN);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(self.account_id.as_bytes());
        out.extend_from_slice(&self.key_version.to_be_bytes());
        out.extend_from_slice(self.kx1.as_bytes());
        out.extend_from_slice(self.sig1.as_bytes());
        out
    }

    /// Strict: the label, the exact length (no trailing bytes) and both keys valid
    pub fn parse(bytes: &[u8]) -> Result<Bundle> {
        if bytes.len() != BUNDLE_LEN {
            return Err(Error::Malformed("a bundle is 3621 bytes"));
        }
        if &bytes[..17] != LABEL {
            return Err(Error::Malformed("a bundle starts with its label"));
        }
        let id = <[u8; 16]>::try_from(&bytes[17..33]).expect("16 bytes");
        let key_version = u32::from_be_bytes([bytes[33], bytes[34], bytes[35], bytes[36]]);
        let kx1 = Kx1PublicKey::from_bytes(&bytes[37..37 + kx1::PUBLIC_KEY])?;
        let sig1 = Sig1PublicKey::from_bytes(&bytes[37 + kx1::PUBLIC_KEY..])?;
        Ok(Bundle { account_id: Uuid(id), key_version, kx1, sig1 })
    }

    /// The account signs its own bundle: the signature over exactly these bytes
    pub fn sign(&self, key: &Sig1PrivateKey) -> Result<Vec<u8>> {
        key.sign(CONTEXT_BUNDLE, &self.to_bytes())
    }

    /// Parses the bundle and checks the signature against the `sig1` key inside it, which is how a first contact with an
    /// account's keys is accepted: the fingerprint is what a person compares
    pub fn parse_signed(bytes: &[u8], signature: &[u8]) -> Result<Bundle> {
        let bundle = Bundle::parse(bytes)?;
        bundle.sig1.verify(CONTEXT_BUNDLE, bytes, signature)?;
        Ok(bundle)
    }

    /// `SHA-512("kemlock/v1/fingerprint" ‖ bundle)`
    pub fn fingerprint(&self) -> [u8; 64] {
        fingerprint(&self.to_bytes())
    }
}

pub fn fingerprint(bundle: &[u8]) -> [u8; 64] {
    let mut hash = Sha512::new();
    hash.update(FINGERPRINT_LABEL);
    hash.update(bundle);
    hash.finalize().into()
}

/// The 12 groups of 5 digits people compare: group `i` is `u40be(fingerprint[5i .. 5i+5]) mod 100000`, with leading zeros
pub fn fingerprint_groups(fingerprint: &[u8; 64]) -> [u32; 12] {
    let mut groups = [0u32; 12];
    for (i, group) in groups.iter_mut().enumerate() {
        let n = fingerprint[5 * i..5 * i + 5].iter().fold(0u64, |n, b| n << 8 | u64::from(*b));
        *group = (n % 100_000) as u32;
    }
    groups
}

/// The 60 digits as 12 groups of 5 separated by a space
pub fn fingerprint_text(fingerprint: &[u8; 64]) -> String {
    fingerprint_groups(fingerprint).iter().map(|g| format!("{g:05}")).collect::<Vec<_>>().join(" ")
}
