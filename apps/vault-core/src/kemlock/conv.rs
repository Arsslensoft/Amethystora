//! `crypto.md`, "Conventions" and "Legacy ids": `lp`, base64url, UUIDs, owners and the ids older clients map to UUIDs.

use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

use super::{Error, Result};

/// `lp(x) = u32be(len(x)) ‖ x`: how every variable-length field enters a hashed or authenticated input
pub fn lp(x: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + x.len());
    put_lp(&mut out, x);
    out
}

pub fn put_lp(out: &mut Vec<u8>, x: &[u8]) {
    out.extend_from_slice(&u32::try_from(x.len()).expect("a field under 4 GiB").to_be_bytes());
    out.extend_from_slice(x);
}

/// Base64url without padding (RFC 4648 section 5)
pub fn b64_encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The strict decoder: padding, the standard alphabet and whitespace are refused, and so are the spare bits of a last
/// character that a canonical encoding leaves at zero
pub fn b64_decode(text: &str) -> Result<Vec<u8>> {
    if !text.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(Error::Malformed("base64url without padding"));
    }
    URL_SAFE_NO_PAD.decode(text).map_err(|_| Error::Malformed("base64url without padding"))
}

/// A UUID as its 16 raw bytes (RFC 9562 byte order)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Uuid(pub [u8; 16]);

impl Uuid {
    /// A version 4 UUID, which is what a client chooses for a new item
    pub fn random_v4() -> Uuid {
        let mut bytes = [0u8; 16];
        crate::seal::random(&mut bytes);
        bytes[6] = bytes[6] & 0x0f | 0x40;
        bytes[8] = bytes[8] & 0x3f | 0x80;
        Uuid(bytes)
    }

    /// The hyphenated lower-case form and nothing else
    pub fn parse(text: &str) -> Result<Uuid> {
        let bytes = text.as_bytes();
        if bytes.len() != 36 {
            return Err(Error::Malformed("a hyphenated lower-case uuid"));
        }
        let mut out = [0u8; 16];
        let mut at = 0;
        let mut high = true;
        for (i, &b) in bytes.iter().enumerate() {
            if matches!(i, 8 | 13 | 18 | 23) {
                if b != b'-' {
                    return Err(Error::Malformed("a hyphenated lower-case uuid"));
                }
                continue;
            }
            let digit = match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => return Err(Error::Malformed("a hyphenated lower-case uuid")),
            };
            if high {
                out[at] = digit << 4;
            } else {
                out[at] |= digit;
                at += 1;
            }
            high = !high;
        }
        Ok(Uuid(out))
    }

    /// The `is_uuid` test of the legacy ids: a hyphenated lower-case UUID, which is never mapped
    pub fn is_uuid(text: &str) -> bool {
        Uuid::parse(text).is_ok()
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]
        )
    }
}

impl fmt::Debug for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// Whose items they are: `0x01` a person's own vault, `0x02` a space
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum OwnerKind {
    User = 1,
    Space = 2,
}

/// An owner: `u8(type) ‖ uuid`, 17 bytes in a binary input and `user:<uuid>` or `space:<uuid>` in JSON
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Owner {
    pub kind: OwnerKind,
    pub id: Uuid,
}

impl Owner {
    pub fn user(id: Uuid) -> Owner {
        Owner { kind: OwnerKind::User, id }
    }

    pub fn to_bytes(&self) -> [u8; 17] {
        let mut out = [0u8; 17];
        out[0] = self.kind as u8;
        out[1..].copy_from_slice(&self.id.0);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Owner> {
        let bytes: &[u8; 17] = bytes.try_into().map_err(|_| Error::Malformed("an owner is 17 bytes"))?;
        let kind = match bytes[0] {
            1 => OwnerKind::User,
            2 => OwnerKind::Space,
            _ => return Err(Error::Malformed("an owner's type is 1 or 2")),
        };
        let mut id = [0u8; 16];
        id.copy_from_slice(&bytes[1..]);
        Ok(Owner { kind, id: Uuid(id) })
    }

    pub fn parse(text: &str) -> Result<Owner> {
        let (kind, id) = if let Some(id) = text.strip_prefix("user:") {
            (OwnerKind::User, id)
        } else if let Some(id) = text.strip_prefix("space:") {
            (OwnerKind::Space, id)
        } else {
            return Err(Error::Malformed("an owner is user:<uuid> or space:<uuid>"));
        };
        Ok(Owner { kind, id: Uuid::parse(id)? })
    }
}

impl fmt::Display for Owner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.kind {
            OwnerKind::User => write!(f, "user:{}", self.id),
            OwnerKind::Space => write!(f, "space:{}", self.id),
        }
    }
}

/// RFC 9562 section 5.8: the first 16 bytes of a hash with the version nibble and the variant bits set
fn uuidv8(hash: &[u8]) -> Uuid {
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = bytes[6] & 0x0f | 0x80;
    bytes[8] = bytes[8] & 0x3f | 0x80;
    Uuid(bytes)
}

const LEGACY: &[u8] = b"kemlock/v1/legacy-id";

/// `uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("space") ‖ lp(old space id)))`. A space id is 1 to 64 characters of
/// `[A-Za-z0-9_-]`.
pub fn legacy_space_uuid(old: &str) -> Result<Uuid> {
    if old.is_empty() || old.len() > 64 || !old.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
        return Err(Error::Malformed("an old space id is 1 to 64 characters of A-Z a-z 0-9 _ -"));
    }
    let mut input = LEGACY.to_vec();
    put_lp(&mut input, b"space");
    put_lp(&mut input, old.as_bytes());
    Ok(uuidv8(&Sha256::digest(&input)))
}

/// `uuidv8(SHA-256("kemlock/v1/legacy-id" ‖ lp("item") ‖ owner (17) ‖ lp(old item id)))`. The owner is part of the input:
/// two people's old vaults both hold an `acc-1`.
pub fn legacy_item_uuid(owner: &Owner, old: &str) -> Uuid {
    let mut input = LEGACY.to_vec();
    put_lp(&mut input, b"item");
    input.extend_from_slice(&owner.to_bytes());
    put_lp(&mut input, old.as_bytes());
    uuidv8(&Sha256::digest(&input))
}

/// The id an item has on the server: itself when it already is a hyphenated lower-case UUID, never mapped, else the
/// legacy mapping. The original id stays inside the item's JSON.
pub fn item_uuid(owner: &Owner, id: &str) -> Uuid {
    Uuid::parse(id).unwrap_or_else(|_| legacy_item_uuid(owner, id))
}
