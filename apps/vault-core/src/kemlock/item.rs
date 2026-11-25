//! `kem1`, the item envelope (`crypto.md`, "`kem1`: the item envelope"), and the item as it travels.
//!
//! Each item has its own random 32-byte item key. The client assigns the revision, which is part of what is sealed:
//!
//! ```text
//! aad        = "kemlock/v1/item" ‖ item id (16) ‖ u64be(revision) ‖ lp(kind) ‖ owner (17)
//! ciphertext = AES-256-GCM(item key, nonce, item JSON (UTF-8), aad)
//! wrap aad   = "kemlock/v1/item-key" ‖ item id (16) ‖ owner (17) ‖ u32be(key version)
//! item_key   = AES-256-GCM(owner's "kemlock/v1/item-wrap" child key, nonce, item key, wrap aad)
//! ```
//!
//! Only items of a person's own vault are carried out here (`owner` `user:<uuid>`): an item of a space is wrapped under a
//! collection's key, which a personal client does not hold.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::aead;
use super::conv::{Owner, OwnerKind, Uuid, b64_decode, b64_encode, put_lp};
use super::{Error, Key, Result};

const ITEM_LABEL: &[u8] = b"kemlock/v1/item";
const WRAP_LABEL: &[u8] = b"kemlock/v1/item-key";
/// A wrapped item key: nonce, 32 bytes, tag
pub const WRAPPED_ITEM_KEY: usize = aead::NONCE + 32 + aead::TAG;
/// The most ciphertext a client reads from the wire. The server's own roof is not in `crypto.md`; this is the client's.
pub const MAX_CIPHERTEXT: usize = 8 * 1024 * 1024;
pub const FORMAT: &str = "kem1";

/// A kind is 1 to 64 bytes of `[a-z0-9_-]`
pub fn check_kind(kind: &str) -> Result<()> {
    if kind.is_empty() || kind.len() > 64 || !kind.bytes().all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'-')) {
        return Err(Error::Malformed("a kind is 1 to 64 characters of a-z 0-9 _ -"));
    }
    Ok(())
}

/// The aad of the item's ciphertext
pub fn item_aad(id: &Uuid, revision: u64, kind: &str, owner: &Owner) -> Result<Vec<u8>> {
    check_kind(kind)?;
    let mut aad = ITEM_LABEL.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&revision.to_be_bytes());
    put_lp(&mut aad, kind.as_bytes());
    aad.extend_from_slice(&owner.to_bytes());
    Ok(aad)
}

/// The aad of the item key's wrap, which is not bound to the revision, so an edit may keep the item key
pub fn wrap_aad(id: &Uuid, owner: &Owner, key_version: u32) -> Vec<u8> {
    let mut aad = WRAP_LABEL.to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad.extend_from_slice(&owner.to_bytes());
    aad.extend_from_slice(&key_version.to_be_bytes());
    aad
}

/// Seals the item's JSON under its item key: `nonce ‖ ciphertext ‖ tag`
pub fn seal_item(item_key: &Key, id: &Uuid, revision: u64, kind: &str, owner: &Owner, json: &[u8]) -> Result<Vec<u8>> {
    Ok(aead::seal(item_key.as_bytes(), json, &item_aad(id, revision, kind, owner)?))
}

#[cfg(test)]
pub(crate) fn seal_item_with_nonce(
    item_key: &Key,
    nonce: &[u8; 12],
    id: &Uuid,
    revision: u64,
    kind: &str,
    owner: &Owner,
    json: &[u8],
) -> Result<Vec<u8>> {
    Ok(aead::seal_with_nonce(item_key.as_bytes(), nonce, json, &item_aad(id, revision, kind, owner)?))
}

/// Opens an item's ciphertext. It opens only under the id, revision, kind and owner it was sealed with.
pub fn open_item(item_key: &Key, id: &Uuid, revision: u64, kind: &str, owner: &Owner, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if ciphertext.len() > MAX_CIPHERTEXT {
        return Err(Error::Refused("an item's ciphertext is too long"));
    }
    aead::open(item_key.as_bytes(), ciphertext, &item_aad(id, revision, kind, owner)?)
}

/// Wraps the item key under the owner's `item-wrap` child key, at the key version the account has now
pub fn wrap_item_key(item_wrap: &Key, item_key: &Key, id: &Uuid, owner: &Owner, key_version: u32) -> Vec<u8> {
    aead::seal(item_wrap.as_bytes(), item_key.as_bytes(), &wrap_aad(id, owner, key_version))
}

#[cfg(test)]
pub(crate) fn wrap_item_key_with_nonce(
    item_wrap: &Key,
    nonce: &[u8; 12],
    item_key: &Key,
    id: &Uuid,
    owner: &Owner,
    key_version: u32,
) -> Vec<u8> {
    aead::seal_with_nonce(item_wrap.as_bytes(), nonce, item_key.as_bytes(), &wrap_aad(id, owner, key_version))
}

/// Opens the wrapped item key, with the key version the item says
pub fn unwrap_item_key(item_wrap: &Key, wrapped: &[u8], id: &Uuid, owner: &Owner, key_version: u32) -> Result<Key> {
    if wrapped.len() != WRAPPED_ITEM_KEY {
        return Err(Error::Malformed("a wrapped item key is 60 bytes"));
    }
    let plain = aead::open(item_wrap.as_bytes(), wrapped, &wrap_aad(id, owner, key_version))?;
    Key::from_slice(&plain).ok_or(Error::Unopened)
}

/// An item as JSON travels (`ItemDto` of the server's OpenAPI document), with the fields `crypto.md` names. Unknown
/// fields are refused. `deleted` is always present, `true` or `false`, in both directions; a tombstone has neither
/// `ciphertext` nor `itemKey`. `deletedAt` and `held` are set by the server and a client reads them and ignores them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct WireItem {
    pub id: String,
    pub owner: String,
    pub kind: String,
    pub format: String,
    pub revision: u64,
    pub key_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ciphertext: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub item_key: Option<String>,
    pub deleted: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collection_id: Option<String>,
    #[serde(default, skip_serializing)]
    pub deleted_at: Option<String>,
    #[serde(default, skip_serializing)]
    pub held: Option<bool>,
}

impl WireItem {
    /// Reads one item from JSON text: unknown fields, a missing `deleted` and a wrong type are refused
    pub fn from_json(text: &str) -> Result<WireItem> {
        serde_json::from_str(text).map_err(|_| Error::Malformed("an item's JSON"))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("an item is plain data")
    }

    /// The item as a `kem1` item of a person's vault, checked: format, owner, id, kind, revision, key version, and the
    /// lengths of what is sealed before any of it is opened
    pub fn kem1(&self) -> Result<Kem1Item> {
        if self.format != FORMAT {
            return Err(Error::Malformed("not a kem1 item"));
        }
        let id = Uuid::parse(&self.id)?;
        let owner = Owner::parse(&self.owner)?;
        if owner.kind != OwnerKind::User || self.collection_id.is_some() {
            return Err(Error::Refused("an item of a space is not this client's"));
        }
        check_kind(&self.kind)?;
        if self.revision == 0 || self.revision > i64::MAX as u64 {
            return Err(Error::Malformed("a revision starts at 1"));
        }
        let body = if self.deleted {
            if self.ciphertext.is_some() || self.item_key.is_some() {
                return Err(Error::Malformed("a tombstone has no ciphertext or item key"));
            }
            Kem1Body::Deleted
        } else {
            if self.key_version == 0 {
                return Err(Error::Malformed("a live item has a key version"));
            }
            let (Some(ciphertext), Some(item_key)) = (&self.ciphertext, &self.item_key) else {
                return Err(Error::Malformed("a live item has a ciphertext and an item key"));
            };
            // The text is measured before it is decoded: base64url is 4 characters for 3 bytes
            if ciphertext.len() > MAX_CIPHERTEXT / 3 * 4 + 4 {
                return Err(Error::Refused("an item's ciphertext is too long"));
            }
            let ciphertext = b64_decode(ciphertext)?;
            let item_key = b64_decode(item_key)?;
            if ciphertext.len() < aead::MIN_SEALED || ciphertext.len() > MAX_CIPHERTEXT {
                return Err(Error::Malformed("an item's ciphertext is at least 28 bytes"));
            }
            if item_key.len() != WRAPPED_ITEM_KEY {
                return Err(Error::Malformed("a wrapped item key is 60 bytes"));
            }
            Kem1Body::Live { ciphertext, item_key }
        };
        Ok(Kem1Item { id, owner, kind: self.kind.clone(), revision: self.revision, key_version: self.key_version, body })
    }
}

/// What a `kem1` item carries once it is read: sealed bytes, or a tombstone
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kem1Body {
    Live { ciphertext: Vec<u8>, item_key: Vec<u8> },
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Kem1Item {
    pub id: Uuid,
    pub owner: Owner,
    pub kind: String,
    pub revision: u64,
    pub key_version: u32,
    pub body: Kem1Body,
}

impl Kem1Item {
    /// A new live item, sealed: a fresh item key, wrapped under `item_wrap` at `key_version`, and the JSON sealed under it at
    /// `revision` (1 for a new item, then the previous one plus one)
    pub fn seal(item_wrap: &Key, key_version: u32, id: Uuid, owner: Owner, kind: &str, revision: u64, json: &[u8]) -> Result<Kem1Item> {
        let item_key = Key::random();
        Self::seal_under(item_wrap, key_version, &item_key, id, owner, kind, revision, json)
    }

    /// An edit may keep the item key: the same wrap, a new revision and a fresh nonce
    #[allow(clippy::too_many_arguments)]
    pub fn seal_under(
        item_wrap: &Key,
        key_version: u32,
        item_key: &Key,
        id: Uuid,
        owner: Owner,
        kind: &str,
        revision: u64,
        json: &[u8],
    ) -> Result<Kem1Item> {
        if revision == 0 {
            return Err(Error::Malformed("a revision starts at 1"));
        }
        let ciphertext = seal_item(item_key, &id, revision, kind, &owner, json)?;
        let wrapped = wrap_item_key(item_wrap, item_key, &id, &owner, key_version);
        Ok(Kem1Item { id, owner, kind: kind.to_owned(), revision, key_version, body: Kem1Body::Live { ciphertext, item_key: wrapped } })
    }

    /// The deletion of an item: a tombstone, whose revision still moves on
    pub fn tombstone(id: Uuid, owner: Owner, kind: &str, revision: u64, key_version: u32) -> Result<Kem1Item> {
        check_kind(kind)?;
        if revision == 0 {
            return Err(Error::Malformed("a revision starts at 1"));
        }
        Ok(Kem1Item { id, owner, kind: kind.to_owned(), revision, key_version, body: Kem1Body::Deleted })
    }

    /// Opens the item: unwraps its key, then opens the JSON. Returns the item key too, which an edit may keep.
    pub fn open(&self, item_wrap: &Key) -> Result<(Key, Zeroizing<Vec<u8>>)> {
        let Kem1Body::Live { ciphertext, item_key } = &self.body else {
            return Err(Error::Malformed("a tombstone has nothing to open"));
        };
        let key = unwrap_item_key(item_wrap, item_key, &self.id, &self.owner, self.key_version)?;
        let json = open_item(&key, &self.id, self.revision, &self.kind, &self.owner, ciphertext)?;
        Ok((key, json))
    }

    pub fn deleted(&self) -> bool {
        self.body == Kem1Body::Deleted
    }

    /// The ciphertext, or none for a tombstone
    pub fn ciphertext(&self) -> Option<&[u8]> {
        match &self.body {
            Kem1Body::Live { ciphertext, .. } => Some(ciphertext),
            Kem1Body::Deleted => None,
        }
    }

    pub fn to_wire(&self) -> WireItem {
        let (ciphertext, item_key, deleted) = match &self.body {
            Kem1Body::Live { ciphertext, item_key } => (Some(b64_encode(ciphertext)), Some(b64_encode(item_key)), false),
            Kem1Body::Deleted => (None, None, true),
        };
        WireItem {
            id: self.id.to_string(),
            owner: self.owner.to_string(),
            kind: self.kind.clone(),
            format: FORMAT.to_owned(),
            revision: self.revision,
            key_version: self.key_version,
            ciphertext,
            item_key,
            deleted,
            collection_id: None,
            deleted_at: None,
            held: None,
        }
    }
}
