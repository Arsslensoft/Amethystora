//! The signed manifest (`crypto.md`, "Signed manifest"):
//!
//! ```text
//! manifest = "kemlock/v1/manifest" ‖ owner (17) ‖ u64be(counter) ‖ u32be(n)
//!            ‖ n × (item id (16) ‖ u64be(revision) ‖ SHA-256(ciphertext) (32) ‖ u8(deleted))
//! ```
//!
//! Entries are sorted by item id bytes and a tombstone's hash is 32 zero bytes. The writer signs it with `sig1` under
//! context `"manifest"`. The counter only goes up: a device keeps the highest it has seen.

use sha2::{Digest, Sha256};

use super::conv::{Owner, Uuid};
use super::sig1::{CONTEXT_MANIFEST, Sig1PrivateKey, Sig1PublicKey};
use super::{Error, Result};

const LABEL: &[u8] = b"kemlock/v1/manifest";
const HEADER: usize = LABEL.len() + 17 + 8 + 4;
const ENTRY: usize = 16 + 8 + 32 + 1;
/// The most entries one manifest holds for this client: the count is checked against the bytes before anything is built
pub const MAX_ENTRIES: usize = 1_000_000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub item_id: Uuid,
    pub revision: u64,
    /// `SHA-256(ciphertext)`, or 32 zero bytes for a tombstone
    pub ciphertext_hash: [u8; 32],
    pub deleted: bool,
}

impl Entry {
    pub fn live(item_id: Uuid, revision: u64, ciphertext: &[u8]) -> Entry {
        Entry { item_id, revision, ciphertext_hash: Sha256::digest(ciphertext).into(), deleted: false }
    }

    pub fn tombstone(item_id: Uuid, revision: u64) -> Entry {
        Entry { item_id, revision, ciphertext_hash: [0; 32], deleted: true }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub owner: Owner,
    pub counter: u64,
    /// Sorted by item id, each id once
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// Sorts the entries; an id twice, or a tombstone with a hash, or a live entry with none, is refused
    pub fn new(owner: Owner, counter: u64, mut entries: Vec<Entry>) -> Result<Manifest> {
        entries.sort_by_key(|e| e.item_id);
        if entries.windows(2).any(|pair| pair[0].item_id == pair[1].item_id) {
            return Err(Error::Malformed("an item twice in a manifest"));
        }
        if entries.len() > MAX_ENTRIES {
            return Err(Error::Refused("a manifest with too many entries"));
        }
        if entries.iter().any(|e| e.deleted != (e.ciphertext_hash == [0; 32])) {
            return Err(Error::Malformed("a tombstone's hash is zeros, and no other entry's is"));
        }
        Ok(Manifest { owner, counter, entries })
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER + self.entries.len() * ENTRY);
        out.extend_from_slice(LABEL);
        out.extend_from_slice(&self.owner.to_bytes());
        out.extend_from_slice(&self.counter.to_be_bytes());
        out.extend_from_slice(&u32::try_from(self.entries.len()).expect("under 4 billion entries").to_be_bytes());
        for entry in &self.entries {
            out.extend_from_slice(entry.item_id.as_bytes());
            out.extend_from_slice(&entry.revision.to_be_bytes());
            out.extend_from_slice(&entry.ciphertext_hash);
            out.push(u8::from(entry.deleted));
        }
        out
    }

    /// Strict: the label, the count against the length, no trailing bytes, ids ascending and once, `deleted` 0 or 1
    pub fn parse(bytes: &[u8]) -> Result<Manifest> {
        if bytes.len() < HEADER || &bytes[..LABEL.len()] != LABEL {
            return Err(Error::Malformed("a manifest starts with its label"));
        }
        let owner = Owner::from_bytes(&bytes[LABEL.len()..LABEL.len() + 17])?;
        let at = LABEL.len() + 17;
        let counter = u64::from_be_bytes(bytes[at..at + 8].try_into().expect("8 bytes"));
        let count = u32::from_be_bytes(bytes[at + 8..at + 12].try_into().expect("4 bytes")) as usize;
        if count > MAX_ENTRIES || bytes.len() != HEADER + count * ENTRY {
            return Err(Error::Malformed("a manifest's count does not fit its length"));
        }
        let mut entries = Vec::with_capacity(count);
        for chunk in bytes[HEADER..].as_chunks::<ENTRY>().0 {
            let mut id = [0u8; 16];
            id.copy_from_slice(&chunk[..16]);
            let mut hash = [0u8; 32];
            hash.copy_from_slice(&chunk[24..56]);
            let deleted = match chunk[56] {
                0 => false,
                1 => true,
                _ => return Err(Error::Malformed("a manifest's deleted is 0 or 1")),
            };
            entries.push(Entry {
                item_id: Uuid(id),
                revision: u64::from_be_bytes(chunk[16..24].try_into().expect("8 bytes")),
                ciphertext_hash: hash,
                deleted,
            });
        }
        if entries.windows(2).any(|pair| pair[0].item_id >= pair[1].item_id) {
            return Err(Error::Malformed("a manifest's entries ascend by item id"));
        }
        if entries.iter().any(|e| e.deleted != (e.ciphertext_hash == [0; 32])) {
            return Err(Error::Malformed("a tombstone's hash is zeros, and no other entry's is"));
        }
        Ok(Manifest { owner, counter, entries })
    }

    /// Signed with `sig1` under context `"manifest"`: the signature is over exactly these bytes
    pub fn sign(&self, key: &Sig1PrivateKey) -> Result<Vec<u8>> {
        key.sign(CONTEXT_MANIFEST, &self.to_bytes())
    }

    /// Checks the signature over the bytes as they are, then reads them
    pub fn parse_signed(bytes: &[u8], signature: &[u8], key: &Sig1PublicKey) -> Result<Manifest> {
        key.verify(CONTEXT_MANIFEST, bytes, signature)?;
        Manifest::parse(bytes)
    }
}
