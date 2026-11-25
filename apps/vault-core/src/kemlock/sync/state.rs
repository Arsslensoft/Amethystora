//! What a Kemlock connection keeps beside the fields every connection has (`sync::merge::Connection`): its DPoP key, its device, the
//! account's keys as the server holds them, the no-downgrade record, where the sync cursor and the signed manifest stand, and the
//! move from Bitwarden's copies. It lives in the connection's item, which is service-only and sealed in the vault.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// A vault item that is Kemlock's own `kem1` item too, which the move adopts rather than writes twice (spec-protocol 10.4)
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Adoption {
    /// The vault item
    pub kind: String,
    pub id: String,
    /// The Kemlock entry's own id, which the item has on the server
    pub entry: String,
}

/// Where the move of the vault's own items from Bitwarden's copies stands
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MoveRecord {
    pub started_ms: i64,
    #[serde(default)]
    pub finished_ms: Option<i64>,
    /// Item id on the server -> SHA-256 of the canonical JSON the move sent, for the check to compare with what is read back
    #[serde(default)]
    pub sent: BTreeMap<String, String>,
    /// Attachment id -> SHA-256 of the file's bytes
    #[serde(default)]
    pub files: BTreeMap<String, String>,
    /// How many times the check sent what differed again
    #[serde(default)]
    pub redone: u32,
    /// Item id -> the revision the move wrote it at: the check finding a higher one reads an edit made since, which is no difference
    #[serde(default)]
    pub revisions: BTreeMap<String, u64>,
    /// The items the last check found different from what was sent: the next run writes them again
    #[serde(default)]
    pub redo: Vec<String>,
}

#[derive(Clone, Default, Serialize, Deserialize)]
pub struct KemlockState {
    /// The device's DPoP key (an Ed25519 seed, in hex): the tokens are bound to it
    pub dpop_key: String,
    pub device_id: String,
    /// The key version of the account's bundle and of every item this client writes
    pub key_version: u32,
    /// The settings of the last good sign-in: a later prelogin asking for less is refused
    pub kdf_memory_kib: u32,
    pub kdf_iterations: u32,
    pub kdf_parallelism: u32,
    /// What `GET /account/keys` gave, as the server sends it (base64url): the signed bundle, and the private keys sealed under the root
    pub public_bundle: String,
    pub bundle_signature: String,
    pub sealed_private_keys: String,
    /// OPAQUE worked for this account once: from then on the Bitwarden-hash route is closed, whatever the server says
    #[serde(default)]
    pub opaque_seen: bool,
    /// The identifier the same connection used on the server's Bitwarden API, so that both are one device there
    #[serde(default)]
    pub bitwarden_device: Option<String>,
    /// The sync cursor, stored only once a run has finished writing
    #[serde(default)]
    pub cursor: Option<String>,
    /// The highest signed manifest this client verified: its counter and the SHA-256 of its bytes
    #[serde(default)]
    pub manifest_counter: u64,
    #[serde(default)]
    pub manifest_sha256: Option<String>,
    /// Items the signed manifest did not list, and since when (ms)
    #[serde(default)]
    pub held: BTreeMap<String, i64>,
    #[serde(default)]
    pub adopt: Vec<Adoption>,
    #[serde(default, rename = "move")]
    pub moved: Option<MoveRecord>,
}

impl KemlockState {
    pub fn params(&self) -> crate::kemlock::master::KdfParams {
        crate::kemlock::master::KdfParams { memory_kib: self.kdf_memory_kib, iterations: self.kdf_iterations, parallelism: self.kdf_parallelism }
    }
}

/// What a run of this back end learned that the connection keeps: put there by the service once the run's items are in place
#[derive(Clone, Debug, Default)]
pub struct News {
    /// The sync cursor to store: only when the run finished writing, so that one that died repeats from the old one
    pub cursor: Option<String>,
    pub manifest_counter: Option<u64>,
    pub manifest_sha256: Option<String>,
    pub held: Option<BTreeMap<String, i64>>,
    /// The move's record as it stands, and whether the run ended it (the adoptions are used up)
    pub moved: Option<MoveRecord>,
    pub adopted: bool,
}

impl KemlockState {
    pub fn apply(&mut self, news: News) {
        if news.cursor.is_some() {
            self.cursor = news.cursor;
        }
        if let Some(counter) = news.manifest_counter {
            self.manifest_counter = counter;
            self.manifest_sha256 = news.manifest_sha256;
        }
        if let Some(held) = news.held {
            self.held = held;
        }
        if news.moved.is_some() {
            self.moved = news.moved;
        }
        if news.adopted {
            self.adopt.clear();
        }
    }
}
