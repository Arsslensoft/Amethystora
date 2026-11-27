//! The Vault on Kemlock Server's own API (`/kem/v1`): plans/vault-kemlock, written from `spec-protocol.md` and `spec-items.md`
//! beside the Bitwarden back end (`crate::sync`), which it never touches. Nothing here opens a socket or a file: the service
//! gives a run an `Http` that reaches the network service, the vault's items and the connection, and writes back what the run says.
//!
//! No libcrypto: every byte format is `crate::kemlock`'s, in pure Rust, so the service that runs this never loads it. What does need
//! libcrypto (a key's halves, a certificate's chain) is asked through `crate::sync::convert::Convert`, as the Bitwarden side does.

pub mod account;
pub mod api;
pub mod dpop;
pub mod engine;
#[cfg(any(test, feature = "fake-server"))]
pub mod fake;
pub mod items;
pub mod signin;
pub mod state;
#[cfg(test)]
mod tests;

/// What the device is called on the server, and its kind (`spec-protocol.md` 2.7)
pub const DEVICE_NAME: &str = crate::sync::DEVICE_NAME;
pub const DEVICE_KIND: &str = "amethystora";

/// Every word a Kemlock back end stops with, as `Problem::Kemlock` carries it: stable, for the socket, the window and `vault.just`
pub mod word {
    /// The address answers like a server of another kind
    pub const NOT_KEMLOCK: &str = "not-kemlock";
    /// The server says it is set up under another address than the one given, so it would refuse every proof
    pub const DOMAIN_DIFFERS: &str = "domain-differs";
    /// It lacks `opaque`, `dpop` or `sync`
    pub const SERVER_TOO_OLD: &str = "server-too-old";
    /// A refresh token reused, or the security stamp changed: signed out on the server
    pub const SESSION_ENDED: &str = "session-ended";
    /// DPoP refused the proof: the clock, or the address the server was set up under
    pub const DPOP_REFUSED: &str = "dpop-refused";
    /// A second `use-dpop-nonce` in a row
    pub const DPOP_NONCE: &str = "dpop-nonce";
    /// The account signs in with single sign-on, which the Vault does not do
    pub const SSO_ONLY: &str = "sso-only";
    /// 403 `account-disabled`, `account-being-deleted` or `forbidden`
    pub const ACCOUNT_REFUSED: &str = "account-refused";
    /// OPAQUE did not verify and the Bitwarden route is not open: a wrong password, or not the server that was set up
    pub const WRONG_PASSWORD_OR_SERVER: &str = "wrong-password-or-server";
    /// A Compatible account whose only second step is not an authenticator code
    pub const ENROL_NEEDS_TOTP: &str = "enrol-needs-totp";
    /// The server's keys for the account do not check out (the bundle's signature, its id, its keys)
    pub const KEYS_INVALID: &str = "keys-invalid";
    /// Items under another key version than the one connected
    pub const KEYS_CHANGED: &str = "keys-changed";
    /// A manifest that does not verify, is of another owner, or is not what the server said
    pub const MANIFEST_INVALID: &str = "manifest-invalid";
    /// A manifest older than one already verified
    pub const MANIFEST_ROLLED_BACK: &str = "manifest-rolled-back";
    /// The signed manifest lists an item the server no longer serves
    pub const ITEM_MISSING: &str = "item-missing";
    /// An item at a lower revision than the manifest lists, or than this device saw
    pub const ITEM_ROLLED_BACK: &str = "item-rolled-back";
    /// An item seen deleted that is back, with no manifest listing it
    pub const ITEM_RESURRECTED: &str = "item-resurrected";
    /// Items no signed manifest lists, for a day
    pub const ITEMS_UNLISTED: &str = "items-unlisted";
    /// The server keeps files in a bucket, which the Vault does not use
    pub const FILES_BUCKET: &str = "files-bucket";
    /// What the move wrote did not read back as it was sent
    pub const MOVE_CHECK: &str = "move-check";
    /// The server stopped the person: the account's second step was refused
    pub const SECOND_STEP_REFUSED: &str = "second-step-refused";
    /// The server sent something that is not the protocol
    pub const BAD_ANSWER: &str = "bad-answer";
    /// This server serves two versions of an item at once (federation): left for the Kemlock app
    pub const SIBLINGS: &str = "siblings";
}

/// Items a person's vault names: the item kinds of the Kemlock API this client writes
pub mod kind {
    pub const LOGIN: &str = "login";
    pub const OTP: &str = "otp";
    pub const BACKUP_CODES: &str = "backup-codes";
    pub const SSH_KEY: &str = "ssh-key";
    pub const KEY: &str = "key";
    pub const CERTIFICATE: &str = "certificate";
    pub const NOTE: &str = "note";
}

/// The device identifier a Kemlock sign-in sends as `bitwardenDeviceIdentifier`, when the same connection used the Bitwarden API
pub fn is_device_identifier(text: &str) -> bool {
    (1..=256).contains(&text.len())
}
