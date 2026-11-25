//! Kemlock Server's byte formats, version 1: the client side of `docs/crypto.md`, written from that file and held to
//! its CC0 test vectors (`tests/kemlock-vectors`), never from Kemlock's own code (AGPL and GPL; plans/vault-kemlock).
//!
//! Pure Rust (RustCrypto and dalek crates): the service that uses this never links libcrypto. Each file names the
//! section of `crypto.md` it carries out. What is left out, because a personal vault does not need it: spaces and their
//! chain, Sends, federation, duplicate tags, the recovery kit, passkey wraps and the server's own seal.
//!
//! A decoder checks every length before it decrypts anything and refuses unknown versions, unknown fields and trailing
//! bytes. A failure to open never says which half of a hybrid or which field was wrong.

use std::fmt;

pub mod aead;
pub mod bundle;
pub mod conv;
pub mod item;
pub mod keys;
pub mod kma1;
pub mod kx1;
pub mod manifest;
pub mod master;
pub mod opaque;
pub mod phrase;
pub mod sealedbox;
pub mod secret;
pub mod sig1;

#[cfg(test)]
mod vectors;

pub use secret::{Key, RootKey, Secret};

/// Why a Kemlock value was not accepted
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The bytes or text are not in the format: a wrong length, label, version or alphabet, an unknown field, trailing bytes
    Malformed(&'static str),
    /// In the format, but outside what this client will do: a limit, a setting a server must not ask for
    Refused(&'static str),
    /// A key, an aad or a signature did not fit. Which of them is never said
    Unopened,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Malformed(what) => write!(f, "not in the Kemlock format: {what}"),
            Error::Refused(what) => write!(f, "refused: {what}"),
            Error::Unopened => f.write_str("did not open"),
        }
    }
}

impl std::error::Error for Error {}

pub type Result<T> = std::result::Result<T, Error>;
