//! Keys, held in memory that wipes itself when it is dropped.

use std::fmt;

use zeroize::Zeroizing;

/// `N` secret bytes. Never printed, compared in constant time, wiped on drop.
#[derive(Clone)]
pub struct Secret<const N: usize>(Zeroizing<[u8; N]>);

/// A 32-byte key: the user key, its children, an item key, a master key
pub type Key = Secret<32>;
/// The account's 64-byte root key (`crypto.md`, "Account keys")
pub type RootKey = Secret<64>;

impl<const N: usize> Secret<N> {
    pub fn new(bytes: [u8; N]) -> Self {
        Secret(Zeroizing::new(bytes))
    }

    /// Exactly `N` bytes, or none
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let bytes: &[u8; N] = bytes.try_into().ok()?;
        Some(Self::build(|out| out.copy_from_slice(bytes)))
    }

    /// Made in place, so that no copy of it is left on the stack
    pub fn build(fill: impl FnOnce(&mut [u8; N])) -> Self {
        let mut bytes = Zeroizing::new([0u8; N]);
        fill(&mut bytes);
        Secret(bytes)
    }

    pub fn random() -> Self {
        Self::build(|bytes| crate::seal::random(&mut bytes[..]))
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.0
    }
}

impl<const N: usize> PartialEq for Secret<N> {
    fn eq(&self, other: &Self) -> bool {
        crate::seal::same(&self.0[..], &other.0[..])
    }
}

impl<const N: usize> Eq for Secret<N> {}

impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[key]")
    }
}
