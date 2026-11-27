//! The account's keys as a Kemlock server hands them over (`spec-protocol.md` 4), opened and checked: the root key opens the
//! wrap of every item key and the account's private keys, and the bundle's signature is checked here because the server does
//! not check it. What a run keeps of it is the item wrap, and the `sig1` key that signs the manifest.

use crate::kemlock::bundle::Bundle;
use crate::kemlock::conv::{Uuid, b64_decode};
use crate::kemlock::keys::{Child, PrivateKeys, child_key, user_key};
use crate::kemlock::sig1::{Sig1PrivateKey, Sig1PublicKey};
use crate::kemlock::{Key, RootKey};
use crate::sync::api::Problem;

use super::state::KemlockState;
use super::word;

/// The keys a run works with
pub struct Account {
    pub id: Uuid,
    pub key_version: u32,
    pub item_wrap: Key,
    pub sig_private: Sig1PrivateKey,
    pub sig_public: Sig1PublicKey,
}

/// Opens what the account holds, from the root key and the bundle, signature and sealed private keys (all as bytes): the bundle
/// has to be the account's (its id, its key version), carry a signature that verifies under its own `sig1` key, and the private keys
/// have to be the ones it names.
pub fn open(root: &RootKey, account: &Uuid, key_version: u32, public_bundle: &[u8], bundle_signature: &[u8], sealed_private_keys: &[u8]) -> Result<Account, Problem> {
    let invalid = || Problem::Kemlock(word::KEYS_INVALID);
    let bundle = Bundle::parse_signed(public_bundle, bundle_signature).map_err(|_| invalid())?;
    if bundle.account_id != *account || bundle.key_version != key_version || key_version == 0 {
        return Err(invalid());
    }
    let user = user_key(root);
    let private = PrivateKeys::open(sealed_private_keys, &user, account, key_version).map_err(|_| invalid())?;
    if private.sig1.public_key() != bundle.sig1 || private.kx1.public_key() != bundle.kx1 {
        return Err(invalid());
    }
    Ok(Account { id: *account, key_version, item_wrap: child_key(&user, Child::ItemWrap), sig_public: bundle.sig1, sig_private: private.sig1 })
}

/// The same from what a connection keeps
pub fn open_state(root_hex: &str, account: &str, state: &KemlockState) -> Result<Account, Problem> {
    let invalid = || Problem::Kemlock(word::KEYS_INVALID);
    let root_bytes = zeroize::Zeroizing::new(crate::seal::unhex(root_hex).ok_or_else(invalid)?);
    let root = RootKey::from_slice(&root_bytes).ok_or_else(invalid)?;
    let account = Uuid::parse(account).map_err(|_| invalid())?;
    let decode = |text: &str| b64_decode(text).map_err(|_| invalid());
    open(&root, &account, state.key_version, &decode(&state.public_bundle)?, &decode(&state.bundle_signature)?, &decode(&state.sealed_private_keys)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::kemlock::bundle::Bundle;
    use crate::kemlock::keys::PrivateKeys;

    /// What an account holds, as a registration makes it
    pub fn made(account: Uuid) -> (RootKey, Vec<u8>, Vec<u8>, Vec<u8>) {
        let root = RootKey::random();
        let private = PrivateKeys::generate();
        let bundle = Bundle { account_id: account, key_version: 1, kx1: private.kx1.public_key(), sig1: private.sig1.public_key() };
        let signature = bundle.sign(&private.sig1).unwrap();
        let sealed = private.seal(&user_key(&root), &account, 1);
        (root, bundle.to_bytes(), signature, sealed)
    }

    #[test]
    fn the_account_opens_and_a_swapped_part_does_not() {
        let id = Uuid::random_v4();
        let (root, bundle, signature, sealed) = made(id);
        let account = open(&root, &id, 1, &bundle, &signature, &sealed).unwrap();
        assert_eq!(account.id, id);
        assert_eq!(account.sig_private.public_key(), account.sig_public);
        // Another account's id, another key version, another root key, a bundle of another account's keys
        assert!(open(&root, &Uuid::random_v4(), 1, &bundle, &signature, &sealed).is_err());
        assert!(open(&root, &id, 2, &bundle, &signature, &sealed).is_err());
        assert!(open(&RootKey::random(), &id, 1, &bundle, &signature, &sealed).is_err());
        let (_, other_bundle, other_signature, _) = made(id);
        assert!(open(&root, &id, 1, &other_bundle, &other_signature, &sealed).is_err(), "the sealed keys are not the bundle's");
        // A bundle whose signature is not its own
        assert!(open(&root, &id, 1, &bundle, &other_signature, &sealed).is_err());
    }
}
