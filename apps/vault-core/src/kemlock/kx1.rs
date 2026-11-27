//! `kx1`, the hybrid exchange key (`crypto.md`, "`kx1`"): ML-KEM-1024 and X25519, combined as X-Wing's construction does,
//! with Kemlock's label first.
//!
//! - public key: ML-KEM-1024 encapsulation key (1568) ‖ X25519 public key (32), 1600 bytes
//! - private key: ML-KEM seed `d ‖ z` (64) ‖ X25519 private key (32), 96 bytes
//! - ciphertext: ML-KEM ciphertext (1568) ‖ X25519 ephemeral public key (32), 1600 bytes
//! - shared secret: `SHA3-256("kemlock/v1/kx1" ‖ ss_m ‖ ss_x ‖ ct_x ‖ pk_x)`

use ml_kem::{Decapsulate, KeyExport, ml_kem_1024};
use sha3::{Digest, Sha3_256};
use x25519_dalek::{X25519_BASEPOINT_BYTES, x25519};
use zeroize::Zeroizing;

use super::{Error, Key, Result};

pub const MLKEM_PK: usize = 1568;
pub const PUBLIC_KEY: usize = 1600;
pub const PRIVATE_KEY: usize = 96;
pub const CIPHERTEXT: usize = 1600;
const LABEL: &[u8] = b"kemlock/v1/kx1";

/// An exchange public key: 1600 bytes, the ML-KEM half checked to be a valid encapsulation key
#[derive(Clone, PartialEq, Eq)]
pub struct Kx1PublicKey(Box<[u8; PUBLIC_KEY]>);

impl Kx1PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Kx1PublicKey> {
        let bytes: &[u8; PUBLIC_KEY] = bytes.try_into().map_err(|_| Error::Malformed("a kx1 public key is 1600 bytes"))?;
        encapsulation_key(&bytes[..MLKEM_PK])?;
        Ok(Kx1PublicKey(Box::new(*bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY] {
        &self.0
    }

    fn x25519(&self) -> [u8; 32] {
        let pk = <[u8; 32]>::try_from(&self.0[MLKEM_PK..]).expect("32 bytes");
        pk
    }

    /// A shared secret and the ciphertext that gives it to the holder of the private key. An all-zero X25519 secret (a
    /// public key of low order) is refused.
    pub fn encapsulate(&self) -> Result<(Vec<u8>, Key)> {
        let mut m = Zeroizing::new(ml_kem::B32::default());
        crate::seal::random(&mut m[..]);
        let mut ephemeral = Zeroizing::new([0u8; 32]);
        crate::seal::random(&mut ephemeral[..]);
        self.encapsulate_with(&m, &ephemeral)
    }

    /// With the two random inputs given: for tests only, where a fixed pair makes the output a fixed answer
    pub(crate) fn encapsulate_with(&self, m: &ml_kem::B32, ephemeral: &[u8; 32]) -> Result<(Vec<u8>, Key)> {
        let ek = encapsulation_key(&self.0[..MLKEM_PK])?;
        let (ct_m, ss_m) = ek.encapsulate_deterministic(m);
        let ct_x = x25519(*ephemeral, X25519_BASEPOINT_BYTES);
        let ss_x = Zeroizing::new(x25519(*ephemeral, self.x25519()));
        let pk_x = self.x25519();
        let key = combine(ss_m.as_slice(), &ss_x, &ct_x, &pk_x)?;
        let mut ct = Vec::with_capacity(CIPHERTEXT);
        ct.extend_from_slice(ct_m.as_slice());
        ct.extend_from_slice(&ct_x);
        Ok((ct, key))
    }
}

impl std::fmt::Debug for Kx1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Kx1PublicKey(..)")
    }
}

/// An exchange private key: the ML-KEM seed and the X25519 secret, wiped on drop
#[derive(Clone)]
pub struct Kx1PrivateKey(Zeroizing<[u8; PRIVATE_KEY]>);

impl Kx1PrivateKey {
    pub fn generate() -> Kx1PrivateKey {
        let mut bytes = Zeroizing::new([0u8; PRIVATE_KEY]);
        crate::seal::random(&mut bytes[..]);
        Kx1PrivateKey(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Kx1PrivateKey> {
        let bytes: &[u8; PRIVATE_KEY] = bytes.try_into().map_err(|_| Error::Malformed("a kx1 private key is 96 bytes"))?;
        // Copied into memory that wipes itself, never through a plain array on the stack
        let mut key = Zeroizing::new([0u8; PRIVATE_KEY]);
        key.copy_from_slice(bytes);
        Ok(Kx1PrivateKey(key))
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY] {
        &self.0
    }

    fn decapsulation_key(&self) -> ml_kem_1024::DecapsulationKey {
        // The seed straight into the key, which takes it by value: no named copy of it is left behind
        ml_kem_1024::DecapsulationKey::from_seed(ml_kem::Seed::try_from(&self.0[..64]).expect("64 bytes"))
    }

    fn x25519_secret(&self) -> Zeroizing<[u8; 32]> {
        let mut sk = Zeroizing::new([0u8; 32]);
        sk.copy_from_slice(&self.0[64..]);
        sk
    }

    /// The public key: the encapsulation key of the seed and the X25519 public key of the secret
    pub fn public_key(&self) -> Kx1PublicKey {
        let dk = self.decapsulation_key();
        let mut out = Vec::with_capacity(PUBLIC_KEY);
        out.extend_from_slice(dk.encapsulation_key().to_bytes().as_slice());
        out.extend_from_slice(&x25519(*self.x25519_secret(), X25519_BASEPOINT_BYTES));
        Kx1PublicKey(out.into_boxed_slice().try_into().expect("a whole public key"))
    }

    /// Recomputes the shared secret. ML-KEM rejects implicitly, so a changed ciphertext gives another secret and no error;
    /// an all-zero X25519 secret is an error, and which half failed is never said.
    pub fn decapsulate(&self, ciphertext: &[u8]) -> Result<Key> {
        let ciphertext: &[u8; CIPHERTEXT] = ciphertext.try_into().map_err(|_| Error::Malformed("a kx1 ciphertext is 1600 bytes"))?;
        let ct_m = ml_kem_1024::Ciphertext::try_from(&ciphertext[..MLKEM_PK]).map_err(|_| Error::Unopened)?;
        let ct_x = <[u8; 32]>::try_from(&ciphertext[MLKEM_PK..]).expect("32 bytes");
        let ss_m = self.decapsulation_key().decapsulate(&ct_m);
        let sk_x = self.x25519_secret();
        let ss_x = Zeroizing::new(x25519(*sk_x, ct_x));
        let pk_x = x25519(*sk_x, X25519_BASEPOINT_BYTES);
        combine(ss_m.as_slice(), &ss_x, &ct_x, &pk_x)
    }
}

impl std::fmt::Debug for Kx1PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[key]")
    }
}

fn encapsulation_key(bytes: &[u8]) -> Result<ml_kem_1024::EncapsulationKey> {
    let key = ml_kem::Key::<ml_kem_1024::EncapsulationKey>::try_from(bytes).map_err(|_| Error::Malformed("an ML-KEM-1024 key"))?;
    ml_kem_1024::EncapsulationKey::new(&key).map_err(|_| Error::Malformed("an ML-KEM-1024 encapsulation key"))
}

/// `SHA3-256(label ‖ ss_m ‖ ss_x ‖ ct_x ‖ pk_x)`, once an all-zero `ss_x` is refused. `ct_m` stays out of the hash
/// because ML-KEM's implicit rejection already binds it.
fn combine(ss_m: &[u8], ss_x: &[u8; 32], ct_x: &[u8; 32], pk_x: &[u8; 32]) -> Result<Key> {
    if ss_x.iter().fold(0u8, |sum, b| sum | b) == 0 {
        return Err(Error::Unopened);
    }
    let mut hash = Sha3_256::new();
    hash.update(LABEL);
    hash.update(ss_m);
    hash.update(ss_x);
    hash.update(ct_x);
    hash.update(pk_x);
    let digest = hash.finalize();
    Ok(Key::build(|out| out.copy_from_slice(digest.as_slice())))
}
