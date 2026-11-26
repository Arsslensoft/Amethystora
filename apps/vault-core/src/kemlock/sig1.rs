//! `sig1`, the hybrid signing key (`crypto.md`, "`sig1`"): ML-DSA-65 and Ed25519, and a signature passes only when both
//! verify over the same message `m' = "kemlock/v1/sig1" ‖ lp(context) ‖ lp(message)`.
//!
//! - public key: ML-DSA-65 public key (1952) ‖ Ed25519 public key (32), 1984 bytes
//! - private key: ML-DSA-65 seed ξ (32) ‖ Ed25519 seed (32), 64 bytes
//! - signature: ML-DSA-65 signature over `m'` with an empty context (3309) ‖ Ed25519 signature (64), 3373 bytes

use ed25519_dalek::{Signature as EdSignature, Signer, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey};
use ml_dsa::signature::rand_core::{TryCryptoRng, TryRng};
use ml_dsa::{KeyExport, MlDsa65};
use zeroize::Zeroizing;

use super::conv::put_lp;
use super::{Error, Result};

pub const PUBLIC_KEY: usize = 1984;
pub const PRIVATE_KEY: usize = 64;
pub const SIGNATURE: usize = 3373;
const MLDSA_PK: usize = 1952;
const MLDSA_SIG: usize = 3309;
const LABEL: &[u8] = b"kemlock/v1/sig1";

/// The contexts a personal vault signs under (`"confirm"` and `"space-chain"` belong to spaces)
pub const CONTEXT_BUNDLE: &str = "bundle";
pub const CONTEXT_MANIFEST: &str = "manifest";

type MlSigningKey = ml_dsa::SigningKey<MlDsa65>;
type MlVerifyingKey = ml_dsa::VerifyingKey<MlDsa65>;
type MlSignature = ml_dsa::Signature<MlDsa65>;

/// `m'`: the label, then the context and the message each behind its length
fn signed_message(context: &str, message: &[u8]) -> Vec<u8> {
    let mut m = Vec::with_capacity(LABEL.len() + 8 + context.len() + message.len());
    m.extend_from_slice(LABEL);
    put_lp(&mut m, context.as_bytes());
    put_lp(&mut m, message);
    m
}

/// The kernel's random bytes as ML-DSA's hedge
struct Kernel;

impl TryRng for Kernel {
    type Error = std::convert::Infallible;

    fn try_next_u32(&mut self) -> std::result::Result<u32, Self::Error> {
        let b: [u8; 4] = crate::seal::random_array();
        Ok(u32::from_le_bytes(b))
    }

    fn try_next_u64(&mut self) -> std::result::Result<u64, Self::Error> {
        let b: [u8; 8] = crate::seal::random_array();
        Ok(u64::from_le_bytes(b))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> std::result::Result<(), Self::Error> {
        crate::seal::random(dst);
        Ok(())
    }
}

impl TryCryptoRng for Kernel {}

/// A signing public key: 1984 bytes, both halves checked to be points and keys of their kind
#[derive(Clone, PartialEq, Eq)]
pub struct Sig1PublicKey(Box<[u8; PUBLIC_KEY]>);

impl Sig1PublicKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Sig1PublicKey> {
        let bytes: &[u8; PUBLIC_KEY] = bytes.try_into().map_err(|_| Error::Malformed("a sig1 public key is 1984 bytes"))?;
        let ed = <[u8; 32]>::try_from(&bytes[MLDSA_PK..]).expect("32 bytes");
        EdVerifyingKey::from_bytes(&ed).map_err(|_| Error::Malformed("an Ed25519 public key"))?;
        Ok(Sig1PublicKey(Box::new(*bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; PUBLIC_KEY] {
        &self.0
    }

    /// Passes only when the ML-DSA signature and the Ed25519 signature both verify. Which one failed is never said.
    pub fn verify(&self, context: &str, message: &[u8], signature: &[u8]) -> Result<()> {
        let signature: &[u8; SIGNATURE] = signature.try_into().map_err(|_| Error::Malformed("a sig1 signature is 3373 bytes"))?;
        let m = signed_message(context, message);
        let encoded = ml_dsa::EncodedVerifyingKey::<MlDsa65>::try_from(&self.0[..MLDSA_PK]).map_err(|_| Error::Unopened);
        let ml_sig = MlSignature::try_from(&signature[..MLDSA_SIG]).map_err(|_| Error::Unopened);
        let ed_pk = <[u8; 32]>::try_from(&self.0[MLDSA_PK..]).expect("32 bytes");
        let ed_pk = EdVerifyingKey::from_bytes(&ed_pk).map_err(|_| Error::Unopened);
        let ed_bytes = <[u8; 64]>::try_from(&signature[MLDSA_SIG..]).expect("64 bytes");
        let ed_sig = EdSignature::from_bytes(&ed_bytes);
        // Both halves always run, so that the time says nothing about which failed
        let ml_ok = match (encoded, ml_sig) {
            (Ok(encoded), Ok(sig)) => MlVerifyingKey::decode(&encoded).verify_with_context(&m, &[], &sig),
            _ => false,
        };
        let ed_ok = match ed_pk {
            Ok(pk) => pk.verify_strict(&m, &ed_sig).is_ok(),
            Err(_) => false,
        };
        if ml_ok & ed_ok { Ok(()) } else { Err(Error::Unopened) }
    }
}

impl std::fmt::Debug for Sig1PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Sig1PublicKey(..)")
    }
}

/// A signing private key: the two seeds, wiped on drop
#[derive(Clone)]
pub struct Sig1PrivateKey(Zeroizing<[u8; PRIVATE_KEY]>);

impl Sig1PrivateKey {
    pub fn generate() -> Sig1PrivateKey {
        let mut bytes = Zeroizing::new([0u8; PRIVATE_KEY]);
        crate::seal::random(&mut bytes[..]);
        Sig1PrivateKey(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Sig1PrivateKey> {
        let bytes: &[u8; PRIVATE_KEY] = bytes.try_into().map_err(|_| Error::Malformed("a sig1 private key is 64 bytes"))?;
        Ok(Sig1PrivateKey(Zeroizing::new(*bytes)))
    }

    pub fn as_bytes(&self) -> &[u8; PRIVATE_KEY] {
        &self.0
    }

    fn ml_key(&self) -> MlSigningKey {
        let mut xi = ml_dsa::Seed::default();
        xi.copy_from_slice(&self.0[..32]);
        MlSigningKey::from_seed(&xi)
    }

    fn ed_key(&self) -> EdSigningKey {
        let mut seed = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&self.0[32..]);
        EdSigningKey::from_bytes(&seed)
    }

    pub fn public_key(&self) -> Sig1PublicKey {
        let mut out = Vec::with_capacity(PUBLIC_KEY);
        out.extend_from_slice(ml_dsa::Keypair::verifying_key(&self.ml_key()).to_bytes().as_slice());
        out.extend_from_slice(self.ed_key().verifying_key().as_bytes());
        Sig1PublicKey(out.into_boxed_slice().try_into().expect("a whole public key"))
    }

    /// A signature under `context`, with ML-DSA hedged by fresh randomness (verifiers accept hedged and deterministic)
    pub fn sign(&self, context: &str, message: &[u8]) -> Result<Vec<u8>> {
        let m = signed_message(context, message);
        let ml = self.ml_key().expanded_key().sign_randomized(&m, &[], &mut Kernel).map_err(|_| Error::Unopened)?;
        Ok(self.join(&m, &ml))
    }

    /// With ML-DSA deterministic: the vectors' signatures are
    #[cfg(test)]
    pub(crate) fn sign_deterministic(&self, context: &str, message: &[u8]) -> Result<Vec<u8>> {
        let m = signed_message(context, message);
        let ml = self.ml_key().expanded_key().sign_deterministic(&m, &[]).map_err(|_| Error::Unopened)?;
        Ok(self.join(&m, &ml))
    }

    fn join(&self, m: &[u8], ml: &MlSignature) -> Vec<u8> {
        let mut out = Vec::with_capacity(SIGNATURE);
        out.extend_from_slice(ml.encode().as_slice());
        out.extend_from_slice(&self.ed_key().sign(m).to_bytes());
        out
    }
}

impl std::fmt::Debug for Sig1PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[key]")
    }
}
