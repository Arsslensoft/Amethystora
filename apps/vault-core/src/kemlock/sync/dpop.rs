//! DPoP (RFC 9449), as Kemlock's API asks it of every client (`spec-protocol.md` 3): a proof is a compact JWS signed with a key
//! this connection made once, naming the method and the address it is for, the time, a fresh id, the hash of the access token it
//! goes with and the server's last nonce. The key is Ed25519 (EdDSA): the server takes it, and Ed25519 is in the Vault already.

use ed25519_dalek::{Signer, SigningKey};
use serde_json::json;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::kemlock::conv::b64_encode;

/// The key a connection signs its proofs with. The tokens a server issues are bound to its thumbprint, so losing it means
/// signing in again.
pub struct DpopKey {
    seed: Zeroizing<[u8; 32]>,
}

impl DpopKey {
    pub fn generate() -> DpopKey {
        let mut seed = Zeroizing::new([0u8; 32]);
        crate::seal::random(&mut seed[..]);
        DpopKey { seed }
    }

    pub fn from_hex(text: &str) -> Option<DpopKey> {
        let bytes = Zeroizing::new(crate::seal::unhex(text)?);
        let seed: [u8; 32] = bytes.as_slice().try_into().ok()?;
        Some(DpopKey { seed: Zeroizing::new(seed) })
    }

    pub fn to_hex(&self) -> Zeroizing<String> {
        Zeroizing::new(crate::seal::hex(&self.seed[..]))
    }

    fn signing(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }

    fn x(&self) -> String {
        b64_encode(&self.signing().verifying_key().to_bytes())
    }

    /// The public key as a JWK: no private member, ever
    pub fn jwk(&self) -> serde_json::Value {
        json!({"kty": "OKP", "crv": "Ed25519", "x": self.x()})
    }

    /// RFC 7638's thumbprint: the SHA-256 of the JWK's required members in order, as base64url
    pub fn thumbprint(&self) -> String {
        let canonical = format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", self.x());
        b64_encode(&Sha256::digest(canonical.as_bytes()))
    }

    /// A proof for one request. `htu` is the URL as it will be sent, which this reduces to scheme, host, port and path; `ath` is the
    /// access token the request carries, if it carries one; `nonce` the server's last.
    pub fn proof(&self, method: &str, url: &str, access_token: Option<&str>, nonce: Option<&str>, iat: i64) -> String {
        let mut jti = [0u8; 16];
        crate::seal::random(&mut jti);
        self.proof_with(method, url, access_token, nonce, iat, &b64_encode(&jti))
    }

    pub fn proof_with(&self, method: &str, url: &str, access_token: Option<&str>, nonce: Option<&str>, iat: i64, jti: &str) -> String {
        let header = json!({"typ": "dpop+jwt", "alg": "EdDSA", "jwk": self.jwk()});
        let mut claims = json!({"jti": jti, "htm": method, "htu": htu(url), "iat": iat});
        if let Some(token) = access_token {
            claims["ath"] = json!(ath(token));
        }
        if let Some(nonce) = nonce {
            claims["nonce"] = json!(nonce);
        }
        let signing_input = format!("{}.{}", b64_encode(header.to_string().as_bytes()), b64_encode(claims.to_string().as_bytes()));
        let signature = self.signing().sign(signing_input.as_bytes());
        format!("{signing_input}.{}", b64_encode(&signature.to_bytes()))
    }
}

/// The hash a proof carries for the access token it goes with
pub fn ath(token: &str) -> String {
    b64_encode(&Sha256::digest(token.as_bytes()))
}

/// What the server compares: scheme and host in lower case, a default port dropped, the path as it is, no query, no fragment
pub fn htu(url: &str) -> String {
    let url = url.split('#').next().unwrap_or("");
    let url = url.split('?').next().unwrap_or("");
    let Some((scheme, rest)) = url.split_once("://") else { return url.to_string() };
    let scheme = scheme.to_ascii_lowercase();
    let (authority, path) = match rest.find('/') {
        Some(at) => (&rest[..at], &rest[at..]),
        None => (rest, ""),
    };
    let authority = authority.to_ascii_lowercase();
    let default = if scheme == "https" { ":443" } else { ":80" };
    let authority = authority.strip_suffix(default).unwrap_or(&authority);
    format!("{scheme}://{authority}{path}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use ed25519_dalek::{Signature, Verifier};

    fn parts(proof: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let [header, claims, signature]: [&str; 3] = proof.split('.').collect::<Vec<_>>().try_into().unwrap();
        let decode = |part: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(part).unwrap();
        (serde_json::from_slice(&decode(header)).unwrap(), serde_json::from_slice(&decode(claims)).unwrap(), decode(signature))
    }

    #[test]
    fn a_proof_names_the_request_and_verifies_under_its_own_key() {
        let key = DpopKey::generate();
        let proof = key.proof_with("POST", "HTTP://Example.TEST:80/kem/v1/items:batch?x=1#y", Some("token"), Some("n1"), 1_764_000_000, "j1");
        let (header, claims, signature) = parts(&proof);
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["alg"], "EdDSA");
        assert_eq!(header["jwk"], key.jwk());
        assert!(header["jwk"].get("d").is_none(), "a JWK with a private member is refused");
        assert_eq!(claims["htm"], "POST");
        assert_eq!(claims["htu"], "http://example.test/kem/v1/items:batch");
        assert_eq!(claims["iat"], 1_764_000_000);
        assert_eq!(claims["jti"], "j1");
        assert_eq!(claims["nonce"], "n1");
        assert_eq!(claims["ath"], ath("token"));
        // Over the ASCII of `header.claims`, as 64 raw bytes
        let (signing_input, _) = proof.rsplit_once('.').unwrap();
        let public = key.signing().verifying_key();
        assert!(public.verify(signing_input.as_bytes(), &Signature::from_slice(&signature).unwrap()).is_ok());
    }

    #[test]
    fn a_sign_in_proof_has_no_ath_and_the_first_has_no_nonce() {
        let key = DpopKey::generate();
        let (_, claims, _) = parts(&key.proof("GET", "https://a.test/kem/v1/config", None, None, 5));
        assert!(claims.get("ath").is_none() && claims.get("nonce").is_none());
        // Fresh ids, so a replay of one is the only way to be refused for it
        let again = parts(&key.proof("GET", "https://a.test/kem/v1/config", None, None, 5)).1;
        assert_ne!(claims["jti"], again["jti"]);
    }

    #[test]
    fn the_thumbprint_is_rfc_7638s_and_the_key_round_trips() {
        let key = DpopKey::generate();
        let expected = b64_encode(&Sha256::digest(format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{}\"}}", key.jwk()["x"].as_str().unwrap()).as_bytes()));
        assert_eq!(key.thumbprint(), expected);
        let back = DpopKey::from_hex(&key.to_hex()).unwrap();
        assert_eq!(back.thumbprint(), key.thumbprint());
        assert!(DpopKey::from_hex("00").is_none());
    }

    #[test]
    fn htu_drops_the_default_port_the_query_and_the_fragment() {
        assert_eq!(htu("https://A.test:443/kem/v1/sync?since=x"), "https://a.test/kem/v1/sync");
        assert_eq!(htu("https://a.test:8443/p"), "https://a.test:8443/p");
        assert_eq!(htu("http://127.0.0.1:18299/kem/v1/config"), "http://127.0.0.1:18299/kem/v1/config");
        assert_eq!(htu("https://a.test"), "https://a.test");
    }
}
