//! ES256 signing key for OxiCloud's OpenID Provider.
//!
//! The key is derived deterministically from the server's JWT secret with
//! a domain-separation label, so it survives restarts without a new piece
//! of key material to store, back up or lose. Rotating the JWT secret
//! rotates this key too; relying parties re-fetch the JWKS by `kid`.
//!
//! Derivation is `SHA-256(label ‖ 0x00 ‖ secret ‖ counter)` until the digest
//! is a valid P-256 scalar (first try with overwhelming probability). The
//! JWT secret is required to be high-entropy (≥ 32 chars, enforced at
//! config load), which is what makes a plain hash an adequate KDF here.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use p256::ecdsa::{Signature, SigningKey, signature::Signer};
use sha2::{Digest, Sha256};

use crate::application::ports::idp_ports::IdpTokenSignerPort;
use crate::common::errors::DomainError;

const LABEL: &[u8] = b"oxicloud/idp/es256/v1";

pub struct IdpSigningKey {
    key: SigningKey,
    kid: String,
    x: String,
    y: String,
}

impl IdpSigningKey {
    pub fn derive(secret: &str) -> Self {
        let key = (0u32..)
            .find_map(|counter| {
                let mut h = Sha256::new();
                h.update(LABEL);
                h.update([0u8]);
                h.update(secret.as_bytes());
                h.update(counter.to_be_bytes());
                SigningKey::from_slice(&h.finalize()).ok()
            })
            .expect("a valid P-256 scalar is found within a few attempts");

        let point = key.verifying_key().to_encoded_point(false);
        let x = URL_SAFE_NO_PAD.encode(point.x().expect("uncompressed point has x"));
        let y = URL_SAFE_NO_PAD.encode(point.y().expect("uncompressed point has y"));
        // RFC 7638 thumbprint as kid: stable for the key, changes with it.
        let thumbprint_input = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
        let kid = URL_SAFE_NO_PAD.encode(Sha256::digest(thumbprint_input.as_bytes()));

        Self { key, kid, x, y }
    }
}

impl IdpTokenSignerPort for IdpSigningKey {
    fn sign(&self, claims: &serde_json::Value) -> Result<String, DomainError> {
        let header = serde_json::json!({ "alg": "ES256", "typ": "JWT", "kid": self.kid });
        let enc = |v: &serde_json::Value| {
            serde_json::to_vec(v)
                .map(|b| URL_SAFE_NO_PAD.encode(b))
                .map_err(|e| DomainError::internal_error("IdpSigningKey", e.to_string()))
        };
        let signing_input = format!("{}.{}", enc(&header)?, enc(claims)?);
        let sig: Signature = self.key.sign(signing_input.as_bytes());
        // JWS ES256 wants the fixed-size r‖s form, not DER (RFC 7518 §3.4).
        Ok(format!(
            "{signing_input}.{}",
            URL_SAFE_NO_PAD.encode(sig.to_bytes())
        ))
    }

    fn jwks(&self) -> serde_json::Value {
        serde_json::json!({
            "keys": [{
                "kty": "EC",
                "crv": "P-256",
                "x": self.x,
                "y": self.y,
                "use": "sig",
                "alg": "ES256",
                "kid": self.kid,
            }]
        })
    }

    fn algorithm(&self) -> &'static str {
        "ES256"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};

    const SECRET: &str = "test-secret-do-not-use-in-prod-minimum-32-chars";

    #[test]
    fn derivation_is_deterministic_and_secret_bound() {
        let a = IdpSigningKey::derive(SECRET);
        let b = IdpSigningKey::derive(SECRET);
        let c = IdpSigningKey::derive("another-secret-another-secret-another");
        assert_eq!(a.kid, b.kid);
        assert_ne!(a.kid, c.kid);
    }

    /// Interop pin: a token we sign must verify with an independent JOSE
    /// implementation using only the published JWKS.
    #[test]
    fn signed_token_verifies_against_published_jwks() {
        let k = IdpSigningKey::derive(SECRET);
        let now = chrono::Utc::now().timestamp();
        let token = k
            .sign(&serde_json::json!({
                "iss": "https://cloud.example.org",
                "sub": "u1",
                "aud": "chat",
                "iat": now,
                "exp": now + 60,
            }))
            .unwrap();

        let jwk = &k.jwks()["keys"][0];
        assert_eq!(
            decode_header(&token).unwrap().kid.as_deref(),
            jwk["kid"].as_str()
        );
        let key =
            DecodingKey::from_ec_components(jwk["x"].as_str().unwrap(), jwk["y"].as_str().unwrap())
                .unwrap();
        let mut v = Validation::new(Algorithm::ES256);
        v.set_audience(&["chat"]);
        v.set_issuer(&["https://cloud.example.org"]);
        let data = decode::<serde_json::Value>(&token, &key, &v).unwrap();
        assert_eq!(data.claims["sub"], "u1");

        // Tampering breaks it.
        let mut parts: Vec<&str> = token.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(
            br#"{"sub":"admin","aud":"chat","exp":9999999999,"iss":"https://cloud.example.org"}"#,
        );
        parts[1] = &forged;
        assert!(decode::<serde_json::Value>(&parts.join("."), &key, &v).is_err());
    }
}
