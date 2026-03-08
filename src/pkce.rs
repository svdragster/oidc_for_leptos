use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use sha2::{Digest, Sha256};

use crate::error::OidcError;

/// PKCE challenge pair (RFC 7636)
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The code verifier (stored in cookie, sent during token exchange)
    pub verifier: String,
    /// The code challenge (sent in authorization URL)
    pub challenge: String,
}

/// Generate a new PKCE challenge using S256 method.
/// Uses 32 random bytes → base64url verifier, SHA256 → base64url challenge.
pub fn generate() -> Result<PkceChallenge, OidcError> {
    let mut random_bytes = [0u8; 32];
    getrandom::getrandom(&mut random_bytes)
        .map_err(|e| OidcError::Pkce(format!("failed to generate random bytes: {}", e)))?;

    let verifier = URL_SAFE_NO_PAD.encode(random_bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = URL_SAFE_NO_PAD.encode(hash);

    Ok(PkceChallenge {
        verifier,
        challenge,
    })
}

/// Compute the S256 challenge from a given verifier (for verification/testing)
pub fn compute_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_length_valid() {
        // RFC 7636 Section 4.1: verifier must be 43-128 characters
        let pkce = generate().unwrap();
        assert!(
            pkce.verifier.len() >= 43 && pkce.verifier.len() <= 128,
            "verifier length {} not in 43-128 range",
            pkce.verifier.len()
        );
    }

    #[test]
    fn verifier_is_url_safe() {
        let pkce = generate().unwrap();
        for c in pkce.verifier.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "invalid character in verifier: '{}'",
                c
            );
        }
    }

    #[test]
    fn challenge_matches_verifier() {
        let pkce = generate().unwrap();
        let expected = compute_challenge(&pkce.verifier);
        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn two_calls_produce_different_verifiers() {
        let a = generate().unwrap();
        let b = generate().unwrap();
        assert_ne!(a.verifier, b.verifier);
    }

    #[test]
    fn rfc7636_appendix_b_s256() {
        // RFC 7636 Appendix B test vector
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
        let challenge = compute_challenge(verifier);
        assert_eq!(challenge, expected_challenge);
    }
}
