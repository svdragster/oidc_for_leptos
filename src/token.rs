use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use serde::{Deserialize, Serialize};

use crate::error::OidcError;
use crate::state::UserInfo;

/// JWT claims extracted from token payload (no signature validation)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JwtClaims {
    #[serde(default)]
    pub sub: Option<String>,
    #[serde(default)]
    pub email: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub preferred_username: Option<String>,
    #[serde(default)]
    pub given_name: Option<String>,
    #[serde(default)]
    pub family_name: Option<String>,
    #[serde(default)]
    pub exp: Option<i64>,
    #[serde(default)]
    pub iat: Option<i64>,
}

/// Decode JWT claims from token payload without signature validation.
/// Safe for tokens already validated by the IdP — SSR just needs user info for rendering.
pub fn decode_claims(jwt: &str) -> Result<JwtClaims, OidcError> {
    let parts: Vec<&str> = jwt.split('.').collect();
    if parts.len() != 3 {
        return Err(OidcError::JwtDecode(format!(
            "expected 3 parts, got {}",
            parts.len()
        )));
    }

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .map_err(|e| OidcError::JwtDecode(format!("base64 decode failed: {}", e)))?;

    let json_str = String::from_utf8(payload_bytes)
        .map_err(|e| OidcError::JwtDecode(format!("invalid UTF-8: {}", e)))?;

    serde_json::from_str(&json_str)
        .map_err(|e| OidcError::JwtDecode(format!("JSON parse failed: {}", e)))
}

/// Extract UserInfo from JWT claims
pub fn extract_user_info(claims: &JwtClaims) -> UserInfo {
    let name = claims.name.clone().or_else(|| {
        match (claims.given_name.as_ref(), claims.family_name.as_ref()) {
            (Some(given), Some(family)) => Some(format!("{} {}", given, family)),
            (Some(given), None) => Some(given.clone()),
            (None, Some(family)) => Some(family.clone()),
            (None, None) => None,
        }
    });

    UserInfo {
        subject: claims.sub.clone().unwrap_or_default(),
        email: claims.email.clone(),
        name,
        preferred_username: claims.preferred_username.clone(),
    }
}

/// Check if token is expired. Missing exp = treated as expired.
pub fn is_expired(claims: &JwtClaims, now_secs: i64, leeway_secs: i64) -> bool {
    match claims.exp {
        Some(exp) => now_secs > exp + leeway_secs,
        None => true,
    }
}

/// Check if token needs proactive refresh (within threshold of expiry)
pub fn needs_refresh(claims: &JwtClaims, now_secs: i64, threshold_secs: i64) -> bool {
    match claims.exp {
        Some(exp) => now_secs + threshold_secs >= exp,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper: encode a JSON payload as a fake JWT (header.payload.signature)
    fn make_jwt(payload: &str) -> String {
        let header = URL_SAFE_NO_PAD.encode(r#"{"alg":"RS256","typ":"JWT"}"#);
        let payload_b64 = URL_SAFE_NO_PAD.encode(payload);
        format!("{}.{}.mock_signature", header, payload_b64)
    }

    #[test]
    fn decode_valid_claims() {
        let jwt = make_jwt(r#"{"sub":"user123","email":"test@example.com","exp":1735689600,"iat":1735686000}"#);
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.email, Some("test@example.com".to_string()));
        assert_eq!(claims.exp, Some(1735689600));
    }

    #[test]
    fn decode_missing_optional_fields() {
        let jwt = make_jwt(r#"{"sub":"user123"}"#);
        let claims = decode_claims(&jwt).unwrap();
        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.email, None);
        assert_eq!(claims.exp, None);
        assert_eq!(claims.name, None);
    }

    #[test]
    fn decode_malformed_not_three_parts() {
        assert!(decode_claims("only.two").is_err());
        assert!(decode_claims("just_one").is_err());
        assert!(decode_claims("a.b.c.d").is_err());
    }

    #[test]
    fn decode_invalid_base64() {
        assert!(decode_claims("header.!!!invalid!!!.sig").is_err());
    }

    #[test]
    fn decode_invalid_json() {
        let bad_json_b64 = URL_SAFE_NO_PAD.encode("not json");
        let jwt = format!("header.{}.sig", bad_json_b64);
        assert!(decode_claims(&jwt).is_err());
    }

    #[test]
    fn extract_user_info_full() {
        let claims = JwtClaims {
            sub: Some("sub123".into()),
            email: Some("user@example.com".into()),
            name: Some("John Doe".into()),
            preferred_username: Some("johnd".into()),
            given_name: None,
            family_name: None,
            exp: Some(9999999999),
            iat: Some(1000000000),
        };
        let info = extract_user_info(&claims);
        assert_eq!(info.subject, "sub123");
        assert_eq!(info.name, Some("John Doe".to_string()));
    }

    #[test]
    fn extract_user_info_from_given_family() {
        let claims = JwtClaims {
            sub: Some("sub".into()),
            name: None,
            given_name: Some("Jane".into()),
            family_name: Some("Smith".into()),
            ..Default::default()
        };
        let info = extract_user_info(&claims);
        assert_eq!(info.name, Some("Jane Smith".to_string()));
    }

    #[test]
    fn is_expired_with_leeway() {
        let claims = JwtClaims {
            exp: Some(1000),
            ..Default::default()
        };
        // now=1030, leeway=60 → 1030 > 1000+60? no
        assert!(!is_expired(&claims, 1030, 60));
        // now=1061, leeway=60 → 1061 > 1000+60? yes
        assert!(is_expired(&claims, 1061, 60));
    }

    #[test]
    fn is_expired_missing_exp() {
        let claims = JwtClaims {
            exp: None,
            ..Default::default()
        };
        assert!(is_expired(&claims, 0, 0));
    }

    #[test]
    fn needs_refresh_within_threshold() {
        let claims = JwtClaims {
            exp: Some(1000),
            ..Default::default()
        };
        // now=800, threshold=300 → 800+300=1100 >= 1000? yes
        assert!(needs_refresh(&claims, 800, 300));
        // now=600, threshold=300 → 600+300=900 >= 1000? no
        assert!(!needs_refresh(&claims, 600, 300));
    }

    // Known JWT test vector (manually constructed)
    #[test]
    fn known_jwt_vector() {
        // Payload: {"sub":"user123","exp":1735689600}
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzM1Njg5NjAwfQ.mock";
        let claims = decode_claims(jwt).unwrap();
        assert_eq!(claims.sub, Some("user123".to_string()));
        assert_eq!(claims.exp, Some(1735689600));
    }
}

// Default impl for test convenience
impl Default for JwtClaims {
    fn default() -> Self {
        Self {
            sub: None,
            email: None,
            name: None,
            preferred_username: None,
            given_name: None,
            family_name: None,
            exp: None,
            iat: None,
        }
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        // decode_claims should never panic on arbitrary input
        #[test]
        fn decode_never_panics(input in "\\PC{0,500}") {
            let _ = decode_claims(&input);
        }
    }
}
