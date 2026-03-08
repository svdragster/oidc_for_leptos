/// All error types for oidc_for_leptos
#[derive(thiserror::Error, Debug, Clone)]
pub enum OidcError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("PKCE error: {0}")]
    Pkce(String),

    #[error("Token exchange failed: {0}")]
    TokenExchange(String),

    #[error("Token refresh failed: {0}")]
    TokenRefresh(String),

    #[error("Token was revoked by the auth server")]
    TokenRevoked,

    #[error("Token already refreshed by another tab")]
    AlreadyRefreshed,

    #[error("No refresh token available")]
    NoRefreshToken,

    #[error("JWT decode error: {0}")]
    JwtDecode(String),

    #[error("Cookie error: {0}")]
    Cookie(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("OAuth callback error: {kind}: {description}")]
    Callback { kind: String, description: String },

    #[error("OIDC discovery error: {0}")]
    Discovery(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_variants_display() {
        let errors = vec![
            OidcError::Config("bad config".into()),
            OidcError::Pkce("bad pkce".into()),
            OidcError::TokenExchange("exchange failed".into()),
            OidcError::TokenRefresh("refresh failed".into()),
            OidcError::TokenRevoked,
            OidcError::AlreadyRefreshed,
            OidcError::NoRefreshToken,
            OidcError::JwtDecode("bad jwt".into()),
            OidcError::Cookie("cookie fail".into()),
            OidcError::Network("network fail".into()),
            OidcError::Callback {
                kind: "access_denied".into(),
                description: "user denied".into(),
            },
            OidcError::Discovery("discovery fail".into()),
        ];

        for e in &errors {
            assert!(!format!("{}", e).is_empty());
        }
    }
}
