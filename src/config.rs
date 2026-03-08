use serde::{Deserialize, Serialize};

/// OIDC configuration for the authentication library
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// OIDC issuer URL (e.g. "https://auth.example.com")
    pub issuer: String,
    /// OAuth2 client ID
    pub client_id: String,
    /// OAuth2 redirect URI for callback
    pub redirect_uri: String,
    /// URI to redirect to after logout
    pub post_logout_redirect_uri: String,
    /// OAuth2 scopes to request
    pub scopes: Vec<String>,
    /// Cookie domain for cross-subdomain sharing (e.g. ".example.com")
    pub cookie_domain: Option<String>,
    /// Prefix for cookie names (default: "oidc_")
    pub cookie_name_prefix: String,
    /// Force Secure flag on cookies (default: auto-detect from protocol)
    pub cookie_secure: Option<bool>,
    /// Whether to store id_token in cookies (default: false, saves space)
    pub store_id_token: bool,
    /// Seconds before expiry to trigger refresh (default: 300 = 5 min)
    pub refresh_threshold_secs: u64,
    /// Clock skew leeway for expiry checks (default: 60)
    pub clock_skew_leeway_secs: u64,
    /// Override token endpoint (default: {issuer}/oauth/v2/token)
    pub token_endpoint: Option<String>,
    /// Override authorization endpoint (default: {issuer}/oauth/v2/authorize)
    pub authorization_endpoint: Option<String>,
    /// Override end_session endpoint (default: {issuer}/oidc/v1/end_session)
    pub end_session_endpoint: Option<String>,
}

impl Default for OidcConfig {
    fn default() -> Self {
        Self {
            issuer: String::new(),
            client_id: String::new(),
            redirect_uri: String::new(),
            post_logout_redirect_uri: String::new(),
            scopes: vec![
                "openid".into(),
                "profile".into(),
                "email".into(),
                "offline_access".into(),
            ],
            cookie_domain: None,
            cookie_name_prefix: "oidc_".into(),
            cookie_secure: None,
            store_id_token: false,
            refresh_threshold_secs: 300,
            clock_skew_leeway_secs: 60,
            token_endpoint: None,
            authorization_endpoint: None,
            end_session_endpoint: None,
        }
    }
}

impl OidcConfig {
    /// Normalized issuer URL (trailing slash removed)
    fn normalized_issuer(&self) -> &str {
        self.issuer.trim_end_matches('/')
    }

    /// Token endpoint URL
    pub fn token_endpoint(&self) -> String {
        self.token_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/v2/token", self.normalized_issuer()))
    }

    /// Authorization endpoint URL
    pub fn authorization_endpoint(&self) -> String {
        self.authorization_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oauth/v2/authorize", self.normalized_issuer()))
    }

    /// End session endpoint URL
    pub fn end_session_endpoint(&self) -> String {
        self.end_session_endpoint
            .clone()
            .unwrap_or_else(|| format!("{}/oidc/v1/end_session", self.normalized_issuer()))
    }

    /// Build a cookie name with the configured prefix
    pub fn cookie_name(&self, suffix: &str) -> String {
        format!("{}{}", self.cookie_name_prefix, suffix)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_scopes() {
        let config = OidcConfig::default();
        assert_eq!(
            config.scopes,
            vec!["openid", "profile", "email", "offline_access"]
        );
    }

    #[test]
    fn default_prefix() {
        let config = OidcConfig::default();
        assert_eq!(config.cookie_name_prefix, "oidc_");
        assert_eq!(config.cookie_name("access_token"), "oidc_access_token");
    }

    #[test]
    fn trailing_slash_normalization() {
        let config = OidcConfig {
            issuer: "https://auth.example.com/".into(),
            ..Default::default()
        };
        assert_eq!(
            config.token_endpoint(),
            "https://auth.example.com/oauth/v2/token"
        );
        assert_eq!(
            config.authorization_endpoint(),
            "https://auth.example.com/oauth/v2/authorize"
        );
        assert_eq!(
            config.end_session_endpoint(),
            "https://auth.example.com/oidc/v1/end_session"
        );
    }

    #[test]
    fn no_trailing_slash() {
        let config = OidcConfig {
            issuer: "https://auth.example.com".into(),
            ..Default::default()
        };
        assert_eq!(
            config.token_endpoint(),
            "https://auth.example.com/oauth/v2/token"
        );
    }

    #[test]
    fn custom_endpoints_override_defaults() {
        let config = OidcConfig {
            issuer: "https://auth.example.com".into(),
            token_endpoint: Some("https://custom.example.com/token".into()),
            authorization_endpoint: Some("https://custom.example.com/auth".into()),
            end_session_endpoint: Some("https://custom.example.com/logout".into()),
            ..Default::default()
        };
        assert_eq!(config.token_endpoint(), "https://custom.example.com/token");
        assert_eq!(
            config.authorization_endpoint(),
            "https://custom.example.com/auth"
        );
        assert_eq!(
            config.end_session_endpoint(),
            "https://custom.example.com/logout"
        );
    }
}
