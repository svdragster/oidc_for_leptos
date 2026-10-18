/// Cookie name suffixes
pub const ACCESS_TOKEN: &str = "access_token";
pub const REFRESH_TOKEN: &str = "refresh_token";
pub const ID_TOKEN: &str = "id_token";
pub const EXPIRES_AT: &str = "expires_at";
pub const PKCE_VERIFIER: &str = "verifier";
pub const OAUTH_STATE: &str = "state";
pub const USER_INFO: &str = "user_info";
/// Marker cookie: `0` = this login keeps its token cookies for the browser
/// session only ([`crate::config::OidcConfig::session_cookies_param`]).
pub const PERSIST: &str = "persist";

/// Lifetime of persistent token cookies: 180 days (typical refresh-token cap).
pub const TOKEN_COOKIE_MAX_AGE_SECS: i64 = 180 * 24 * 60 * 60;

/// Container for reading all token cookies at once
#[derive(Debug, Clone)]
pub struct TokenCookies {
    pub access_token: String,
    pub refresh_token: String,
    pub id_token: Option<String>,
    pub expires_at: i64,
}

/// Parse a specific cookie value from a cookie string (shared, platform-independent)
pub fn parse_cookie_value(cookie_string: &str, name: &str) -> Option<String> {
    for pair in cookie_string.split(';') {
        let pair = pair.trim();
        if let Some((key, value)) = pair.split_once('=') {
            if key.trim() == name {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

/// Cookie attribute string. `max_age_secs: None` = session cookie (no
/// Max-Age/Expires: the browser drops it when it closes).
pub fn cookie_attributes(max_age_secs: Option<i64>, domain: Option<&str>, secure: bool) -> String {
    let mut attrs = String::from("Path=/");
    if let Some(max_age) = max_age_secs {
        attrs.push_str(&format!("; Max-Age={}", max_age));
    }
    attrs.push_str("; SameSite=Lax");
    if let Some(domain) = domain {
        attrs.push_str(&format!("; Domain={}", domain));
    }
    if secure {
        attrs.push_str("; Secure");
    }
    attrs
}

/// Max-Age for token cookies: None (session cookie) when the login opted out
/// of persistence, else [`TOKEN_COOKIE_MAX_AGE_SECS`].
pub fn token_cookie_max_age(session_only: bool) -> Option<i64> {
    (!session_only).then_some(TOKEN_COOKIE_MAX_AGE_SECS)
}

// -- Browser cookie operations --
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod browser {
    use super::*;
    use crate::config::OidcConfig;
    use wasm_bindgen::JsCast;

    fn get_document() -> Option<web_sys::HtmlDocument> {
        web_sys::window()?
            .document()?
            .dyn_into::<web_sys::HtmlDocument>()
            .ok()
    }

    /// Auto-detect whether to set Secure flag based on protocol
    fn should_use_secure(config: &OidcConfig) -> bool {
        if let Some(secure) = config.cookie_secure {
            return secure;
        }
        if let Some(window) = web_sys::window() {
            if let Ok(protocol) = window.location().protocol() {
                return protocol == "https:";
            }
        }
        true
    }

    /// Build cookie attribute string (None = session cookie)
    fn cookie_attrs(config: &OidcConfig, max_age_secs: Option<i64>) -> String {
        cookie_attributes(max_age_secs, config.cookie_domain.as_deref(), should_use_secure(config))
    }

    /// Read a single cookie by name
    pub fn read_cookie(name: &str) -> Option<String> {
        let document = get_document()?;
        let cookie_string = document.cookie().ok()?;
        parse_cookie_value(&cookie_string, name)
    }

    /// Write a single cookie
    pub fn write_cookie(name: &str, value: &str, config: &OidcConfig, max_age_secs: i64) {
        write_cookie_with(name, value, config, Some(max_age_secs));
    }

    /// Write a single cookie; `max_age_secs: None` = session cookie.
    pub fn write_cookie_with(name: &str, value: &str, config: &OidcConfig, max_age_secs: Option<i64>) {
        let Some(document) = get_document() else {
            return;
        };
        let attrs = cookie_attrs(config, max_age_secs);
        let cookie = format!("{}={}; {}", name, value, attrs);
        let _ = document.set_cookie(&cookie);
    }

    /// Remember whether this login keeps its token cookies for the browser
    /// session only (`true`) or persistently (`false`, the default). The
    /// marker itself is a session cookie, so it can never outlive the tokens.
    pub fn set_session_only(config: &OidcConfig, session_only: bool) {
        let name = config.cookie_name(PERSIST);
        if session_only {
            write_cookie_with(&name, "0", config, None);
        } else {
            clear_cookie(&name, config);
        }
    }

    /// Whether the current login keeps its token cookies for the session only.
    pub fn is_session_only(config: &OidcConfig) -> bool {
        read_cookie(&config.cookie_name(PERSIST)).as_deref() == Some("0")
    }

    /// Clear a single cookie by setting it to expire
    pub fn clear_cookie(name: &str, config: &OidcConfig) {
        let Some(document) = get_document() else {
            return;
        };
        let mut clear = format!(
            "{}=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT",
            name
        );
        if let Some(ref domain) = config.cookie_domain {
            clear.push_str(&format!("; Domain={}", domain));
        }
        let _ = document.set_cookie(&clear);
    }

    /// Read all token cookies. Returns None if access_token or refresh_token missing.
    pub fn read_tokens(config: &OidcConfig) -> Option<TokenCookies> {
        let document = get_document()?;
        let cookie_string = document.cookie().ok()?;

        let access_token =
            parse_cookie_value(&cookie_string, &config.cookie_name(ACCESS_TOKEN))?;
        let refresh_token =
            parse_cookie_value(&cookie_string, &config.cookie_name(REFRESH_TOKEN))?;
        let id_token =
            parse_cookie_value(&cookie_string, &config.cookie_name(ID_TOKEN));
        let expires_at_str =
            parse_cookie_value(&cookie_string, &config.cookie_name(EXPIRES_AT))?;
        let expires_at = expires_at_str.parse::<i64>().ok()?;

        Some(TokenCookies {
            access_token,
            refresh_token,
            id_token,
            expires_at,
        })
    }

    /// Write all token cookies
    pub fn write_tokens(
        config: &OidcConfig,
        access_token: &str,
        refresh_token: &str,
        id_token: Option<&str>,
        expires_at: i64,
    ) {
        // 180 days, or a session cookie when this login opted out of
        // persistence (refreshes keep that choice via the PERSIST marker).
        let max_age = token_cookie_max_age(is_session_only(config));

        write_cookie_with(
            &config.cookie_name(ACCESS_TOKEN),
            access_token,
            config,
            max_age,
        );
        write_cookie_with(
            &config.cookie_name(REFRESH_TOKEN),
            refresh_token,
            config,
            max_age,
        );
        if config.store_id_token {
            if let Some(id_token) = id_token {
                write_cookie_with(
                    &config.cookie_name(ID_TOKEN),
                    id_token,
                    config,
                    max_age,
                );
            }
        }
        write_cookie_with(
            &config.cookie_name(EXPIRES_AT),
            &expires_at.to_string(),
            config,
            max_age,
        );
    }

    /// Clear all token and auth-related cookies
    pub fn clear_tokens(config: &OidcConfig) {
        clear_cookie(&config.cookie_name(ACCESS_TOKEN), config);
        clear_cookie(&config.cookie_name(REFRESH_TOKEN), config);
        clear_cookie(&config.cookie_name(ID_TOKEN), config);
        clear_cookie(&config.cookie_name(EXPIRES_AT), config);
        clear_cookie(&config.cookie_name(USER_INFO), config);
        clear_cookie(&config.cookie_name(PERSIST), config);
    }

    /// Write PKCE verifier to a short-lived cookie (5 min)
    pub fn write_pkce_verifier(config: &OidcConfig, verifier: &str) {
        write_cookie(
            &config.cookie_name(PKCE_VERIFIER),
            verifier,
            config,
            300, // 5 minutes
        );
    }

    /// Read PKCE verifier from cookie
    pub fn read_pkce_verifier(config: &OidcConfig) -> Option<String> {
        read_cookie(&config.cookie_name(PKCE_VERIFIER))
    }

    /// Clear PKCE verifier cookie
    pub fn clear_pkce_verifier(config: &OidcConfig) {
        clear_cookie(&config.cookie_name(PKCE_VERIFIER), config);
    }

    /// Write OAuth state parameter to a short-lived cookie (5 min) for CSRF verification
    pub fn write_oauth_state(config: &OidcConfig, state: &str) {
        write_cookie(
            &config.cookie_name(OAUTH_STATE),
            state,
            config,
            300, // 5 minutes — same as PKCE verifier
        );
    }

    /// Read OAuth state parameter from cookie
    pub fn read_oauth_state(config: &OidcConfig) -> Option<String> {
        read_cookie(&config.cookie_name(OAUTH_STATE))
    }

    /// Clear OAuth state cookie
    pub fn clear_oauth_state(config: &OidcConfig) {
        clear_cookie(&config.cookie_name(OAUTH_STATE), config);
    }

    /// Write serialized UserInfo to cookie (fallback for opaque access tokens in SSR)
    pub fn write_user_info(config: &OidcConfig, user_info: &crate::state::UserInfo) {
        if let Ok(json) = serde_json::to_string(user_info) {
            // URL-encode the JSON so it's safe in a cookie value
            let encoded = js_sys::encode_uri_component(&json)
                .as_string()
                .unwrap_or_default();
            write_cookie_with(
                &config.cookie_name(USER_INFO),
                &encoded,
                config,
                token_cookie_max_age(is_session_only(config)),
            );
        }
    }

    /// Read UserInfo from cookie
    pub fn read_user_info(config: &OidcConfig) -> Option<crate::state::UserInfo> {
        let encoded = read_cookie(&config.cookie_name(USER_INFO))?;
        let json = js_sys::decode_uri_component(&encoded)
            .ok()?
            .as_string()?;
        serde_json::from_str(&json).ok()
    }

    /// Clear UserInfo cookie
    pub fn clear_user_info(config: &OidcConfig) {
        clear_cookie(&config.cookie_name(USER_INFO), config);
    }
}

// -- SSR cookie reading from HTTP request --
#[cfg(feature = "ssr")]
pub mod server {
    use super::*;
    use crate::config::OidcConfig;

    /// Read token cookies from the current actix-web request
    pub fn read_tokens_from_request(config: &OidcConfig) -> Option<TokenCookies> {
        // HttpRequest is provided via Leptos context during SSR
        let req: actix_web::HttpRequest = leptos::prelude::use_context()?;

        let access_token = req
            .cookie(&config.cookie_name(ACCESS_TOKEN))
            .map(|c| c.value().to_string())?;
        let refresh_token = req
            .cookie(&config.cookie_name(REFRESH_TOKEN))
            .map(|c| c.value().to_string())?;
        let id_token = req
            .cookie(&config.cookie_name(ID_TOKEN))
            .map(|c| c.value().to_string());
        let expires_at_str = req
            .cookie(&config.cookie_name(EXPIRES_AT))
            .map(|c| c.value().to_string())?;
        let expires_at = expires_at_str.parse::<i64>().ok()?;

        Some(TokenCookies {
            access_token,
            refresh_token,
            id_token,
            expires_at,
        })
    }

    /// Read UserInfo from cookie (SSR fallback for opaque access tokens).
    /// The browser writes this cookie URL-encoded via encodeURIComponent.
    pub fn read_user_info_from_request(config: &OidcConfig) -> Option<crate::state::UserInfo> {
        let req: actix_web::HttpRequest = leptos::prelude::use_context()?;
        let encoded = req
            .cookie(&config.cookie_name(USER_INFO))
            .map(|c| c.value().to_string())?;
        // Percent-decode the cookie value to get the JSON string
        let decoded = percent_decode(&encoded);
        serde_json::from_str(&decoded).ok()
    }

    /// Simple percent-decoding for cookie values written by encodeURIComponent.
    /// Handles %XX sequences; non-encoded chars pass through unchanged.
    pub(crate) fn percent_decode(input: &str) -> String {
        let mut result = String::with_capacity(input.len());
        let mut chars = input.chars();
        while let Some(c) = chars.next() {
            if c == '%' {
                let hex: String = chars.by_ref().take(2).collect();
                if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                    result.push(byte as char);
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            } else {
                result.push(c);
            }
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cookie_value_basic() {
        let cookies = "foo=bar; oidc_access_token=abc123; baz=qux";
        assert_eq!(
            parse_cookie_value(cookies, "oidc_access_token"),
            Some("abc123".into())
        );
        assert_eq!(parse_cookie_value(cookies, "foo"), Some("bar".into()));
        assert_eq!(parse_cookie_value(cookies, "missing"), None);
    }

    #[test]
    fn parse_cookie_value_with_spaces() {
        let cookies = " foo = bar ; oidc_access_token = abc123 ";
        assert_eq!(
            parse_cookie_value(cookies, "oidc_access_token"),
            Some("abc123".into())
        );
    }

    #[test]
    fn parse_cookie_value_empty_string() {
        assert_eq!(parse_cookie_value("", "anything"), None);
    }

    #[test]
    fn parse_cookie_value_no_equals() {
        assert_eq!(parse_cookie_value("nopair", "nopair"), None);
    }

    #[test]
    fn persistent_cookie_attributes() {
        assert_eq!(
            cookie_attributes(Some(300), None, true),
            "Path=/; Max-Age=300; SameSite=Lax; Secure"
        );
        assert_eq!(
            cookie_attributes(Some(0), Some(".example.com"), false),
            "Path=/; Max-Age=0; SameSite=Lax; Domain=.example.com"
        );
    }

    #[test]
    fn session_cookie_attributes_have_no_lifetime() {
        let attrs = cookie_attributes(None, None, true);
        assert_eq!(attrs, "Path=/; SameSite=Lax; Secure");
        assert!(!attrs.contains("Max-Age"));
        assert!(!attrs.contains("Expires"));
    }

    #[test]
    fn token_cookie_lifetime_follows_the_persist_choice() {
        assert_eq!(token_cookie_max_age(false), Some(180 * 24 * 60 * 60));
        assert_eq!(token_cookie_max_age(true), None);
    }

    #[test]
    fn parse_cookie_prefix_isolation() {
        let cookies = "oidc_access_token=token1; other_access_token=token2";
        assert_eq!(
            parse_cookie_value(cookies, "oidc_access_token"),
            Some("token1".into())
        );
        assert_eq!(
            parse_cookie_value(cookies, "other_access_token"),
            Some("token2".into())
        );
    }
}
