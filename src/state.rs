use leptos::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicI64, Ordering};

use crate::config::OidcConfig;

/// User info extracted from OIDC tokens
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct UserInfo {
    pub subject: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub preferred_username: Option<String>,
}

/// Authentication state machine
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub enum AuthState {
    Loading,
    Authenticated(UserInfo),
    Unauthenticated,
    Error(String),
}

/// Why no access token could be produced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TokenUnavailable {
    /// The session is over (no tokens, or the IdP rejected the refresh token):
    /// send the user to login.
    Terminal,
    /// The IdP could not be reached or answered with a temporary error. Tokens
    /// and state are kept and the refresh is retried — never log out for this.
    Transient,
}

/// Health of the silent refresh, separate from [`AuthState`]: a transient
/// failure keeps the `AuthState` as it is and only shows up here (drives the
/// host app's reconnect notice).
#[derive(Clone, Debug, Default, PartialEq)]
pub struct RefreshStatus {
    /// A token request is running in this tab.
    pub in_flight: bool,
    /// Consecutive failed attempts of the current run (0 = healthy).
    pub failed_attempts: u32,
    /// Unix seconds of the first failure of the current run.
    pub failing_since: Option<i64>,
    /// The run has been failing for ~30 s: offer a manual retry.
    pub stalled: bool,
    /// Why the session ended — set together with `AuthState::Unauthenticated`.
    pub end_reason: Option<crate::refresh_policy::SessionEndReason>,
}

impl RefreshStatus {
    /// Automatic retries are running after a transient failure.
    pub fn is_reconnecting(&self) -> bool {
        self.failed_attempts > 0
    }
}

/// Clock abstraction for deterministic testing
pub trait Clock: Send + Sync + 'static {
    fn now_unix_secs(&self) -> i64;
}

/// Production clock using platform time
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_secs(&self) -> i64 {
        #[cfg(target_arch = "wasm32")]
        {
            (js_sys::Date::new_0().get_time() / 1000.0) as i64
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64
        }
    }
}

/// Test clock with manual time control
pub struct MockClock(AtomicI64);

impl MockClock {
    pub fn new(initial: i64) -> Self {
        Self(AtomicI64::new(initial))
    }

    pub fn set(&self, ts: i64) {
        self.0.store(ts, Ordering::Relaxed);
    }

    pub fn advance(&self, secs: i64) {
        self.0.fetch_add(secs, Ordering::Relaxed);
    }
}

impl Clock for MockClock {
    fn now_unix_secs(&self) -> i64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// Main auth context provided to the component tree
#[derive(Clone)]
pub struct AuthContext {
    pub(crate) state: RwSignal<AuthState>,
    pub(crate) config: OidcConfig,
    pub(crate) access_token: RwSignal<Option<String>>,
    pub(crate) id_token: RwSignal<Option<String>>,
    pub(crate) refresh_status: RwSignal<RefreshStatus>,
}

impl AuthContext {
    /// Current auth state signal
    pub fn state(&self) -> RwSignal<AuthState> {
        self.state
    }

    /// Whether the user is currently authenticated
    pub fn is_authenticated(&self) -> bool {
        matches!(self.state.get_untracked(), AuthState::Authenticated(_))
    }

    /// Whether auth is still loading
    pub fn is_loading(&self) -> bool {
        matches!(self.state.get_untracked(), AuthState::Loading)
    }

    /// Current access token (if authenticated)
    pub fn access_token(&self) -> Option<String> {
        self.access_token.get_untracked()
    }

    /// Current ID token (if stored)
    pub fn id_token(&self) -> Option<String> {
        self.id_token.get_untracked()
    }

    /// Refresh health (in flight, failing, stalled, end reason).
    pub fn refresh_status(&self) -> RwSignal<RefreshStatus> {
        self.refresh_status
    }

    /// Retry a failing refresh right now (manual "retry" button). Resets the
    /// backoff wait; no-op on the server or when nothing is failing.
    pub fn retry_refresh_now(&self) {
        #[cfg(any(feature = "hydrate", feature = "csr"))]
        crate::session::retry_now();
    }

    /// Return an access token that is valid right now, refreshing first when the
    /// cookie expiry says it is stale. Complements the proactive setTimeout
    /// refresh, which does not fire while a mobile tab/PWA is suspended.
    /// Returns None when unauthenticated or the refresh fails (either way —
    /// use [`Self::valid_access_token_checked`] to tell them apart).
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    pub async fn valid_access_token(&self) -> Option<String> {
        self.valid_access_token_checked().await.ok()
    }

    /// Like [`Self::valid_access_token`], but says whether a missing token is
    /// terminal (session over) or transient (IdP unreachable, retrying).
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    pub async fn valid_access_token_checked(&self) -> Result<String, TokenUnavailable> {
        let Some(tokens) = crate::cookie::browser::read_tokens(&self.config) else {
            // No session cookies at all (logged out, possibly in another tab).
            crate::session::end_session_without_tokens();
            return Err(TokenUnavailable::Terminal);
        };
        let now = crate::session::now_secs();
        let leeway = self.config.clock_skew_leeway_secs as i64;

        if tokens.expires_at > now + leeway {
            // Cookie token is still fresh — sync the signals (another tab may have
            // refreshed since this one was suspended) and use it directly.
            return Ok(crate::session::sync_from_cookie(tokens));
        }

        crate::session::refresh(crate::events::RefreshTrigger::Api, false).await
    }

    /// Force a refresh after the server returned 401 although the local expiry
    /// still looked valid (token revoked server-side). Returns the new token.
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    pub async fn refresh_after_unauthorized(&self) -> Option<String> {
        self.refresh_after_unauthorized_checked().await.ok()
    }

    /// Like [`Self::refresh_after_unauthorized`], terminal vs. transient.
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    pub async fn refresh_after_unauthorized_checked(&self) -> Result<String, TokenUnavailable> {
        crate::session::refresh(crate::events::RefreshTrigger::Unauthorized, true).await
    }

    /// Current user info (if authenticated)
    pub fn user_info(&self) -> Option<UserInfo> {
        match self.state.get_untracked() {
            AuthState::Authenticated(info) => Some(info),
            _ => None,
        }
    }

    /// OIDC config reference
    pub fn config(&self) -> &OidcConfig {
        &self.config
    }

    /// Build the authorization URL for login (without PKCE — PKCE is added by LoginLink)
    pub fn login_url_base(&self) -> String {
        format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}",
            self.config.authorization_endpoint(),
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&self.config.scopes.join(" ")),
        )
    }

    /// Generate a complete login URL with PKCE, state, and nonce.
    /// Writes PKCE verifier and state to cookies for callback verification.
    /// Use this for programmatic redirects (as opposed to LoginLink for <a> tags).
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    pub fn generate_login_url(&self) -> Result<String, crate::error::OidcError> {
        use base64::Engine;

        let pkce = crate::pkce::generate()?;
        crate::cookie::browser::write_pkce_verifier(&self.config, &pkce.verifier);

        // Generate state for CSRF protection
        let mut state_bytes = [0u8; 16];
        getrandom::getrandom(&mut state_bytes)
            .map_err(|e| crate::error::OidcError::Pkce(format!("random generation failed: {}", e)))?;
        let state = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(state_bytes);
        crate::cookie::browser::write_oauth_state(&self.config, &state);

        // Generate nonce
        let mut nonce_bytes = [0u8; 16];
        getrandom::getrandom(&mut nonce_bytes)
            .map_err(|e| crate::error::OidcError::Pkce(format!("random generation failed: {}", e)))?;
        let nonce = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(nonce_bytes);

        let auth_endpoint = self.config.authorization_endpoint();
        leptos::logging::log!("[oidc] authorization_endpoint = {}", auth_endpoint);
        leptos::logging::log!("[oidc] issuer = {}", self.config.issuer);

        Ok(format!(
            "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
            auth_endpoint,
            urlencoding::encode(&self.config.client_id),
            urlencoding::encode(&self.config.redirect_uri),
            urlencoding::encode(&self.config.scopes.join(" ")),
            urlencoding::encode(&state),
            urlencoding::encode(&pkce.challenge),
            urlencoding::encode(&nonce),
        ))
    }

    /// Build the logout URL
    pub fn logout_url(&self) -> String {
        let base = self.config.end_session_endpoint();
        let mut url = base.clone();

        if let Some(id_token) = self.id_token.get_untracked() {
            url = format!("{}?id_token_hint={}", url, urlencoding::encode(&id_token));
            url = format!(
                "{}&post_logout_redirect_uri={}",
                url,
                urlencoding::encode(&self.config.post_logout_redirect_uri)
            );
        } else {
            url = format!(
                "{}?post_logout_redirect_uri={}",
                url,
                urlencoding::encode(&self.config.post_logout_redirect_uri)
            );
        }

        url
    }
}

/// URL encoding helper (no external dep needed for this simple case)
mod urlencoding {
    pub fn encode(input: &str) -> String {
        url::form_urlencoded::byte_serialize(input.as_bytes()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_clock_works() {
        let clock = MockClock::new(1000);
        assert_eq!(clock.now_unix_secs(), 1000);
        clock.advance(60);
        assert_eq!(clock.now_unix_secs(), 1060);
        clock.set(2000);
        assert_eq!(clock.now_unix_secs(), 2000);
    }

    #[test]
    fn system_clock_returns_reasonable_time() {
        let clock = SystemClock;
        let now = clock.now_unix_secs();
        // Should be after 2024-01-01
        assert!(now > 1704067200);
    }

    #[test]
    fn auth_state_serialization() {
        let state = AuthState::Authenticated(UserInfo {
            subject: "sub".into(),
            email: Some("test@test.com".into()),
            name: Some("Test".into()),
            preferred_username: None,
        });
        let json = serde_json::to_string(&state).unwrap();
        let deserialized: AuthState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, deserialized);
    }

    #[test]
    fn auth_state_transitions() {
        // All valid states can be created
        let _ = AuthState::Loading;
        let _ = AuthState::Unauthenticated;
        let _ = AuthState::Error("test error".into());
        let _ = AuthState::Authenticated(UserInfo {
            subject: "sub".into(),
            email: None,
            name: None,
            preferred_username: None,
        });
    }
}
