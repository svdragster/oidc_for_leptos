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
