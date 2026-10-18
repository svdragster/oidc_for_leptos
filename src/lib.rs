// oidc_for_leptos — OIDC/OAuth2 authentication for Leptos 0.8.x
//
// Cookie-first token storage, SSR-aware, cross-tab safe.

// -- Shared modules (all features) --
pub mod config;
pub mod error;
pub mod state;
pub mod token;
pub mod pkce;
pub mod cookie;
// Pure refresh policy (classification, backoff, rotation hygiene) — unit-tested natively
pub mod refresh_policy;
// Auth events for the host app's telemetry hook
pub mod events;

// -- Callback parsing is shared, browser handler is gated --
pub mod callback;

// -- CSR/hydrate only --
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod locks;
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod refresh;
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod session;

// -- SSR only --
#[cfg(feature = "ssr")]
pub mod server;

// -- Both SSR and CSR (with internal cfg branching) --
pub mod provider;
pub mod components;

// -- Optional, low priority --
pub mod discovery;

// -- Public API re-exports --
pub use config::OidcConfig;
pub use state::{AuthState, AuthContext, UserInfo, Clock, SystemClock, MockClock, RefreshStatus, TokenUnavailable};
pub use refresh_policy::{FailureClass, SessionEndReason};
pub use events::{
    emit_auth_event, set_auth_event_hook, AuthEvent, AuthEventKind, ClientEnv, RefreshOutcome,
    RefreshTrigger,
};
pub use provider::{OidcAuthProvider, use_auth};
pub use error::OidcError;
pub use components::{Authenticated, Unauthenticated, AuthLoading, LoginLink, LogoutLink};

/// Emit a `login_redirect` auth event with the current session facts
/// (host apps call this whenever they send the user to the login page).
/// No-op on the server.
pub fn report_login_redirect(reason: &str) {
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    session::report_login_redirect(reason);
    #[cfg(not(any(feature = "hydrate", feature = "csr")))]
    let _ = reason;
}
