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

// -- Callback parsing is shared, browser handler is gated --
pub mod callback;

// -- CSR/hydrate only --
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod locks;
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub mod refresh;

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
pub use state::{AuthState, AuthContext, UserInfo, Clock, SystemClock, MockClock};
pub use provider::{OidcAuthProvider, use_auth};
pub use error::OidcError;
pub use components::{Authenticated, Unauthenticated, AuthLoading, LoginLink, LogoutLink};
