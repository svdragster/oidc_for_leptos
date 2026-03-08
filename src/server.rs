/// SSR server module: read cookies from HTTP request and initialize auth state.

use crate::config::OidcConfig;
use crate::state::{AuthState, Clock};
use crate::token;

/// Initialize auth state from the current HTTP request's cookies.
/// Decodes JWT claims without signature validation — API server is the trust boundary.
pub fn init_auth_state_from_request<C: Clock>(config: &OidcConfig, clock: &C) -> AuthState {
    let Some(tokens) = crate::cookie::server::read_tokens_from_request(config) else {
        return AuthState::Unauthenticated;
    };

    let now = clock.now_unix_secs();
    let leeway = config.clock_skew_leeway_secs as i64;

    // Try to decode claims from access_token (JWT), fall back to id_token
    let claims = token::decode_claims(&tokens.access_token)
        .or_else(|_| {
            tokens
                .id_token
                .as_deref()
                .ok_or_else(|| crate::error::OidcError::JwtDecode("no decodable token".into()))
                .and_then(|id| token::decode_claims(id))
        });

    match claims {
        Ok(claims) => {
            if token::is_expired(&claims, now, leeway) {
                // Token expired — render as unauthenticated, client will attempt refresh
                AuthState::Unauthenticated
            } else {
                let user_info = token::extract_user_info(&claims);
                AuthState::Authenticated(user_info)
            }
        }
        Err(_) => {
            // Opaque access token (not JWT) — check expires_at cookie instead
            if tokens.expires_at + leeway < now {
                AuthState::Unauthenticated
            } else {
                // Try to read UserInfo from the dedicated cookie (written by client after
                // token exchange/refresh). This provides real user info even with opaque tokens.
                let user_info = crate::cookie::server::read_user_info_from_request(config)
                    .unwrap_or_else(|| crate::state::UserInfo {
                        subject: String::new(),
                        email: None,
                        name: None,
                        preferred_username: None,
                    });
                AuthState::Authenticated(user_info)
            }
        }
    }
}
