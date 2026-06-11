/// Token refresh logic with cross-tab coordination via Web Locks.
///
/// Flow: acquire lock → re-check if still needed → call IdP → update cookies → release lock.

use leptos::prelude::*;
use serde::Deserialize;
use wasm_bindgen::JsCast;

use crate::config::OidcConfig;
use crate::cookie;
use crate::error::OidcError;
use crate::locks;

/// Token response from the IdP's token endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    pub refresh_token: String,
    pub expires_in: u64,
    #[serde(default)]
    pub token_type: String,
}

/// Refresh the access token using the refresh_token from cookies.
/// Uses Web Locks to prevent thundering herd across tabs.
pub async fn refresh_access_token(config: &OidcConfig) -> Result<TokenResponse, OidcError> {
    let lock_name = format!("{}_refresh_lock", config.cookie_name_prefix);
    let config = config.clone();

    locks::with_refresh_lock(&lock_name, || async {
        refresh_inner(&config, false).await
    })
    .await
}

/// Force-refresh: skip the expires_at freshness check.
/// Used when token was revoked server-side but local expiry looks valid.
pub async fn force_refresh_access_token(config: &OidcConfig) -> Result<TokenResponse, OidcError> {
    let lock_name = format!("{}_refresh_lock", config.cookie_name_prefix);
    let config = config.clone();

    locks::with_refresh_lock(&lock_name, || async {
        refresh_inner(&config, true).await
    })
    .await
}

/// Inner refresh logic that runs while holding the lock
async fn refresh_inner(config: &OidcConfig, force: bool) -> Result<TokenResponse, OidcError> {
    let tokens = cookie::browser::read_tokens(config)
        .ok_or(OidcError::NoRefreshToken)?;

    // Re-check if refresh is still needed (another tab may have done it)
    if !force {
        let now = (js_sys::Date::new_0().get_time() / 1000.0) as i64;
        let threshold = config.refresh_threshold_secs as i64;
        if tokens.expires_at > now + threshold {
            return Err(OidcError::AlreadyRefreshed);
        }
    }

    if tokens.refresh_token.is_empty() {
        return Err(OidcError::NoRefreshToken);
    }

    // Build form body for refresh_token grant
    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        js_sys::encode_uri_component(&config.client_id)
            .as_string()
            .unwrap_or_default(),
        js_sys::encode_uri_component(&tokens.refresh_token)
            .as_string()
            .unwrap_or_default(),
    );

    let response = fetch_token_endpoint(&config.token_endpoint(), &body).await?;

    // Calculate new expires_at
    let now = (js_sys::Date::new_0().get_time() / 1000.0) as i64;
    let expires_at = now + response.expires_in as i64;

    // Preserve existing id_token if refresh response doesn't include one
    let id_token = response.id_token.as_deref().or_else(|| {
        tokens.id_token.as_deref()
    });

    // Write updated tokens to cookies
    cookie::browser::write_tokens(
        config,
        &response.access_token,
        &response.refresh_token,
        id_token,
        expires_at,
    );

    Ok(response)
}

/// Make HTTP request to token endpoint using web-sys fetch API
pub(crate) async fn fetch_token_endpoint(
    url: &str,
    body: &str,
) -> Result<TokenResponse, OidcError> {
    let window = web_sys::window()
        .ok_or_else(|| OidcError::Network("no window object".into()))?;

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&wasm_bindgen::JsValue::from_str(body));

    let headers = web_sys::Headers::new()
        .map_err(|e| OidcError::Network(format!("failed to create headers: {:?}", e)))?;
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(|e| OidcError::Network(format!("failed to set header: {:?}", e)))?;
    opts.set_headers(&headers);

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| OidcError::Network(format!("failed to create request: {:?}", e)))?;

    let promise = window.fetch_with_request(&request);
    let response_value = wasm_bindgen_futures::JsFuture::from(promise)
        .await
        .map_err(|e| OidcError::Network(format!("fetch failed: {:?}", e)))?;

    let response: web_sys::Response = response_value
        .dyn_into()
        .map_err(|_| OidcError::Network("response is not a Response object".into()))?;

    let status = response.status();

    if status == 400 || status == 401 {
        // Log error body for diagnostics
        if let Ok(text_promise) = response.text() {
            if let Ok(text_value) = wasm_bindgen_futures::JsFuture::from(text_promise).await {
                let body_text = text_value.as_string().unwrap_or_default();
                leptos::logging::error!(
                    "[oidc] token endpoint returned {}: {}",
                    status,
                    body_text
                );
            }
        }
        return Err(OidcError::TokenRevoked);
    }

    if !response.ok() {
        return Err(OidcError::Network(format!(
            "token endpoint returned status {}",
            status
        )));
    }

    let json_promise = response
        .json()
        .map_err(|e| OidcError::TokenExchange(format!("failed to get JSON: {:?}", e)))?;
    let json_value = wasm_bindgen_futures::JsFuture::from(json_promise)
        .await
        .map_err(|e| OidcError::TokenExchange(format!("failed to parse JSON: {:?}", e)))?;

    serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| OidcError::TokenExchange(format!("failed to deserialize: {:?}", e)))
}

/// Schedule a token refresh timer (setTimeout) for `threshold` seconds before expiry
pub fn schedule_refresh(
    config: OidcConfig,
    expires_at: i64,
    state_signal: leptos::prelude::RwSignal<crate::state::AuthState>,
    access_token_signal: leptos::prelude::RwSignal<Option<String>>,
    id_token_signal: leptos::prelude::RwSignal<Option<String>>,
) {
    let now = (js_sys::Date::new_0().get_time() / 1000.0) as i64;
    let threshold = config.refresh_threshold_secs as i64;
    let delay_secs = (expires_at - threshold) - now;

    if delay_secs <= 0 {
        // Already needs refresh, do it now
        leptos::task::spawn_local(async move {
            try_refresh_or_unauthenticate(&config, state_signal, access_token_signal, id_token_signal).await;
        });
        return;
    }

    let delay_ms = (delay_secs * 1000) as i32;

    if let Some(window) = web_sys::window() {
        let closure = wasm_bindgen::closure::Closure::once(move || {
            leptos::task::spawn_local(async move {
                try_refresh_or_unauthenticate(&config, state_signal, access_token_signal, id_token_signal).await;
            });
        });
        let _ = window.set_timeout_with_callback_and_timeout_and_arguments_0(
            closure.as_ref().unchecked_ref(),
            delay_ms,
        );
        closure.forget();
    }
}

/// Try to refresh tokens, or transition to Unauthenticated on failure
pub async fn try_refresh_or_unauthenticate(
    config: &OidcConfig,
    state_signal: leptos::prelude::RwSignal<crate::state::AuthState>,
    access_token_signal: leptos::prelude::RwSignal<Option<String>>,
    id_token_signal: leptos::prelude::RwSignal<Option<String>>,
) {
    refresh_and_apply(config, state_signal, access_token_signal, id_token_signal, false).await;
}

/// Refresh tokens and apply the result to signals + cookies.
///
/// Returns the access token now in effect: the freshly refreshed one, or the one
/// another tab already refreshed to. Returns None when the session is dead
/// (revoked/no refresh token) or the refresh failed.
///
/// `force` skips the expires_at freshness check — use it after the server
/// rejected a token that still looked valid locally (revoked server-side).
pub async fn refresh_and_apply(
    config: &OidcConfig,
    state_signal: leptos::prelude::RwSignal<crate::state::AuthState>,
    access_token_signal: leptos::prelude::RwSignal<Option<String>>,
    id_token_signal: leptos::prelude::RwSignal<Option<String>>,
    force: bool,
) -> Option<String> {
    let result = if force {
        force_refresh_access_token(config).await
    } else {
        refresh_access_token(config).await
    };

    match result {
        Ok(response) => {
            let expires_at = (js_sys::Date::new_0().get_time() / 1000.0) as i64
                + response.expires_in as i64;

            // Update signals
            access_token_signal.set(Some(response.access_token.clone()));
            if config.store_id_token {
                id_token_signal.set(response.id_token.clone());
            }

            // Extract user info from new tokens
            let user_info = if let Ok(claims) = crate::token::decode_claims(&response.access_token)
            {
                if claims.sub.is_some() {
                    crate::token::extract_user_info(&claims)
                } else if let Some(ref id_token) = response.id_token {
                    crate::token::decode_claims(id_token)
                        .map(|c| crate::token::extract_user_info(&c))
                        .unwrap_or_else(|_| crate::state::UserInfo {
                            subject: String::new(),
                            email: None,
                            name: None,
                            preferred_username: None,
                        })
                } else {
                    // Keep existing user info
                    match state_signal.get_untracked() {
                        crate::state::AuthState::Authenticated(info) => info,
                        _ => crate::state::UserInfo {
                            subject: String::new(),
                            email: None,
                            name: None,
                            preferred_username: None,
                        },
                    }
                }
            } else {
                match state_signal.get_untracked() {
                    crate::state::AuthState::Authenticated(info) => info,
                    _ => crate::state::UserInfo {
                        subject: String::new(),
                        email: None,
                        name: None,
                        preferred_username: None,
                    },
                }
            };

            // Persist UserInfo cookie for SSR fallback (handles opaque access tokens)
            cookie::browser::write_user_info(config, &user_info);

            state_signal.set(crate::state::AuthState::Authenticated(user_info));

            // Schedule next refresh
            schedule_refresh(
                config.clone(),
                expires_at,
                state_signal,
                access_token_signal,
                id_token_signal,
            );

            Some(response.access_token)
        }
        Err(OidcError::AlreadyRefreshed) => {
            // Another tab handled it — re-read cookies to update signals
            if let Some(tokens) = cookie::browser::read_tokens(config) {
                access_token_signal.set(Some(tokens.access_token.clone()));
                if config.store_id_token {
                    id_token_signal.set(tokens.id_token);
                }
                // Schedule next refresh based on cookie data
                schedule_refresh(
                    config.clone(),
                    tokens.expires_at,
                    state_signal,
                    access_token_signal,
                    id_token_signal,
                );
                Some(tokens.access_token)
            } else {
                None
            }
        }
        Err(OidcError::TokenRevoked) | Err(OidcError::NoRefreshToken) => {
            // Session is dead — clear everything and go to unauthenticated
            cookie::browser::clear_tokens(config);
            access_token_signal.set(None);
            id_token_signal.set(None);
            state_signal.set(crate::state::AuthState::Unauthenticated);
            None
        }
        Err(e) => {
            leptos::logging::error!("[oidc] refresh failed: {}", e);
            state_signal.set(crate::state::AuthState::Error(format!(
                "Token refresh failed: {}",
                e
            )));
            None
        }
    }
}
