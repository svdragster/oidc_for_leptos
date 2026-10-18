//! Token endpoint I/O (browser only).
//!
//! One refresh attempt = read cookies → re-check freshness → POST the
//! refresh_token grant (with a timeout) → write cookies. It runs while the
//! cross-tab lock is held. What a failure *means* is decided by
//! `refresh_policy` (pure); retries, state and events live in `session`.

use serde::Deserialize;
use wasm_bindgen::JsCast;

use crate::config::OidcConfig;
use crate::cookie::{self, TokenCookies};
use crate::refresh_policy::{
    self, classify_http_failure, FailureClass, InflightMarker, TokenEndpointFailure,
    REQUEST_TIMEOUT_MS,
};

/// Token response from the IdP's token endpoint
#[derive(Debug, Clone, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub id_token: Option<String>,
    /// Optional on refresh (RFC 6749 §6: keep the old one when none is issued);
    /// the code exchange requires it and checks for it.
    #[serde(default)]
    pub refresh_token: Option<String>,
    pub expires_in: u64,
    #[serde(default)]
    pub token_type: String,
}

/// Result of one refresh attempt.
pub(crate) enum Attempt {
    /// New tokens were issued and written to the cookies.
    Refreshed {
        access_token: String,
        id_token: Option<String>,
        expires_at: i64,
    },
    /// The cookie token is already fresh (another tab refreshed): nothing sent.
    AlreadyFresh(TokenCookies),
    /// No refresh token stored: there is no session to refresh.
    NoTokens,
    /// The request failed; `failure` says how.
    Failed {
        failure: TokenEndpointFailure,
        /// The refresh token that was sent (compared with the cookie afterwards).
        sent_refresh_token: String,
        /// A leftover in-flight marker matched the sent token.
        rotation_lost: bool,
    },
}

/// One refresh attempt; call it while holding the cross-tab lock.
///
/// `force` skips the freshness check (the API rejected a locally valid token).
/// `check_marker` evaluates a leftover in-flight marker — only on the first
/// attempt of a run, so a confirmation re-send doesn't label itself.
pub(crate) async fn attempt_refresh(config: &OidcConfig, force: bool, check_marker: bool) -> Attempt {
    let Some(tokens) = cookie::browser::read_tokens(config) else {
        return Attempt::NoTokens;
    };
    if tokens.refresh_token.is_empty() {
        return Attempt::NoTokens;
    }

    // Re-check inside the lock: another tab may have refreshed meanwhile.
    let now = crate::session::now_secs();
    if !force && tokens.expires_at > now + config.refresh_threshold_secs as i64 {
        return Attempt::AlreadyFresh(tokens);
    }

    // Rotation hygiene: remember that a request with this token is on its way.
    let fingerprint = refresh_policy::token_fingerprint(&tokens.refresh_token);
    let prior = if check_marker { read_marker(config) } else { None };
    let rotation_lost = refresh_policy::is_rotation_lost(prior.as_ref(), &fingerprint);
    write_marker(config, &InflightMarker { fingerprint, started_at: now });

    let body = format!(
        "grant_type=refresh_token&client_id={}&refresh_token={}",
        encode(&config.client_id),
        encode(&tokens.refresh_token),
    );

    match fetch_token_endpoint(&config.token_endpoint(), &body).await {
        Ok(response) => {
            let expires_at = crate::session::now_secs() + response.expires_in as i64;
            let refresh_token = response
                .refresh_token
                .clone()
                .filter(|t| !t.is_empty())
                .unwrap_or_else(|| tokens.refresh_token.clone());
            // Preserve the existing id_token if the refresh response has none.
            let id_token = response.id_token.clone().or_else(|| tokens.id_token.clone());

            cookie::browser::write_tokens(
                config,
                &response.access_token,
                &refresh_token,
                id_token.as_deref(),
                expires_at,
            );
            clear_marker(config);

            Attempt::Refreshed {
                access_token: response.access_token,
                id_token,
                expires_at,
            }
        }
        Err(failure) => {
            // A definitive rejection did not rotate anything. Transient outcomes
            // (lost reply, timeout, gateway error, unusable 2xx body) keep the
            // marker: the IdP may have rotated the token already.
            if failure.class != FailureClass::Transient {
                clear_marker(config);
            }
            Attempt::Failed {
                failure,
                sent_refresh_token: tokens.refresh_token,
                rotation_lost,
            }
        }
    }
}

/// POST a form body to the token endpoint, aborting after
/// [`REQUEST_TIMEOUT_MS`]. Failures come back classified.
pub(crate) async fn fetch_token_endpoint(
    url: &str,
    body: &str,
) -> Result<TokenResponse, TokenEndpointFailure> {
    let window = web_sys::window().ok_or_else(|| TokenEndpointFailure::transient("no window object"))?;

    let opts = web_sys::RequestInit::new();
    opts.set_method("POST");
    opts.set_body(&wasm_bindgen::JsValue::from_str(body));

    let headers = web_sys::Headers::new()
        .map_err(|e| TokenEndpointFailure::transient(format!("headers: {}", js_message(&e))))?;
    headers
        .set("Content-Type", "application/x-www-form-urlencoded")
        .map_err(|e| TokenEndpointFailure::transient(format!("headers: {}", js_message(&e))))?;
    opts.set_headers(&headers);

    // Bounded request: a hung connection must not block the refresh forever.
    let abort = web_sys::AbortController::new().ok();
    if let Some(ref ctrl) = abort {
        opts.set_signal(Some(&ctrl.signal()));
    }
    let timeout = abort.as_ref().and_then(|ctrl| {
        let ctrl = ctrl.clone();
        let cb = wasm_bindgen::closure::Closure::once(move || ctrl.abort());
        let id = window
            .set_timeout_with_callback_and_timeout_and_arguments_0(
                cb.as_ref().unchecked_ref(),
                REQUEST_TIMEOUT_MS as i32,
            )
            .ok()?;
        Some((id, cb))
    });

    let request = web_sys::Request::new_with_str_and_init(url, &opts)
        .map_err(|e| TokenEndpointFailure::transient(format!("request: {}", js_message(&e))))?;

    let result = wasm_bindgen_futures::JsFuture::from(window.fetch_with_request(&request)).await;
    let timed_out = abort.as_ref().map(|c| c.signal().aborted()).unwrap_or(false);
    if let Some((id, _cb)) = timeout {
        window.clear_timeout_with_handle(id);
    }

    let response: web_sys::Response = match result {
        Ok(v) => v
            .dyn_into()
            .map_err(|_| TokenEndpointFailure::transient("response is not a Response object"))?,
        Err(e) if timed_out => {
            return Err(TokenEndpointFailure::transient(format!(
                "timeout after {} ms ({})",
                REQUEST_TIMEOUT_MS,
                js_message(&e)
            )))
        }
        Err(e) => {
            return Err(TokenEndpointFailure::transient(format!("fetch failed: {}", js_message(&e))))
        }
    };

    let status = response.status();

    if !response.ok() {
        let body_text = match response.text() {
            Ok(p) => wasm_bindgen_futures::JsFuture::from(p)
                .await
                .ok()
                .and_then(|v| v.as_string())
                .unwrap_or_default(),
            Err(_) => String::new(),
        };
        let failure = classify_http_failure(status, &body_text);
        leptos::logging::error!("[oidc] token endpoint returned {}: {}", status, failure.summary());
        return Err(failure);
    }

    let json_promise = response
        .json()
        .map_err(|e| TokenEndpointFailure::transient(format!("unreadable body: {}", js_message(&e))))?;
    let json_value = wasm_bindgen_futures::JsFuture::from(json_promise)
        .await
        .map_err(|e| TokenEndpointFailure::transient(format!("invalid JSON: {}", js_message(&e))))?;

    serde_wasm_bindgen::from_value(json_value)
        .map_err(|e| TokenEndpointFailure::transient(format!("unexpected token response: {}", e)))
}

/// Best-effort message of a JS error value (never contains request bodies).
fn js_message(value: &wasm_bindgen::JsValue) -> String {
    if let Some(s) = value.as_string() {
        return s;
    }
    js_sys::Reflect::get(value, &wasm_bindgen::JsValue::from_str("message"))
        .ok()
        .and_then(|m| m.as_string())
        .unwrap_or_else(|| "unknown error".to_string())
}

fn encode(s: &str) -> String {
    js_sys::encode_uri_component(s).as_string().unwrap_or_default()
}

// -- localStorage helpers (best effort; private mode may throw) --

const INFLIGHT_MARKER: &str = "refresh_inflight";
const LAST_REFRESH_AT: &str = "last_refresh_at";

fn storage() -> Option<web_sys::Storage> {
    web_sys::window()?.local_storage().ok().flatten()
}

fn read_marker(config: &OidcConfig) -> Option<InflightMarker> {
    let raw = storage()?.get_item(&config.cookie_name(INFLIGHT_MARKER)).ok()??;
    InflightMarker::decode(&raw)
}

fn write_marker(config: &OidcConfig, marker: &InflightMarker) {
    if let Some(s) = storage() {
        let _ = s.set_item(&config.cookie_name(INFLIGHT_MARKER), &marker.encode());
    }
}

pub(crate) fn clear_marker(config: &OidcConfig) {
    if let Some(s) = storage() {
        let _ = s.remove_item(&config.cookie_name(INFLIGHT_MARKER));
    }
}

/// Unix seconds of the last successful refresh / code exchange on this device.
pub(crate) fn read_last_refresh_at(config: &OidcConfig) -> Option<i64> {
    storage()?
        .get_item(&config.cookie_name(LAST_REFRESH_AT))
        .ok()??
        .parse()
        .ok()
}

pub(crate) fn write_last_refresh_at(config: &OidcConfig, at: i64) {
    if let Some(s) = storage() {
        let _ = s.set_item(&config.cookie_name(LAST_REFRESH_AT), &at.to_string());
    }
}
