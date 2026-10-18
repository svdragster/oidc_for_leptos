//! Auth events for host-app telemetry.
//!
//! oidc_for_leptos never talks to a telemetry backend itself: the host app
//! registers a hook with [`set_auth_event_hook`] and forwards what it wants.
//! PRIVACY: events never carry token values (fingerprints stay local too).

use std::cell::RefCell;
use std::rc::Rc;

use serde::Serialize;

use crate::refresh_policy::{FailureClass, SessionEndReason, TokenEndpointFailure};

/// What started a refresh attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshTrigger {
    /// Page load with an expired access token.
    Load,
    /// Tab became visible.
    Visibility,
    /// Page restored from the back/forward cache.
    PageShow,
    /// Browser went back online.
    Online,
    /// Proactive timer shortly before expiry.
    Timer,
    /// Backoff retry after a transient failure.
    Retry,
    /// User tapped "retry".
    Manual,
    /// An API call needed a fresh token.
    Api,
    /// The API answered 401 to a locally valid token.
    Unauthorized,
}

/// Event type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthEventKind {
    /// A refresh failed (transient: first failure of a run and when it stalls;
    /// terminal/config: always — the session ends).
    RefreshFailed,
    /// A refresh succeeded after failures, or another tab's token was adopted
    /// instead of clearing the session.
    RefreshRecovered,
    /// The user is being sent to the login page (emitted by host apps).
    LoginRedirect,
}

/// Outcome class of the attempt that produced the event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshOutcome {
    Success,
    /// Another tab's fresh token was adopted (cookie changed / already refreshed).
    Adopted,
    Transient,
    Terminal,
    Config,
}

impl From<FailureClass> for RefreshOutcome {
    fn from(c: FailureClass) -> Self {
        match c {
            FailureClass::Terminal => Self::Terminal,
            FailureClass::Config => Self::Config,
            FailureClass::Transient => Self::Transient,
        }
    }
}

/// Browser facts that help tell causes apart (home-screen app, iOS < 15.4, offline).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct ClientEnv {
    /// Running as an installed home-screen app (display-mode standalone).
    pub standalone: Option<bool>,
    /// `navigator.locks` available (cross-tab refresh lock).
    pub web_locks: Option<bool>,
    /// `navigator.onLine`.
    pub online: Option<bool>,
    /// `document.visibilityState == "visible"`.
    pub visible: Option<bool>,
}

/// One auth event. All fields are diagnostics; none is a token value.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct AuthEvent {
    pub kind: AuthEventKind,
    pub trigger: Option<RefreshTrigger>,
    pub outcome: Option<RefreshOutcome>,
    pub http_status: Option<u16>,
    /// OAuth `error` code from the token endpoint.
    pub oauth_error: Option<String>,
    pub error_description: Option<String>,
    /// Zitadel error id, when the IdP sent one.
    pub zitadel_error_id: Option<String>,
    /// Short transport detail (fetch rejection, timeout).
    pub detail: Option<String>,
    /// The rejected token had an earlier request whose answer was never stored.
    pub rotation_lost: bool,
    /// Consecutive failed attempts in the current run.
    pub failed_attempts: u32,
    /// Seconds since the access token expired (negative = still valid).
    pub secs_since_expires_at: Option<i64>,
    /// Seconds since the last successful refresh / login on this device.
    pub secs_since_last_refresh: Option<i64>,
    /// Seconds the current run has been failing.
    pub secs_failing: Option<i64>,
    /// Login redirects: why the user is sent to the login page.
    pub reason: Option<String>,
    pub env: ClientEnv,
}

impl AuthEvent {
    pub fn new(kind: AuthEventKind) -> Self {
        Self {
            kind,
            trigger: None,
            outcome: None,
            http_status: None,
            oauth_error: None,
            error_description: None,
            zitadel_error_id: None,
            detail: None,
            rotation_lost: false,
            failed_attempts: 0,
            secs_since_expires_at: None,
            secs_since_last_refresh: None,
            secs_failing: None,
            reason: None,
            env: ClientEnv::default(),
        }
    }

    /// Copy the token-endpoint facts of a classified failure.
    pub fn with_failure(mut self, f: &TokenEndpointFailure) -> Self {
        self.outcome = Some(f.class.into());
        self.http_status = f.http_status;
        self.oauth_error = f.oauth_error.clone();
        self.error_description = f.error_description.clone();
        self.zitadel_error_id = f.zitadel_error_id.clone();
        self.detail = f.detail.clone();
        self
    }

    /// Low-cardinality one-liner used as the telemetry message, so events group
    /// by what happened (e.g. `refresh_failed:terminal:rotation_lost`,
    /// `login_redirect:guard:no_tokens`), not by timing values.
    pub fn summary(&self) -> String {
        let kind = match self.kind {
            AuthEventKind::RefreshFailed => "refresh_failed",
            AuthEventKind::RefreshRecovered => "refresh_recovered",
            AuthEventKind::LoginRedirect => "login_redirect",
        };
        let mut s = kind.to_string();
        if let Some(outcome) = self.outcome {
            let o = match outcome {
                RefreshOutcome::Success => "success",
                RefreshOutcome::Adopted => "adopted",
                RefreshOutcome::Transient => "transient",
                RefreshOutcome::Terminal => "terminal",
                RefreshOutcome::Config => "config",
            };
            s.push(':');
            s.push_str(o);
        }
        if self.rotation_lost {
            s.push_str(":rotation_lost");
        }
        if let Some(ref reason) = self.reason {
            s.push(':');
            s.push_str(reason);
        }
        s
    }

    /// Whether the event points at a misconfiguration (forward with high severity).
    pub fn is_high_severity(&self) -> bool {
        self.outcome == Some(RefreshOutcome::Config)
    }
}

/// Reason string for a login redirect caused by a session end.
pub fn login_reason(prefix: &str, end: Option<SessionEndReason>) -> String {
    format!("{}:{}", prefix, end.map(SessionEndReason::as_str).unwrap_or("unknown"))
}

type Hook = Rc<dyn Fn(&AuthEvent)>;

thread_local! {
    // WASM is single-threaded; on SSR no events are emitted.
    static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
}

/// Register the host app's auth-event hook (replaces a previous one).
pub fn set_auth_event_hook(hook: impl Fn(&AuthEvent) + 'static) {
    HOOK.with(|h| *h.borrow_mut() = Some(Rc::new(hook)));
}

/// Log an event and hand it to the registered hook (if any).
pub fn emit_auth_event(event: AuthEvent) {
    leptos::logging::log!("[oidc] auth event: {}", event.summary());
    // Clone the hook out so it may itself call back into this module.
    let hook = HOOK.with(|h| h.borrow().clone());
    if let Some(hook) = hook {
        hook(&event);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::refresh_policy::classify_http_failure;

    #[test]
    fn summary_is_low_cardinality() {
        let f = classify_http_failure(400, r#"{"error":"invalid_grant"}"#);
        let mut e = AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(&f);
        e.rotation_lost = true;
        e.secs_since_expires_at = Some(12_345);
        assert_eq!(e.summary(), "refresh_failed:terminal:rotation_lost");

        let mut r = AuthEvent::new(AuthEventKind::LoginRedirect);
        r.reason = Some(login_reason("guard", Some(SessionEndReason::NoTokens)));
        assert_eq!(r.summary(), "login_redirect:guard:no_tokens");
    }

    #[test]
    fn config_events_are_high_severity() {
        let f = classify_http_failure(401, r#"{"error":"invalid_client"}"#);
        assert!(AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(&f).is_high_severity());
        let t = TokenEndpointFailure::transient("offline");
        assert!(!AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(&t).is_high_severity());
    }

    #[test]
    fn serialized_event_has_no_token_fields() {
        let f = classify_http_failure(400, r#"{"error":"invalid_request","error_description":"Errors.OIDCSession.RefreshTokenInvalid"}"#);
        let e = AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(&f);
        let json = serde_json::to_value(&e).unwrap();
        let obj = json.as_object().unwrap();
        for key in obj.keys() {
            assert!(!key.contains("token") || key == "secs_since_expires_at", "unexpected key {key}");
        }
        assert_eq!(json["outcome"], "terminal");
        assert_eq!(json["oauth_error"], "invalid_request");
    }

    #[test]
    fn hook_receives_events() {
        use std::cell::Cell;
        thread_local!(static SEEN: Cell<u32> = const { Cell::new(0) });
        set_auth_event_hook(|_e| SEEN.with(|s| s.set(s.get() + 1)));
        emit_auth_event(AuthEvent::new(AuthEventKind::RefreshRecovered));
        assert_eq!(SEEN.with(|s| s.get()), 1);
    }
}
