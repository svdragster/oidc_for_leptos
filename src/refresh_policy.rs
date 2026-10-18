//! Pure refresh policy: classifies token-endpoint outcomes (terminal vs.
//! transient) and decides what happens next (retry with backoff, confirm once,
//! adopt another tab's token, end the session).
//!
//! No browser APIs here. The browser engine (`session.rs`) feeds facts in and
//! acts on the decisions, so these rules are unit-tested natively.
//!
//! Background (ES-One doc 27): any failed silent refresh used to end at the
//! login form. Only a definitive answer from the IdP may end a session now;
//! everything else keeps cookies + state and retries.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Delays (ms) before retry 1…5 after consecutive transient failures: 1, 2, 4, 8, 16 s.
pub const BACKOFF_SCHEDULE_MS: [u32; 5] = [1_000, 2_000, 4_000, 8_000, 16_000];
/// After the schedule, keep retrying every 30 s so the app recovers by itself
/// (e.g. after a longer Zitadel outage) without user action.
pub const BACKOFF_CAP_MS: u32 = 30_000;
/// A failing run counts as "stalled" (manual retry offered) after this long.
pub const STALL_AFTER_SECS: i64 = 30;
/// Delay before re-sending once to confirm an ambiguous rejection.
pub const CONFIRM_DELAY_MS: u32 = 1_000;
/// Abort a token request that has not answered after this long (transient).
pub const REQUEST_TIMEOUT_MS: u32 = 20_000;
/// Stop waiting for the cross-tab Web Lock after this long and proceed without
/// it (a frozen background tab may hold it); rotation hygiene covers the race.
pub const LOCK_TIMEOUT_MS: u32 = 30_000;

/// OAuth error codes that mean "this client is misconfigured", not "this token is dead".
const CONFIG_ERRORS: &[&str] = &[
    "invalid_client",
    "unauthorized_client",
    "unsupported_grant_type",
    "invalid_scope",
];

/// Max length of the IdP's `error_description` / transport detail we keep (telemetry).
const MAX_TEXT_LEN: usize = 160;

/// What a failed refresh means for the session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureClass {
    /// The IdP rejected the refresh token: the session is over.
    Terminal,
    /// Client misconfiguration (`invalid_client`, …): ends the session too, high severity.
    Config,
    /// Network / IdP trouble: keep cookies and state, retry with backoff.
    Transient,
}

/// A classified token-endpoint failure. Never contains token values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenEndpointFailure {
    pub class: FailureClass,
    /// Terminal verdict that is ambiguous: re-send once before ending the session.
    pub confirm: bool,
    pub http_status: Option<u16>,
    /// OAuth `error` code from a JSON error body.
    pub oauth_error: Option<String>,
    /// OAuth `error_description` (truncated).
    pub error_description: Option<String>,
    /// Zitadel error id (e.g. `OIDCS-28ubl`) when the description carries one.
    pub zitadel_error_id: Option<String>,
    /// Short transport detail (fetch rejection, timeout, parse error).
    pub detail: Option<String>,
}

impl TokenEndpointFailure {
    /// Transport failure without an HTTP answer (fetch rejected, timeout) or an
    /// unusable 2xx body — always transient.
    pub fn transient(detail: impl Into<String>) -> Self {
        Self {
            class: FailureClass::Transient,
            confirm: false,
            http_status: None,
            oauth_error: None,
            error_description: None,
            zitadel_error_id: None,
            detail: Some(truncate(&detail.into())),
        }
    }

    /// One-line, token-free summary for logs and error strings.
    pub fn summary(&self) -> String {
        let mut s = format!("{:?}", self.class).to_lowercase();
        if let Some(status) = self.http_status {
            s.push_str(&format!(" http={}", status));
        }
        if let Some(ref e) = self.oauth_error {
            s.push_str(&format!(" error={}", e));
        }
        if let Some(ref id) = self.zitadel_error_id {
            s.push_str(&format!(" id={}", id));
        }
        if let Some(ref d) = self.detail {
            s.push_str(&format!(" ({})", d));
        }
        s
    }
}

#[derive(Deserialize)]
struct OAuthErrorBody {
    error: String,
    #[serde(default)]
    error_description: Option<String>,
}

/// Classify a non-2xx token-endpoint response.
///
/// - 400/401 + JSON `invalid_grant` → terminal (RFC 6749 §5.2).
/// - 400/401 + JSON `invalid_client` / `unauthorized_client` /
///   `unsupported_grant_type` / `invalid_scope` → config error (terminal).
/// - 400/401 + any other JSON OAuth error → terminal, **confirmed by one
///   re-send**. ASSUMPTION (verified in Zitadel v3.4.2 and `main`,
///   `internal/api/oidc/error.go`): Zitadel reports a rotated, expired or
///   revoked refresh token as 400 `invalid_request`, not `invalid_grant` —
///   and uses the same answer when its own event-store lookup fails
///   (`OIDCS-SAF31`), so one confirmation guards against a Zitadel hiccup.
/// - Everything else (non-JSON 4xx from a proxy, 408, 429, 5xx, other 4xx) → transient.
pub fn classify_http_failure(status: u16, body: &str) -> TokenEndpointFailure {
    let parsed = serde_json::from_str::<OAuthErrorBody>(body)
        .ok()
        .filter(|b| !b.error.trim().is_empty());
    let oauth_error = parsed.as_ref().map(|b| b.error.trim().to_string());
    let error_description = parsed
        .as_ref()
        .and_then(|b| b.error_description.as_deref())
        .map(truncate);
    let zitadel_error_id = error_description.as_deref().and_then(extract_zitadel_error_id);

    let (class, confirm) = match (status, oauth_error.as_deref()) {
        (400 | 401, Some("invalid_grant")) => (FailureClass::Terminal, false),
        (400 | 401, Some(e)) if CONFIG_ERRORS.contains(&e) => (FailureClass::Config, false),
        (400 | 401, Some(_)) => (FailureClass::Terminal, true),
        _ => (FailureClass::Transient, false),
    };

    TokenEndpointFailure {
        class,
        confirm,
        http_status: Some(status),
        oauth_error,
        error_description,
        zitadel_error_id,
        detail: None,
    }
}

/// Find a Zitadel error id such as `OIDCS-28ubl` or `COMMAND-Sf3g2` in a text.
/// Pattern: 2–12 uppercase ASCII letters, one dash, 3–8 alphanumerics.
pub fn extract_zitadel_error_id(text: &str) -> Option<String> {
    text.split(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
        .find(|word| {
            let mut parts = word.split('-');
            let (Some(prefix), Some(suffix), None) = (parts.next(), parts.next(), parts.next())
            else {
                return false;
            };
            (2..=12).contains(&prefix.len())
                && prefix.chars().all(|c| c.is_ascii_uppercase())
                && (3..=8).contains(&suffix.len())
                && suffix.chars().all(|c| c.is_ascii_alphanumeric())
        })
        .map(str::to_string)
}

/// Delay before the next retry, given the number of consecutive transient
/// failures so far (1 = the first failure). 1, 2, 4, 8, 16 s, then every 30 s.
pub fn backoff_delay_ms(failed_attempts: u32) -> u32 {
    let idx = failed_attempts.max(1) as usize - 1;
    BACKOFF_SCHEDULE_MS.get(idx).copied().unwrap_or(BACKOFF_CAP_MS)
}

/// Whether a failing run has lasted long enough to offer a manual retry.
pub fn is_stalled(failing_since: i64, now: i64) -> bool {
    now - failing_since >= STALL_AFTER_SECS
}

/// Whether a transient failure is worth a telemetry event: the first failure
/// of a run and the moment it becomes stalled. Keeps an offline phone from
/// sending one event per retry.
pub fn should_report_transient(failed_attempts: u32, stalled_before: bool, stalled_now: bool) -> bool {
    failed_attempts == 1 || (!stalled_before && stalled_now)
}

/// What to do after a failed attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NextStep {
    /// Another tab rotated the token meanwhile (cookie changed): adopt it, no logout.
    AdoptCookie,
    /// Ambiguous rejection: wait and re-send once before ending the session.
    Confirm { delay_ms: u32 },
    /// Clear cookies, state `Unauthenticated`.
    EndSession,
    /// Keep cookies and state; retry after `delay_ms`.
    RetryAfter { delay_ms: u32 },
}

/// Decide the next step after a failed attempt.
///
/// - `cookie_changed`: the refresh-token cookie, re-read after the answer,
///   differs from the token that was sent (rotation hygiene: never clear a
///   token another tab just wrote).
/// - `already_confirmed`: the confirmation re-send already happened in this run.
/// - `failed_attempts`: consecutive transient failures including this one.
pub fn decide_after_failure(
    failure: &TokenEndpointFailure,
    cookie_changed: bool,
    already_confirmed: bool,
    failed_attempts: u32,
) -> NextStep {
    match failure.class {
        FailureClass::Transient => NextStep::RetryAfter {
            delay_ms: backoff_delay_ms(failed_attempts),
        },
        FailureClass::Terminal | FailureClass::Config if cookie_changed => NextStep::AdoptCookie,
        FailureClass::Terminal if failure.confirm && !already_confirmed => NextStep::Confirm {
            delay_ms: CONFIRM_DELAY_MS,
        },
        FailureClass::Terminal | FailureClass::Config => NextStep::EndSession,
    }
}

/// Why a session ended (shown to telemetry, used as the login-redirect reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionEndReason {
    /// No token cookies at all (never logged in, logged out, or the browser deleted them).
    NoTokens,
    /// The IdP rejected the refresh token.
    Rejected,
    /// Rejected, and an earlier request with the same token never got its
    /// answer stored: Zitadel most likely rotated it and the reply was lost.
    RotationLost,
    /// Client misconfiguration at the IdP.
    ConfigError,
}

impl SessionEndReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoTokens => "no_tokens",
            Self::Rejected => "rejected",
            Self::RotationLost => "rotation_lost",
            Self::ConfigError => "config_error",
        }
    }
}

/// End reason for a terminal/config failure.
pub fn end_reason_for(class: FailureClass, rotation_lost: bool) -> SessionEndReason {
    match class {
        FailureClass::Config => SessionEndReason::ConfigError,
        _ if rotation_lost => SessionEndReason::RotationLost,
        _ => SessionEndReason::Rejected,
    }
}

/// Whether a refresh may start now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartDecision {
    /// A refresh is already running in this tab: wait for its result (single-flight).
    JoinInFlight,
    /// The page is hidden: don't start (iOS may freeze the page mid-request and
    /// lose the rotated token). The visibility handler starts it later.
    DeferUntilVisible,
    Start,
}

pub fn should_start_refresh(in_flight: bool, hidden: bool) -> StartDecision {
    if in_flight {
        StartDecision::JoinInFlight
    } else if hidden {
        StartDecision::DeferUntilVisible
    } else {
        StartDecision::Start
    }
}

/// What to do when the page becomes usable again (visible, restored from the
/// back/forward cache, back online).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    /// Refresh now (token due, or a failing run waits for a retry).
    Refresh,
    /// Token still fresh: sync signals from the cookies (another tab may have
    /// refreshed) and re-arm the timer.
    SyncFromCookie,
}

pub fn resume_action(failing: bool, expires_at: i64, now: i64, threshold_secs: i64) -> ResumeAction {
    if failing || expires_at <= now + threshold_secs {
        ResumeAction::Refresh
    } else {
        ResumeAction::SyncFromCookie
    }
}

/// Marker written before a token request and cleared once its answer is
/// handled. A marker left behind means "a request with this token never got
/// its answer stored" (page killed, reply lost) — so a later rejection of the
/// same token is labelled `rotation_lost`. Stores a fingerprint, never the token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InflightMarker {
    pub fingerprint: String,
    pub started_at: i64,
}

impl InflightMarker {
    pub fn encode(&self) -> String {
        format!("{}:{}", self.fingerprint, self.started_at)
    }

    pub fn decode(raw: &str) -> Option<Self> {
        let (fp, ts) = raw.split_once(':')?;
        if fp.is_empty() {
            return None;
        }
        Some(Self {
            fingerprint: fp.to_string(),
            started_at: ts.parse().ok()?,
        })
    }
}

/// Short, non-reversible fingerprint of a token (first 16 hex chars of SHA-256).
pub fn token_fingerprint(token: &str) -> String {
    Sha256::digest(token.as_bytes())
        .iter()
        .take(8)
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// A rejected token whose fingerprint matches a leftover in-flight marker was
/// most likely rotated by an earlier request whose reply never got stored.
pub fn is_rotation_lost(prior: Option<&InflightMarker>, sent_fingerprint: &str) -> bool {
    prior.is_some_and(|m| m.fingerprint == sent_fingerprint)
}

fn truncate(s: &str) -> String {
    if s.chars().count() <= MAX_TEXT_LEN {
        s.to_string()
    } else {
        s.chars().take(MAX_TEXT_LEN).collect::<String>() + "…"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- classification --

    #[test]
    fn invalid_grant_is_terminal_without_confirmation() {
        let f = classify_http_failure(400, r#"{"error":"invalid_grant","error_description":"expired"}"#);
        assert_eq!(f.class, FailureClass::Terminal);
        assert!(!f.confirm);
        assert_eq!(f.oauth_error.as_deref(), Some("invalid_grant"));
        assert_eq!(f.http_status, Some(400));
    }

    #[test]
    fn invalid_grant_with_401_is_terminal() {
        let f = classify_http_failure(401, r#"{"error":"invalid_grant"}"#);
        assert_eq!(f.class, FailureClass::Terminal);
    }

    #[test]
    fn zitadel_invalid_request_is_terminal_but_confirmed() {
        // Zitadel's answer for a rotated/expired refresh token (OIDCS-28ubl / 3jt2w).
        let f = classify_http_failure(
            400,
            r#"{"error":"invalid_request","error_description":"Errors.OIDCSession.RefreshTokenInvalid"}"#,
        );
        assert_eq!(f.class, FailureClass::Terminal);
        assert!(f.confirm);
        assert_eq!(
            f.error_description.as_deref(),
            Some("Errors.OIDCSession.RefreshTokenInvalid")
        );
    }

    #[test]
    fn client_errors_are_config() {
        for code in ["invalid_client", "unauthorized_client", "unsupported_grant_type", "invalid_scope"] {
            let f = classify_http_failure(401, &format!(r#"{{"error":"{}"}}"#, code));
            assert_eq!(f.class, FailureClass::Config, "{code}");
            assert!(!f.confirm);
        }
    }

    #[test]
    fn non_json_400_from_a_proxy_is_transient() {
        let f = classify_http_failure(400, "<html><body>400 Bad Request</body></html>");
        assert_eq!(f.class, FailureClass::Transient);
        assert_eq!(f.oauth_error, None);
    }

    #[test]
    fn empty_or_blank_error_code_is_transient() {
        assert_eq!(classify_http_failure(400, "").class, FailureClass::Transient);
        assert_eq!(
            classify_http_failure(400, r#"{"error":"  "}"#).class,
            FailureClass::Transient
        );
    }

    #[test]
    fn server_and_throttling_errors_are_transient() {
        for status in [408, 429, 500, 502, 503, 504] {
            let f = classify_http_failure(status, r#"{"error":"server_error"}"#);
            assert_eq!(f.class, FailureClass::Transient, "status {status}");
        }
    }

    #[test]
    fn json_error_on_other_4xx_is_transient() {
        // Zitadel maps NotFound/PermissionDenied to 404/403 + invalid_request;
        // only 400/401 count as a verdict on the token.
        assert_eq!(
            classify_http_failure(404, r#"{"error":"invalid_request"}"#).class,
            FailureClass::Transient
        );
        assert_eq!(
            classify_http_failure(403, r#"{"error":"invalid_request"}"#).class,
            FailureClass::Transient
        );
    }

    #[test]
    fn transport_failure_is_transient() {
        let f = TokenEndpointFailure::transient("fetch failed: TypeError: Load failed");
        assert_eq!(f.class, FailureClass::Transient);
        assert_eq!(f.http_status, None);
        assert!(f.summary().starts_with("transient"));
    }

    #[test]
    fn long_descriptions_are_truncated() {
        let long = "x".repeat(500);
        let f = classify_http_failure(400, &format!(r#"{{"error":"invalid_request","error_description":"{}"}}"#, long));
        assert!(f.error_description.unwrap().chars().count() <= MAX_TEXT_LEN + 1);
    }

    #[test]
    fn zitadel_error_id_is_extracted_from_description() {
        let f = classify_http_failure(
            400,
            r#"{"error":"invalid_request","error_description":"Errors.OIDCSession.RefreshTokenInvalid (OIDCS-28ubl)"}"#,
        );
        assert_eq!(f.zitadel_error_id.as_deref(), Some("OIDCS-28ubl"));
    }

    #[test]
    fn extract_zitadel_error_id_patterns() {
        assert_eq!(extract_zitadel_error_id("ID=COMMAND-Sf3g2 msg"), Some("COMMAND-Sf3g2".into()));
        assert_eq!(extract_zitadel_error_id("OIDC-AhX2u"), Some("OIDC-AhX2u".into()));
        assert_eq!(extract_zitadel_error_id("Errors.OIDCSession.RefreshTokenInvalid"), None);
        assert_eq!(extract_zitadel_error_id("X-Request-Id abc-def"), None);
        assert_eq!(extract_zitadel_error_id(""), None);
    }

    // -- retry / backoff --

    #[test]
    fn backoff_follows_schedule_then_caps() {
        let delays: Vec<u32> = (1..=8).map(backoff_delay_ms).collect();
        assert_eq!(delays, vec![1_000, 2_000, 4_000, 8_000, 16_000, 30_000, 30_000, 30_000]);
        // Defensive: 0 behaves like the first failure.
        assert_eq!(backoff_delay_ms(0), 1_000);
    }

    #[test]
    fn run_stalls_after_about_thirty_seconds() {
        // Failures at t=0,1,3,7,15 are not stalled; the retry at t=31 is.
        let since = 1_000;
        assert!(!is_stalled(since, since));
        assert!(!is_stalled(since, since + 15));
        assert!(!is_stalled(since, since + 29));
        assert!(is_stalled(since, since + 30));
        assert!(is_stalled(since, since + 31));
    }

    #[test]
    fn transient_reporting_is_throttled() {
        assert!(should_report_transient(1, false, false));
        assert!(!should_report_transient(2, false, false));
        assert!(should_report_transient(6, false, true));
        assert!(!should_report_transient(7, true, true));
    }

    fn terminal(confirm: bool) -> TokenEndpointFailure {
        TokenEndpointFailure {
            class: FailureClass::Terminal,
            confirm,
            http_status: Some(400),
            oauth_error: Some(if confirm { "invalid_request" } else { "invalid_grant" }.into()),
            error_description: None,
            zitadel_error_id: None,
            detail: None,
        }
    }

    #[test]
    fn transient_failure_retries_with_backoff() {
        let f = TokenEndpointFailure::transient("offline");
        assert_eq!(decide_after_failure(&f, false, false, 1), NextStep::RetryAfter { delay_ms: 1_000 });
        assert_eq!(decide_after_failure(&f, false, false, 3), NextStep::RetryAfter { delay_ms: 4_000 });
        // A changed cookie doesn't matter for transient failures: still a retry
        // (the retry reads the new cookie and finds it fresh).
        assert_eq!(decide_after_failure(&f, true, false, 6), NextStep::RetryAfter { delay_ms: 30_000 });
    }

    #[test]
    fn terminal_with_changed_cookie_adopts_instead_of_clearing() {
        assert_eq!(decide_after_failure(&terminal(false), true, false, 1), NextStep::AdoptCookie);
        assert_eq!(decide_after_failure(&terminal(true), true, true, 1), NextStep::AdoptCookie);
    }

    #[test]
    fn ambiguous_terminal_is_confirmed_once_then_ends() {
        assert_eq!(
            decide_after_failure(&terminal(true), false, false, 1),
            NextStep::Confirm { delay_ms: CONFIRM_DELAY_MS }
        );
        assert_eq!(decide_after_failure(&terminal(true), false, true, 1), NextStep::EndSession);
    }

    #[test]
    fn invalid_grant_ends_immediately() {
        assert_eq!(decide_after_failure(&terminal(false), false, false, 1), NextStep::EndSession);
    }

    #[test]
    fn config_error_ends_session() {
        let f = classify_http_failure(401, r#"{"error":"invalid_client"}"#);
        assert_eq!(decide_after_failure(&f, false, false, 1), NextStep::EndSession);
        assert_eq!(end_reason_for(f.class, true), SessionEndReason::ConfigError);
    }

    #[test]
    fn end_reason_labels_rotation_loss() {
        assert_eq!(end_reason_for(FailureClass::Terminal, false), SessionEndReason::Rejected);
        assert_eq!(end_reason_for(FailureClass::Terminal, true), SessionEndReason::RotationLost);
        assert_eq!(SessionEndReason::RotationLost.as_str(), "rotation_lost");
    }

    #[test]
    fn start_decision_single_flight_and_hidden() {
        assert_eq!(should_start_refresh(true, false), StartDecision::JoinInFlight);
        assert_eq!(should_start_refresh(true, true), StartDecision::JoinInFlight);
        assert_eq!(should_start_refresh(false, true), StartDecision::DeferUntilVisible);
        assert_eq!(should_start_refresh(false, false), StartDecision::Start);
    }

    #[test]
    fn resume_refreshes_when_due_or_failing() {
        let now = 10_000;
        assert_eq!(resume_action(false, now + 3_600, now, 300), ResumeAction::SyncFromCookie);
        assert_eq!(resume_action(false, now + 200, now, 300), ResumeAction::Refresh);
        assert_eq!(resume_action(false, now - 50_000, now, 300), ResumeAction::Refresh);
        assert_eq!(resume_action(true, now + 3_600, now, 300), ResumeAction::Refresh);
    }

    // -- rotation hygiene --

    #[test]
    fn fingerprint_is_short_stable_and_not_the_token() {
        let fp = token_fingerprint("secret-refresh-token");
        assert_eq!(fp.len(), 16);
        assert_eq!(fp, token_fingerprint("secret-refresh-token"));
        assert_ne!(fp, token_fingerprint("other-token"));
        assert!(!fp.contains("secret"));
    }

    #[test]
    fn marker_roundtrip() {
        let m = InflightMarker { fingerprint: "abcd".into(), started_at: 1_700_000_000 };
        assert_eq!(InflightMarker::decode(&m.encode()), Some(m));
        assert_eq!(InflightMarker::decode("garbage"), None);
        assert_eq!(InflightMarker::decode(":123"), None);
        assert_eq!(InflightMarker::decode("abcd:notanumber"), None);
    }

    #[test]
    fn rotation_lost_only_for_the_same_token() {
        let m = InflightMarker { fingerprint: token_fingerprint("t1"), started_at: 1 };
        assert!(is_rotation_lost(Some(&m), &token_fingerprint("t1")));
        assert!(!is_rotation_lost(Some(&m), &token_fingerprint("t2")));
        assert!(!is_rotation_lost(None, &token_fingerprint("t1")));
    }
}
