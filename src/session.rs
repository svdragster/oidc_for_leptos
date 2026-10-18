//! Per-tab session engine (browser only).
//!
//! - **Single-flight:** one refresh per tab at a time; concurrent callers
//!   (API calls, timer, visibility) await the same result.
//! - **One timer:** the proactive "refresh before expiry" timer and the
//!   backoff retry timer share a single handle, cleared on every reschedule.
//! - **Transient failures keep cookies and `AuthState`** and retry with
//!   backoff (1, 2, 4, 8, 16 s, then every 30 s), plus on `online`,
//!   `visibilitychange` and `pageshow`. Only a definitive IdP rejection ends
//!   the session.
//! - **Rotation hygiene:** no refresh starts while the page is hidden; the
//!   cookie is re-read before clearing; ambiguous rejections are re-sent once.
//! - **Auth events** go to the host app's hook (`events`).
//!
//! The decisions themselves come from `refresh_policy` (pure, unit-tested).

use std::cell::RefCell;

use futures::future::{FutureExt, LocalBoxFuture, Shared};
use leptos::prelude::*;
use wasm_bindgen::closure::Closure;
use wasm_bindgen::JsCast;

use crate::config::OidcConfig;
use crate::cookie::{self, TokenCookies};
use crate::events::{
    emit_auth_event, AuthEvent, AuthEventKind, ClientEnv, RefreshOutcome, RefreshTrigger,
};
use crate::locks;
use crate::refresh::{self, Attempt};
use crate::refresh_policy::{
    decide_after_failure, end_reason_for, is_stalled, resume_action, should_report_transient,
    should_start_refresh, NextStep, ResumeAction, SessionEndReason, StartDecision,
    TokenEndpointFailure,
};
use crate::state::{AuthState, RefreshStatus, TokenUnavailable, UserInfo};

type Outcome = Result<String, TokenUnavailable>;

/// Signals + config the engine drives. Set once by the provider.
#[derive(Clone)]
pub(crate) struct Handles {
    pub config: OidcConfig,
    pub state: RwSignal<AuthState>,
    pub access_token: RwSignal<Option<String>>,
    pub id_token: RwSignal<Option<String>>,
    pub status: RwSignal<RefreshStatus>,
}

/// Bookkeeping of the current failing run (reset on success / session end).
#[derive(Clone, Default)]
struct RunState {
    failed_attempts: u32,
    failing_since: Option<i64>,
    stalled: bool,
    /// Retries keep forcing when the run started from an API 401.
    force: bool,
}

/// The single pending timer. `gen` identifies it so a fired timer only clears itself.
struct Timer {
    gen: u64,
    id: i32,
    _closure: Closure<dyn FnMut()>,
}

#[derive(Default)]
struct Engine {
    handles: Option<Handles>,
    in_flight: Option<Shared<LocalBoxFuture<'static, Outcome>>>,
    /// The single pending timer (proactive refresh or backoff retry).
    timer: Option<Timer>,
    timer_gen: u64,
    run: RunState,
}

thread_local! {
    // WASM is single-threaded: one engine per tab.
    static ENGINE: RefCell<Engine> = RefCell::new(Engine::default());
}

/// Called by the provider before anything else touches the engine.
pub(crate) fn init(handles: Handles) {
    ENGINE.with(|e| e.borrow_mut().handles = Some(handles));
}

fn handles() -> Option<Handles> {
    ENGINE.with(|e| e.borrow().handles.clone())
}

/// Current Unix time in seconds (epoch math only — no calendar/timezone use).
pub(crate) fn now_secs() -> i64 {
    (js_sys::Date::now() / 1000.0) as i64
}

fn is_hidden() -> bool {
    web_sys::window()
        .and_then(|w| w.document())
        .map(|d| d.visibility_state() == web_sys::VisibilityState::Hidden)
        .unwrap_or(false)
}

// ---------------------------------------------------------------------------
// Entry points
// ---------------------------------------------------------------------------

/// Refresh the session (single-flight). Joins a running refresh; doesn't start
/// one while the page is hidden (returns `Transient`; the visibility handler
/// refreshes once the page is visible again).
pub(crate) async fn refresh(trigger: RefreshTrigger, force: bool) -> Outcome {
    let Some(h) = handles() else {
        return Err(TokenUnavailable::Transient);
    };

    let in_flight = ENGINE.with(|e| e.borrow().in_flight.clone());
    match should_start_refresh(in_flight.is_some(), is_hidden()) {
        StartDecision::JoinInFlight => {
            if let Some(shared) = in_flight {
                return shared.await;
            }
        }
        StartDecision::DeferUntilVisible => {
            leptos::logging::log!("[oidc] page hidden — refresh ({:?}) deferred until visible", trigger);
            return Err(TokenUnavailable::Transient);
        }
        StartDecision::Start => {}
    }

    // The attempt is driven by its own task so a dropped caller never leaves
    // the in-flight slot occupied; callers only await the shared result.
    let (tx, rx) = futures::channel::oneshot::channel::<Outcome>();
    let shared = rx
        .map(|r| r.unwrap_or(Err(TokenUnavailable::Transient)))
        .boxed_local()
        .shared();
    ENGINE.with(|e| e.borrow_mut().in_flight = Some(shared.clone()));
    // A run is starting: its result schedules the next timer.
    cancel_timer();
    h.status.update(|s| s.in_flight = true);

    let force = force || ENGINE.with(|e| e.borrow().run.force);
    leptos::task::spawn_local(async move {
        let out = run(h.clone(), trigger, force).await;
        ENGINE.with(|e| e.borrow_mut().in_flight = None);
        h.status.update(|s| s.in_flight = false);
        let _ = tx.send(out);
    });

    shared.await
}

/// Manual retry ("retry" button): skip the remaining backoff wait.
pub fn retry_now() {
    let failing = ENGINE.with(|e| e.borrow().run.failed_attempts > 0);
    if failing {
        leptos::task::spawn_local(async {
            let _ = refresh(RefreshTrigger::Manual, false).await;
        });
    }
}

/// Page became usable again (visible, restored from bfcache, back online).
pub(crate) fn on_resume(trigger: RefreshTrigger) {
    let Some(h) = handles() else { return };
    if is_hidden() || ENGINE.with(|e| e.borrow().in_flight.is_some()) {
        return;
    }
    let Some(tokens) = cookie::browser::read_tokens(&h.config) else {
        return;
    };
    let failing = ENGINE.with(|e| e.borrow().run.failed_attempts > 0);
    let threshold = h.config.refresh_threshold_secs as i64;
    match resume_action(failing, tokens.expires_at, now_secs(), threshold) {
        ResumeAction::Refresh => {
            leptos::task::spawn_local(async move {
                let _ = refresh(trigger, false).await;
            });
        }
        ResumeAction::SyncFromCookie => {
            // Another tab may have refreshed while this one slept; timers were
            // throttled in the background — re-arm the single timer.
            sync_from_cookie(tokens);
        }
    }
}

/// Use a still-fresh cookie token: sync signals, settle `Authenticated` if
/// needed (e.g. another tab refreshed while this one was retrying) and re-arm
/// the timer. Returns the access token.
pub(crate) fn sync_from_cookie(tokens: TokenCookies) -> String {
    match handles() {
        Some(h) => {
            let needs_adopt = !matches!(h.state.get_untracked(), AuthState::Authenticated(_))
                || ENGINE.with(|e| e.borrow().run.failed_attempts > 0)
                || ENGINE.with(|e| e.borrow().timer.is_none());
            if needs_adopt {
                adopt(&h, tokens, None)
            } else {
                if h.access_token.get_untracked().as_deref() != Some(tokens.access_token.as_str()) {
                    h.access_token.set(Some(tokens.access_token.clone()));
                    if h.config.store_id_token {
                        h.id_token.set(tokens.id_token);
                    }
                }
                tokens.access_token
            }
        }
        None => tokens.access_token,
    }
}

/// No token cookies at all: settle `Unauthenticated` (reason `no_tokens`).
pub(crate) fn end_session_without_tokens() {
    if let Some(h) = handles() {
        if !matches!(h.state.get_untracked(), AuthState::Unauthenticated) {
            end_session(&h, SessionEndReason::NoTokens);
        }
    }
}

/// Initial state from cookies at page load (provider).
pub(crate) fn start_from_cookies() {
    let Some(h) = handles() else { return };
    match cookie::browser::read_tokens(&h.config) {
        None => {
            h.status.update(|s| s.end_reason = Some(SessionEndReason::NoTokens));
            h.state.set(AuthState::Unauthenticated);
        }
        Some(tokens) => {
            h.access_token.set(Some(tokens.access_token.clone()));
            if h.config.store_id_token {
                h.id_token.set(tokens.id_token.clone());
            }
            let leeway = h.config.clock_skew_leeway_secs as i64;
            if tokens.expires_at + leeway < now_secs() {
                // Expired: stay `Loading` until the refresh settles (never
                // `Unauthenticated` for a transient failure).
                leptos::task::spawn_local(async {
                    let _ = refresh(RefreshTrigger::Load, false).await;
                });
            } else {
                adopt(&h, tokens, None);
            }
        }
    }
}

/// After a successful code exchange: record the issuance and arm the timer.
pub(crate) fn after_login(expires_at: i64) {
    if let Some(h) = handles() {
        refresh::write_last_refresh_at(&h.config, now_secs());
        refresh::clear_marker(&h.config);
        h.status.set(RefreshStatus::default());
    }
    schedule_proactive(expires_at);
}

/// Emit a login-redirect event with the current session facts.
pub fn report_login_redirect(reason: &str) {
    let mut event = AuthEvent::new(AuthEventKind::LoginRedirect);
    event.reason = Some(reason.to_string());
    if let Some(h) = handles() {
        fill_context(&mut event, &h, None);
    } else {
        event.env = client_env();
    }
    emit_auth_event(event);
}

// ---------------------------------------------------------------------------
// One run: attempt (+ optional confirmation) and apply the result
// ---------------------------------------------------------------------------

async fn run(h: Handles, trigger: RefreshTrigger, force: bool) -> Outcome {
    let expires_at_at_start = cookie::browser::read_tokens(&h.config).map(|t| t.expires_at);
    let lock_name = format!("{}_refresh_lock", h.config.cookie_name_prefix);
    let mut confirmed = false;
    let mut rotation_lost = false;
    let mut first = true;

    loop {
        let config = h.config.clone();
        let check_marker = first;
        first = false;
        let attempt = locks::with_refresh_lock(&lock_name, || async move {
            refresh::attempt_refresh(&config, force, check_marker).await
        })
        .await;

        match attempt {
            Attempt::Refreshed { access_token, id_token, expires_at } => {
                return Ok(apply_success(&h, access_token, id_token, expires_at, trigger));
            }
            Attempt::AlreadyFresh(tokens) => {
                // AlreadyRefreshed by another tab: settle Authenticated (a
                // `Loading` page must not hang on the spinner).
                return Ok(adopt(&h, tokens, Some((trigger, RefreshOutcome::Adopted))));
            }
            Attempt::NoTokens => {
                end_session(&h, SessionEndReason::NoTokens);
                return Err(TokenUnavailable::Terminal);
            }
            Attempt::Failed { failure, sent_refresh_token, rotation_lost: lost } => {
                rotation_lost |= lost;
                // Rotation hygiene: re-read the cookie before acting on a rejection.
                let current = cookie::browser::read_tokens(&h.config);
                let cookie_changed = current
                    .as_ref()
                    .is_some_and(|t| !t.refresh_token.is_empty() && t.refresh_token != sent_refresh_token);
                let failed_attempts = ENGINE.with(|e| e.borrow().run.failed_attempts) + 1;

                match decide_after_failure(&failure, cookie_changed, confirmed, failed_attempts) {
                    NextStep::AdoptCookie => {
                        if let Some(tokens) = current {
                            leptos::logging::log!("[oidc] token rejected but another tab rotated it — adopting");
                            return Ok(adopt(&h, tokens, Some((trigger, RefreshOutcome::Adopted))));
                        }
                    }
                    NextStep::Confirm { delay_ms } => {
                        leptos::logging::log!(
                            "[oidc] ambiguous rejection ({}) — confirming once",
                            failure.summary()
                        );
                        confirmed = true;
                        sleep_ms(delay_ms).await;
                        continue;
                    }
                    NextStep::EndSession => {
                        let reason = end_reason_for(failure.class, rotation_lost);
                        let mut event = AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(&failure);
                        event.trigger = Some(trigger);
                        event.rotation_lost = rotation_lost;
                        fill_context(&mut event, &h, expires_at_at_start);
                        end_session(&h, reason);
                        emit_auth_event(event);
                        return Err(TokenUnavailable::Terminal);
                    }
                    NextStep::RetryAfter { delay_ms } => {
                        record_transient(&h, &failure, trigger, force, delay_ms, expires_at_at_start);
                        return Err(TokenUnavailable::Transient);
                    }
                }
                // AdoptCookie without a cookie cannot happen (cookie_changed
                // implies one); treat it as a transient failure to be safe.
                record_transient(&h, &failure, trigger, force, 1_000, expires_at_at_start);
                return Err(TokenUnavailable::Transient);
            }
        }
    }
}

fn apply_success(
    h: &Handles,
    access_token: String,
    id_token: Option<String>,
    expires_at: i64,
    trigger: RefreshTrigger,
) -> String {
    h.access_token.set(Some(access_token.clone()));
    if h.config.store_id_token {
        h.id_token.set(id_token.clone());
    }
    let info = resolve_user_info(h, &access_token, id_token.as_deref());
    // Persist UserInfo cookie for SSR fallback (handles opaque access tokens)
    cookie::browser::write_user_info(&h.config, &info);
    refresh::write_last_refresh_at(&h.config, now_secs());
    finish_run_ok(h, Some((trigger, RefreshOutcome::Success)));
    h.state.set(AuthState::Authenticated(info));
    schedule_proactive(expires_at);
    access_token
}

/// Adopt valid cookie tokens (another tab refreshed, or still fresh).
fn adopt(h: &Handles, tokens: TokenCookies, recovered: Option<(RefreshTrigger, RefreshOutcome)>) -> String {
    h.access_token.set(Some(tokens.access_token.clone()));
    if h.config.store_id_token {
        h.id_token.set(tokens.id_token.clone());
    }
    if !matches!(h.state.get_untracked(), AuthState::Authenticated(_)) {
        let info = resolve_user_info(h, &tokens.access_token, tokens.id_token.as_deref());
        cookie::browser::write_user_info(&h.config, &info);
        finish_run_ok(h, recovered);
        h.state.set(AuthState::Authenticated(info));
    } else {
        finish_run_ok(h, recovered);
    }
    schedule_proactive(tokens.expires_at);
    tokens.access_token
}

/// Reset the failing run; report a recovery if the run had failed before.
fn finish_run_ok(h: &Handles, recovered: Option<(RefreshTrigger, RefreshOutcome)>) {
    let run = ENGINE.with(|e| std::mem::take(&mut e.borrow_mut().run));
    let status = h.status.get_untracked();
    if status.failed_attempts > 0 || status.end_reason.is_some() || status.stalled {
        h.status.update(|s| {
            s.failed_attempts = 0;
            s.failing_since = None;
            s.stalled = false;
            s.end_reason = None;
        });
    }
    if run.failed_attempts > 0 {
        let mut event = AuthEvent::new(AuthEventKind::RefreshRecovered);
        if let Some((trigger, outcome)) = recovered {
            event.trigger = Some(trigger);
            event.outcome = Some(outcome);
        }
        event.failed_attempts = run.failed_attempts;
        event.secs_failing = run.failing_since.map(|s| now_secs() - s);
        fill_context(&mut event, h, None);
        emit_auth_event(event);
    }
}

/// Definitive end: clear cookies + signals, state `Unauthenticated`.
fn end_session(h: &Handles, reason: SessionEndReason) {
    cancel_timer();
    ENGINE.with(|e| e.borrow_mut().run = RunState::default());
    cookie::browser::clear_tokens(&h.config);
    refresh::clear_marker(&h.config);
    h.access_token.set(None);
    h.id_token.set(None);
    // Status first: guards read `end_reason` when the state flips.
    h.status.update(|s| {
        s.failed_attempts = 0;
        s.failing_since = None;
        s.stalled = false;
        s.end_reason = Some(reason);
    });
    leptos::logging::log!("[oidc] session ended: {}", reason.as_str());
    h.state.set(AuthState::Unauthenticated);
}

/// Transient failure: keep cookies + state, count it, schedule the retry.
fn record_transient(
    h: &Handles,
    failure: &TokenEndpointFailure,
    trigger: RefreshTrigger,
    force: bool,
    delay_ms: u32,
    expires_at_at_start: Option<i64>,
) {
    let now = now_secs();
    let (attempts, since, stalled_before, stalled_now) = ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        let run = &mut e.run;
        run.failed_attempts += 1;
        run.force |= force;
        let since = *run.failing_since.get_or_insert(now);
        let before = run.stalled;
        run.stalled = is_stalled(since, now);
        (run.failed_attempts, since, before, run.stalled)
    });
    h.status.update(|s| {
        s.failed_attempts = attempts;
        s.failing_since = Some(since);
        s.stalled = stalled_now;
    });
    leptos::logging::warn!(
        "[oidc] refresh failed transiently (attempt {}, {}) — retrying in {} ms",
        attempts,
        failure.summary(),
        delay_ms
    );
    schedule_timer(delay_ms, RefreshTrigger::Retry);

    if should_report_transient(attempts, stalled_before, stalled_now) {
        let mut event = AuthEvent::new(AuthEventKind::RefreshFailed).with_failure(failure);
        event.trigger = Some(trigger);
        event.failed_attempts = attempts;
        event.secs_failing = Some(now - since);
        fill_context(&mut event, h, expires_at_at_start);
        emit_auth_event(event);
    }
}

// ---------------------------------------------------------------------------
// Timer (single handle)
// ---------------------------------------------------------------------------

/// Arm the proactive refresh `refresh_threshold_secs` before expiry.
pub(crate) fn schedule_proactive(expires_at: i64) {
    let Some(h) = handles() else { return };
    let threshold = h.config.refresh_threshold_secs as i64;
    let delay_secs = (expires_at - threshold - now_secs()).max(0);
    // setTimeout overflows above ~24.8 days; clamp (re-armed on resume anyway).
    let delay_ms = (delay_secs.saturating_mul(1000)).min(i32::MAX as i64) as u32;
    schedule_timer(delay_ms, RefreshTrigger::Timer);
}

/// Replace the single pending timer.
fn schedule_timer(delay_ms: u32, trigger: RefreshTrigger) {
    cancel_timer();
    let Some(window) = web_sys::window() else { return };
    let gen = ENGINE.with(|e| {
        let mut e = e.borrow_mut();
        e.timer_gen += 1;
        e.timer_gen
    });
    let closure = Closure::<dyn FnMut()>::new(move || {
        // Only spawn here; the task drops this closure (never while it runs).
        leptos::task::spawn_local(async move {
            let fired_is_current = ENGINE.with(|e| {
                let mut e = e.borrow_mut();
                let current = e.timer.as_ref().is_some_and(|t| t.gen == gen);
                if current {
                    e.timer = None;
                }
                current
            });
            if fired_is_current {
                let _ = refresh(trigger, false).await;
            }
        });
    });
    let delay = delay_ms.min(i32::MAX as u32) as i32;
    if let Ok(id) = window
        .set_timeout_with_callback_and_timeout_and_arguments_0(closure.as_ref().unchecked_ref(), delay)
    {
        ENGINE.with(|e| e.borrow_mut().timer = Some(Timer { gen, id, _closure: closure }));
    }
}

fn cancel_timer() {
    let old = ENGINE.with(|e| e.borrow_mut().timer.take());
    if let Some(timer) = old {
        if let Some(window) = web_sys::window() {
            window.clear_timeout_with_handle(timer.id);
        }
        // The closure is dropped here — never while it runs (it only spawns a task).
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

async fn sleep_ms(ms: u32) {
    let promise = js_sys::Promise::new(&mut |resolve, _reject| {
        let scheduled = web_sys::window().and_then(|w| {
            w.set_timeout_with_callback_and_timeout_and_arguments_0(&resolve, ms as i32)
                .ok()
        });
        if scheduled.is_none() {
            let _ = resolve.call0(&wasm_bindgen::JsValue::NULL);
        }
    });
    let _ = wasm_bindgen_futures::JsFuture::from(promise).await;
}

/// User info from the new tokens; falls back to the current state, then to
/// the user_info cookie written at login (opaque access tokens, cold start).
fn resolve_user_info(h: &Handles, access_token: &str, id_token: Option<&str>) -> UserInfo {
    crate::token::user_info_from_tokens(access_token, id_token)
        .or_else(|| match h.state.get_untracked() {
            AuthState::Authenticated(info) => Some(info),
            _ => None,
        })
        .or_else(|| cookie::browser::read_user_info(&h.config))
        .unwrap_or_else(|| UserInfo {
            subject: String::new(),
            email: None,
            name: None,
            preferred_username: None,
        })
}

/// Timing facts + browser env for an event.
fn fill_context(event: &mut AuthEvent, h: &Handles, expires_at: Option<i64>) {
    let now = now_secs();
    let expires_at =
        expires_at.or_else(|| cookie::browser::read_tokens(&h.config).map(|t| t.expires_at));
    event.secs_since_expires_at = expires_at.map(|e| now - e);
    event.secs_since_last_refresh = refresh::read_last_refresh_at(&h.config).map(|t| now - t);
    if event.failed_attempts == 0 {
        event.failed_attempts = ENGINE.with(|e| e.borrow().run.failed_attempts);
    }
    event.env = client_env();
}

#[wasm_bindgen::prelude::wasm_bindgen(inline_js = r#"
export function oidc_is_standalone() {
    try {
        return (window.matchMedia && window.matchMedia('(display-mode: standalone)').matches) ||
               window.navigator.standalone === true;
    } catch (e) { return false; }
}
"#)]
extern "C" {
    fn oidc_is_standalone() -> bool;
}

fn client_env() -> ClientEnv {
    let window = web_sys::window();
    ClientEnv {
        standalone: Some(oidc_is_standalone()),
        web_locks: Some(locks::web_locks_available()),
        online: window.as_ref().map(|w| w.navigator().on_line()),
        visible: Some(!is_hidden()),
    }
}
