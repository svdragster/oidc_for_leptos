//! Web Locks API wrapper for preventing token refresh race conditions across tabs.
//!
//! Primary: Web Locks API (navigator.locks.request) for a true cross-tab mutex.
//! Fallback (no Web Locks, lock request rejected, or waited longer than
//! `refresh_policy::LOCK_TIMEOUT_MS` — e.g. a frozen tab holds it): proceed
//! without the lock. The refresh logic then relies on rotation hygiene
//! (freshness re-check, cookie re-read before clearing, confirmation re-send).

use wasm_bindgen::prelude::*;

// JavaScript interop for Web Locks API
#[wasm_bindgen(inline_js = r#"
export function is_web_locks_available() {
    return typeof navigator !== 'undefined' &&
           typeof navigator.locks !== 'undefined' &&
           navigator.locks !== null &&
           typeof navigator.locks.request === 'function';
}

export function acquire_web_lock(name, timeoutMs) {
    return new Promise((resolveOuter) => {
        if (!is_web_locks_available()) {
            resolveOuter({ acquired: false });
            return;
        }

        let releaseCallback = null;
        const releasePromise = new Promise((resolve) => {
            releaseCallback = resolve;
        });

        // Bounded wait: abort the queued request after timeoutMs.
        const ctrl = (typeof AbortController !== 'undefined') ? new AbortController() : null;
        const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
        const opts = { mode: 'exclusive' };
        if (ctrl) { opts.signal = ctrl.signal; }

        try {
            navigator.locks.request(name, opts, async (lock) => {
                if (timer) { clearTimeout(timer); }
                resolveOuter({ acquired: true, release: releaseCallback });
                await releasePromise;
            }).catch(() => {
                // Aborted (timeout) or rejected (e.g. SecurityError): run unlocked.
                if (timer) { clearTimeout(timer); }
                resolveOuter({ acquired: false });
            });
        } catch (e) {
            if (timer) { clearTimeout(timer); }
            resolveOuter({ acquired: false });
        }
    });
}

export function release_web_lock(lockHandle) {
    if (lockHandle && lockHandle.release) {
        lockHandle.release();
    }
}
"#)]
extern "C" {
    fn is_web_locks_available() -> bool;
    fn acquire_web_lock(name: &str, timeout_ms: u32) -> js_sys::Promise;
    fn release_web_lock(lock_handle: &JsValue);
}

/// Whether the browser offers Web Locks (missing on iOS < 15.4). Telemetry fact.
pub fn web_locks_available() -> bool {
    is_web_locks_available()
}

/// Execute a future while holding the cross-tab refresh lock (best effort,
/// see module docs). Prevents multiple tabs from refreshing simultaneously.
pub async fn with_refresh_lock<F, Fut, T>(lock_name: &str, f: F) -> T
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    if !is_web_locks_available() {
        return f().await;
    }

    let lock_handle = wasm_bindgen_futures::JsFuture::from(acquire_web_lock(
        lock_name,
        crate::refresh_policy::LOCK_TIMEOUT_MS,
    ))
    .await
    .ok();

    let result = f().await;

    if let Some(handle) = lock_handle {
        release_web_lock(&handle);
    }

    result
}
