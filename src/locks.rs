/// Web Locks API wrapper for preventing token refresh race conditions across tabs.
///
/// Primary: Web Locks API (navigator.locks.request) for true cross-tab mutex.
/// Fallback: proceed optimistically — cookie-check in refresh logic handles double-refresh.

use wasm_bindgen::prelude::*;

// JavaScript interop for Web Locks API
#[wasm_bindgen(inline_js = r#"
export function is_web_locks_available() {
    return typeof navigator !== 'undefined' &&
           typeof navigator.locks !== 'undefined' &&
           typeof navigator.locks.request === 'function';
}

export function acquire_web_lock(name) {
    return new Promise((resolveOuter) => {
        if (!navigator.locks) {
            resolveOuter({ acquired: false });
            return;
        }

        let releaseCallback = null;
        const releasePromise = new Promise((resolve) => {
            releaseCallback = resolve;
        });

        navigator.locks.request(name, { mode: 'exclusive' }, async (lock) => {
            resolveOuter({
                acquired: true,
                release: releaseCallback
            });
            await releasePromise;
        });
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
    fn acquire_web_lock(name: &str) -> js_sys::Promise;
    fn release_web_lock(lock_handle: &JsValue);
}

/// Execute a function while holding the refresh lock.
/// Prevents multiple tabs from refreshing simultaneously.
pub async fn with_refresh_lock<F, Fut, T, E>(lock_name: &str, f: F) -> Result<T, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    if is_web_locks_available() {
        with_web_lock(lock_name, f).await
    } else {
        // Simplified fallback: just proceed optimistically.
        // Cookie-check in refresh logic prevents actual double-refresh.
        f().await
    }
}

/// Execute function with Web Locks API
async fn with_web_lock<F, Fut, T, E>(lock_name: &str, f: F) -> Result<T, E>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
{
    let lock_result = wasm_bindgen_futures::JsFuture::from(acquire_web_lock(lock_name)).await;

    let lock_handle = match lock_result {
        Ok(handle) => handle,
        Err(_) => {
            // Lock acquisition failed, proceed without lock
            return f().await;
        }
    };

    let result = f().await;

    release_web_lock(&lock_handle);

    result
}
