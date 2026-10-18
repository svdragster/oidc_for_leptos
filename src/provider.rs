use leptos::prelude::*;

use crate::config::OidcConfig;
use crate::state::{AuthContext, AuthState};

/// Main OIDC auth provider component.
///
/// SSR: reads cookies from request, initializes state synchronously (no Loading flash).
/// CSR/hydrate: reads cookies, handles OAuth callbacks, schedules token refresh.
#[component]
pub fn OidcAuthProvider(
    config: OidcConfig,
    children: ChildrenFn,
) -> impl IntoView {
    let state = RwSignal::new(AuthState::Loading);
    let access_token = RwSignal::new(None::<String>);
    let id_token = RwSignal::new(None::<String>);
    let refresh_status = RwSignal::new(crate::state::RefreshStatus::default());

    // -- SSR path: synchronous initialization from request cookies --
    #[cfg(feature = "ssr")]
    {
        let clock = crate::state::SystemClock;
        let initial_state = crate::server::init_auth_state_from_request(&config, &clock);

        // If authenticated, also populate token signals from cookies
        if matches!(initial_state, AuthState::Authenticated(_)) {
            if let Some(tokens) = crate::cookie::server::read_tokens_from_request(&config) {
                access_token.set(Some(tokens.access_token));
                if config.store_id_token {
                    id_token.set(tokens.id_token);
                }
            }
        }

        state.set(initial_state);
    }

    // -- CSR/hydrate path: browser-side initialization --
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    {
        // The session engine owns refreshes, the single timer and retries.
        crate::session::init(crate::session::Handles {
            config: config.clone(),
            state,
            access_token,
            id_token,
            status: refresh_status,
        });

        let config_for_effect = config.clone();

        // Run once on mount
        Effect::new(move |_| {
            let config = config_for_effect.clone();

            // Check if this is an OAuth callback (URL has ?code=)
            let is_callback = web_sys::window()
                .and_then(|w| w.location().href().ok())
                .map(|h| h.contains("code="))
                .unwrap_or(false);

            if is_callback {
                // Handle OAuth callback
                leptos::task::spawn_local(async move {
                    match crate::callback::browser::handle_callback(
                        &config,
                        state,
                        access_token,
                        id_token,
                    )
                    .await
                    {
                        Ok(()) => {
                            // Arm the refresh timer based on the new cookies
                            if let Some(tokens) = crate::cookie::browser::read_tokens(&config) {
                                crate::session::after_login(tokens.expires_at);
                            }
                        }
                        Err(e) => {
                            leptos::logging::error!("[oidc] callback failed: {}", e);
                            state.set(AuthState::Error(format!("Login failed: {}", e)));
                        }
                    }
                });
                return;
            }

            // Not a callback — valid token → Authenticated; expired → refresh
            // (state stays Loading until it settles); none → Unauthenticated.
            crate::session::start_from_cookies();
        });

        // Resume handlers. Mobile browsers suspend setTimeout while a tab/PWA is
        // backgrounded, and a refresh that failed while offline must retry once
        // the network is back:
        // - visibilitychange → visible
        // - pageshow with `persisted` (restored from the back/forward cache)
        // - online
        // Each re-checks freshness (or retries a failing run) via the engine.
        // The provider lives for the app's lifetime — the listeners are leaked.
        {
            use wasm_bindgen::JsCast;

            if let Some(window) = web_sys::window() {
                if let Some(document) = window.document() {
                    let on_visibility = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
                        crate::session::on_resume(crate::events::RefreshTrigger::Visibility);
                    });
                    let _ = document.add_event_listener_with_callback(
                        "visibilitychange",
                        on_visibility.as_ref().unchecked_ref(),
                    );
                    on_visibility.forget();
                }

                let on_pageshow = wasm_bindgen::closure::Closure::<dyn FnMut(web_sys::Event)>::new(
                    move |event: web_sys::Event| {
                        let persisted = event
                            .dyn_ref::<web_sys::PageTransitionEvent>()
                            .map(|e| e.persisted())
                            .unwrap_or(false);
                        if persisted {
                            crate::session::on_resume(crate::events::RefreshTrigger::PageShow);
                        }
                    },
                );
                let _ = window
                    .add_event_listener_with_callback("pageshow", on_pageshow.as_ref().unchecked_ref());
                on_pageshow.forget();

                let on_online = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
                    crate::session::on_resume(crate::events::RefreshTrigger::Online);
                });
                let _ = window
                    .add_event_listener_with_callback("online", on_online.as_ref().unchecked_ref());
                on_online.forget();
            }
        }
    }

    // Build and provide AuthContext
    let auth_context = AuthContext {
        state,
        config: config.clone(),
        access_token,
        id_token,
        refresh_status,
    };

    provide_context(auth_context);
    provide_context(config);

    view! {
        {move || children()}
    }
}

/// Get auth context from Leptos context
pub fn use_auth() -> AuthContext {
    use_context::<AuthContext>()
        .expect("AuthContext not found — wrap your app in <OidcAuthProvider>")
}
