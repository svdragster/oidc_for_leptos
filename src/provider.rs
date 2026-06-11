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
        let config_for_effect = config.clone();
        let state_for_effect = state;
        let access_token_for_effect = access_token;
        let id_token_for_effect = id_token;

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
                let config = config.clone();
                leptos::task::spawn_local(async move {
                    match crate::callback::browser::handle_callback(
                        &config,
                        state_for_effect,
                        access_token_for_effect,
                        id_token_for_effect,
                    )
                    .await
                    {
                        Ok(()) => {
                            // Schedule refresh timer based on current cookies
                            if let Some(tokens) = crate::cookie::browser::read_tokens(&config) {
                                crate::refresh::schedule_refresh(
                                    config,
                                    tokens.expires_at,
                                    state_for_effect,
                                    access_token_for_effect,
                                    id_token_for_effect,
                                );
                            }
                        }
                        Err(e) => {
                            leptos::logging::error!("[oidc] callback failed: {}", e);
                            state_for_effect
                                .set(AuthState::Error(format!("Login failed: {}", e)));
                        }
                    }
                });
                return;
            }

            // Not a callback — check cookies
            if let Some(tokens) = crate::cookie::browser::read_tokens(&config) {
                let now = (js_sys::Date::new_0().get_time() / 1000.0) as i64;
                let leeway = config.clock_skew_leeway_secs as i64;

                access_token_for_effect.set(Some(tokens.access_token.clone()));
                if config.store_id_token {
                    id_token_for_effect.set(tokens.id_token.clone());
                }

                if tokens.expires_at + leeway < now {
                    // Token expired — try refresh
                    let config = config.clone();
                    leptos::task::spawn_local(async move {
                        crate::refresh::try_refresh_or_unauthenticate(
                            &config,
                            state_for_effect,
                            access_token_for_effect,
                            id_token_for_effect,
                        )
                        .await;
                    });
                } else {
                    // Valid token — extract user info and set state
                    let user_info = extract_user_info_from_cookie_tokens(
                        &tokens.access_token,
                        tokens.id_token.as_deref(),
                    );
                    // Persist UserInfo cookie for SSR fallback (handles opaque access tokens)
                    crate::cookie::browser::write_user_info(&config, &user_info);
                    state_for_effect.set(AuthState::Authenticated(user_info));

                    // Schedule proactive refresh
                    crate::refresh::schedule_refresh(
                        config,
                        tokens.expires_at,
                        state_for_effect,
                        access_token_for_effect,
                        id_token_for_effect,
                    );
                }
            } else {
                // No cookies → unauthenticated
                state_for_effect.set(AuthState::Unauthenticated);
            }
        });

        // Mobile browsers suspend setTimeout while a tab/PWA is backgrounded, so
        // the proactive refresh timer may never fire before the user interacts
        // again. Re-check token freshness whenever the tab becomes visible.
        {
            use wasm_bindgen::JsCast;

            let config_for_visibility = config.clone();
            if let Some(document) = web_sys::window().and_then(|w| w.document()) {
                let closure = wasm_bindgen::closure::Closure::<dyn FnMut()>::new(move || {
                    let visible = web_sys::window()
                        .and_then(|w| w.document())
                        .map(|d| d.visibility_state() == web_sys::VisibilityState::Visible)
                        .unwrap_or(false);
                    if !visible {
                        return;
                    }

                    let config = config_for_visibility.clone();
                    leptos::task::spawn_local(async move {
                        let Some(tokens) = crate::cookie::browser::read_tokens(&config) else {
                            return;
                        };
                        let now = (js_sys::Date::new_0().get_time() / 1000.0) as i64;
                        let threshold = config.refresh_threshold_secs as i64;

                        if tokens.expires_at <= now + threshold {
                            crate::refresh::try_refresh_or_unauthenticate(
                                &config,
                                state_for_effect,
                                access_token_for_effect,
                                id_token_for_effect,
                            )
                            .await;
                        } else {
                            // Another tab may have refreshed while this one slept —
                            // sync signals from the cookies.
                            access_token_for_effect.set(Some(tokens.access_token));
                            if config.store_id_token {
                                id_token_for_effect.set(tokens.id_token);
                            }
                        }
                    });
                });
                let _ = document.add_event_listener_with_callback(
                    "visibilitychange",
                    closure.as_ref().unchecked_ref(),
                );
                // Provider lives for the app's lifetime — leak the listener.
                closure.forget();
            }
        }
    }

    // Build and provide AuthContext
    let auth_context = AuthContext {
        state,
        config: config.clone(),
        access_token,
        id_token,
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

/// Extract user info from tokens (try access_token JWT, then id_token)
#[cfg(any(feature = "hydrate", feature = "csr"))]
fn extract_user_info_from_cookie_tokens(
    access_token: &str,
    id_token: Option<&str>,
) -> crate::state::UserInfo {
    if let Ok(claims) = crate::token::decode_claims(access_token) {
        if claims.sub.is_some() {
            return crate::token::extract_user_info(&claims);
        }
    }
    if let Some(id_token) = id_token {
        if let Ok(claims) = crate::token::decode_claims(id_token) {
            return crate::token::extract_user_info(&claims);
        }
    }
    crate::state::UserInfo {
        subject: String::new(),
        email: None,
        name: None,
        preferred_username: None,
    }
}
