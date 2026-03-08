use leptos::prelude::*;
use crate::provider::use_auth;
use crate::state::AuthState;

/// Renders children only when authenticated.
/// Optional fallback for non-authenticated states.
#[component]
pub fn Authenticated(
    children: ChildrenFn,
    #[prop(optional)] fallback: Option<ChildrenFn>,
) -> impl IntoView {
    let auth = use_auth();

    view! {
        {move || {
            match auth.state().get() {
                AuthState::Authenticated(_) => children().into_any(),
                _ => {
                    if let Some(ref fb) = fallback {
                        fb().into_any()
                    } else {
                        view! {}.into_any()
                    }
                }
            }
        }}
    }
}

/// Renders children only when unauthenticated
#[component]
pub fn Unauthenticated(children: ChildrenFn) -> impl IntoView {
    let auth = use_auth();

    view! {
        {move || {
            match auth.state().get() {
                AuthState::Unauthenticated => children().into_any(),
                _ => view! {}.into_any(),
            }
        }}
    }
}

/// Renders children only while auth is loading
#[component]
pub fn AuthLoading(children: ChildrenFn) -> impl IntoView {
    let auth = use_auth();

    view! {
        {move || {
            match auth.state().get() {
                AuthState::Loading => children().into_any(),
                _ => view! {}.into_any(),
            }
        }}
    }
}

/// Login link that generates the authorization URL with PKCE on mount.
/// SSR: renders a placeholder <a href="#">.
/// CSR/hydrate: generates auth URL once via Effect, writes PKCE verifier to cookie.
#[component]
pub fn LoginLink(
    children: Children,
    #[prop(optional)] class: Option<String>,
) -> impl IntoView {
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    {
        let auth = use_auth();
        let login_url = RwSignal::new(None::<String>);

        // Generate auth URL once on mount
        Effect::new(move |_| {
            if login_url.get_untracked().is_some() {
                return;
            }

            let pkce = match crate::pkce::generate() {
                Ok(p) => p,
                Err(e) => {
                    leptos::logging::error!("[oidc] PKCE generation failed: {}", e);
                    return;
                }
            };

            // Write PKCE verifier to short-lived cookie
            crate::cookie::browser::write_pkce_verifier(auth.config(), &pkce.verifier);

            // Generate a random state parameter for CSRF protection and store in cookie
            let mut state_bytes = [0u8; 16];
            let _ = getrandom::getrandom(&mut state_bytes);
            let state = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                state_bytes,
            );
            crate::cookie::browser::write_oauth_state(auth.config(), &state);

            // Generate a nonce
            let mut nonce_bytes = [0u8; 16];
            let _ = getrandom::getrandom(&mut nonce_bytes);
            let nonce = base64::Engine::encode(
                &base64::engine::general_purpose::URL_SAFE_NO_PAD,
                nonce_bytes,
            );

            let config = auth.config();
            let url = format!(
                "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&nonce={}",
                config.authorization_endpoint(),
                url_encode(&config.client_id),
                url_encode(&config.redirect_uri),
                url_encode(&config.scopes.join(" ")),
                url_encode(&state),
                url_encode(&pkce.challenge),
                url_encode(&nonce),
            );

            login_url.set(Some(url));
        });

        view! {
            <a href=move || login_url.get().unwrap_or_else(|| "#".to_string()) class=class.unwrap_or_default()>
                {children()}
            </a>
        }
    }

    #[cfg(not(any(feature = "hydrate", feature = "csr")))]
    {
        view! {
            <a href="#" class=class.unwrap_or_default()>
                {children()}
            </a>
        }
    }
}

/// Logout link that clears cookies and redirects to the IdP's end_session endpoint.
/// SSR/no-feature: renders a placeholder.
#[component]
pub fn LogoutLink(
    children: Children,
    #[prop(optional)] class: Option<String>,
) -> impl IntoView {
    #[cfg(any(feature = "hydrate", feature = "csr"))]
    {
        let auth = use_auth();

        let on_click = {
            let auth = auth.clone();
            move |_e: leptos::ev::MouseEvent| {
                crate::cookie::browser::clear_tokens(auth.config());
            }
        };

        let href = {
            let auth = auth.clone();
            move || auth.logout_url()
        };

        view! {
            <a href=href class=class.unwrap_or_default() on:click=on_click>
                {children()}
            </a>
        }
    }

    #[cfg(not(any(feature = "hydrate", feature = "csr")))]
    {
        view! {
            <a href="#" class=class.unwrap_or_default()>
                {children()}
            </a>
        }
    }
}

/// URL-encode using JS encodeURIComponent (available in WASM)
#[cfg(any(feature = "hydrate", feature = "csr"))]
fn url_encode(s: &str) -> String {
    js_sys::encode_uri_component(s)
        .as_string()
        .unwrap_or_else(|| s.to_string())
}
