use crate::error::OidcError;

/// Parsed OAuth callback parameters
#[derive(Debug, Clone)]
pub struct CallbackParams {
    pub code: String,
    pub state: String,
}

/// Parse OAuth callback parameters from a URL.
/// Checks for error params first, then extracts code + state.
pub fn parse_callback(url_str: &str) -> Result<CallbackParams, OidcError> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| OidcError::Callback {
            kind: "parse_error".into(),
            description: format!("invalid URL: {}", e),
        })?;

    let params: std::collections::HashMap<String, String> =
        parsed.query_pairs().map(|(k, v)| (k.to_string(), v.to_string())).collect();

    // Check for error response first
    if let Some(error) = params.get("error") {
        let description = params
            .get("error_description")
            .cloned()
            .unwrap_or_default();
        return Err(OidcError::Callback {
            kind: error.clone(),
            description,
        });
    }

    let code = params.get("code").cloned().ok_or_else(|| OidcError::Callback {
        kind: "missing_code".into(),
        description: "no 'code' parameter in callback URL".into(),
    })?;

    let state = params.get("state").cloned().ok_or_else(|| OidcError::Callback {
        kind: "missing_state".into(),
        description: "no 'state' parameter in callback URL".into(),
    })?;

    Ok(CallbackParams { code, state })
}

// -- Browser-side callback handler (code exchange) --
#[cfg(any(feature = "hydrate", feature = "csr"))]
pub(crate) mod browser {
    use super::*;
    use crate::config::OidcConfig;
    use crate::cookie;
    use crate::refresh::TokenResponse;
    use crate::state::{AuthState, UserInfo};
    use crate::token;
    use leptos::prelude::*;

    /// Full callback handler: parse URL, exchange code, write cookies, update signals.
    pub async fn handle_callback(
        config: &OidcConfig,
        state_signal: RwSignal<AuthState>,
        access_token_signal: RwSignal<Option<String>>,
        id_token_signal: RwSignal<Option<String>>,
    ) -> Result<(), OidcError> {
        let window = web_sys::window().ok_or_else(|| OidcError::Network("no window".into()))?;
        let href = window
            .location()
            .href()
            .map_err(|_| OidcError::Network("failed to get location.href".into()))?;

        let params = parse_callback(&href)?;

        // Verify CSRF state parameter against stored cookie
        let expected_state = cookie::browser::read_oauth_state(config)
            .ok_or_else(|| OidcError::Callback {
                kind: "state_missing".into(),
                description: "no OAuth state cookie found — possible CSRF attack or expired session".into(),
            })?;
        if params.state != expected_state {
            cookie::browser::clear_oauth_state(config);
            return Err(OidcError::Callback {
                kind: "state_mismatch".into(),
                description: "OAuth state parameter does not match — possible CSRF attack".into(),
            });
        }

        // Read PKCE verifier from cookie
        let verifier = cookie::browser::read_pkce_verifier(config)
            .ok_or_else(|| OidcError::Pkce("no PKCE verifier cookie found".into()))?;

        // Exchange code at token endpoint
        let token_response = exchange_code(config, &params.code, &verifier).await?;

        // Calculate expires_at
        let now = js_sys::Date::new_0().get_time() / 1000.0;
        let expires_at = now as i64 + token_response.expires_in as i64;

        // Write tokens to cookies
        cookie::browser::write_tokens(
            config,
            &token_response.access_token,
            &token_response.refresh_token,
            token_response.id_token.as_deref(),
            expires_at,
        );

        // Clear PKCE verifier and OAuth state cookies (consumed)
        cookie::browser::clear_pkce_verifier(config);
        cookie::browser::clear_oauth_state(config);

        // Decode claims and update auth state
        let user_info = extract_user_info_from_tokens(
            &token_response.access_token,
            token_response.id_token.as_deref(),
        );

        // Persist UserInfo in cookie for SSR fallback (handles opaque access tokens)
        cookie::browser::write_user_info(config, &user_info);

        // Update signals
        access_token_signal.set(Some(token_response.access_token));
        if config.store_id_token {
            id_token_signal.set(token_response.id_token);
        }
        state_signal.set(AuthState::Authenticated(user_info));

        // Clean URL (remove ?code=...&state=...)
        clean_callback_url(&window);

        Ok(())
    }

    /// Exchange authorization code for tokens at the token endpoint
    async fn exchange_code(
        config: &OidcConfig,
        code: &str,
        verifier: &str,
    ) -> Result<TokenResponse, OidcError> {
        let body = format!(
            "grant_type=authorization_code&client_id={}&code={}&redirect_uri={}&code_verifier={}",
            js_sys::encode_uri_component(&config.client_id)
                .as_string()
                .unwrap_or_default(),
            js_sys::encode_uri_component(code)
                .as_string()
                .unwrap_or_default(),
            js_sys::encode_uri_component(&config.redirect_uri)
                .as_string()
                .unwrap_or_default(),
            js_sys::encode_uri_component(verifier)
                .as_string()
                .unwrap_or_default(),
        );

        crate::refresh::fetch_token_endpoint(&config.token_endpoint(), &body).await
    }

    /// Extract user info from access_token (try JWT decode) or id_token as fallback
    fn extract_user_info_from_tokens(
        access_token: &str,
        id_token: Option<&str>,
    ) -> UserInfo {
        // Try access_token first (some IdPs put claims there)
        if let Ok(claims) = token::decode_claims(access_token) {
            if claims.sub.is_some() {
                return token::extract_user_info(&claims);
            }
        }

        // Fall back to id_token
        if let Some(id_token) = id_token {
            if let Ok(claims) = token::decode_claims(id_token) {
                return token::extract_user_info(&claims);
            }
        }

        // Last resort: empty user info
        UserInfo {
            subject: String::new(),
            email: None,
            name: None,
            preferred_username: None,
        }
    }

    /// Remove code/state query params from URL via history.replaceState
    fn clean_callback_url(window: &web_sys::Window) {
        if let Ok(href) = window.location().href() {
            if let Ok(parsed) = url::Url::parse(&href) {
                let clean: String = {
                    let mut clean_url = parsed.clone();
                    // Remove OAuth callback params, keep others
                    let remaining: Vec<(String, String)> = clean_url
                        .query_pairs()
                        .filter(|(k, _)| k != "code" && k != "state" && k != "session_state")
                        .map(|(k, v)| (k.to_string(), v.to_string()))
                        .collect();
                    if remaining.is_empty() {
                        clean_url.set_query(None);
                    } else {
                        clean_url.set_query(None);
                        for (k, v) in &remaining {
                            clean_url.query_pairs_mut().append_pair(k, v);
                        }
                    }
                    clean_url.to_string()
                };

                if let Ok(history) = window.history() {
                    let _ = history.replace_state_with_url(
                        &wasm_bindgen::JsValue::NULL,
                        "",
                        Some(&clean),
                    );
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_success() {
        let result =
            parse_callback("https://app.example.com/callback?code=abc123&state=xyz789").unwrap();
        assert_eq!(result.code, "abc123");
        assert_eq!(result.state, "xyz789");
    }

    #[test]
    fn parse_error_response() {
        let result = parse_callback(
            "https://app.example.com/callback?error=access_denied&error_description=User+denied",
        );
        match result {
            Err(OidcError::Callback { kind, description }) => {
                assert_eq!(kind, "access_denied");
                assert_eq!(description, "User denied");
            }
            other => panic!("expected Callback error, got {:?}", other),
        }
    }

    #[test]
    fn parse_missing_code() {
        let result = parse_callback("https://app.example.com/callback?state=xyz789");
        assert!(matches!(result, Err(OidcError::Callback { kind, .. }) if kind == "missing_code"));
    }

    #[test]
    fn parse_missing_state() {
        let result = parse_callback("https://app.example.com/callback?code=abc123");
        assert!(matches!(result, Err(OidcError::Callback { kind, .. }) if kind == "missing_state"));
    }

    #[test]
    fn parse_missing_both() {
        let result = parse_callback("https://app.example.com/callback");
        assert!(result.is_err());
    }

    #[test]
    fn parse_with_extra_params() {
        // Ensure additional query params don't interfere
        let result = parse_callback(
            "https://app.example.com/callback?code=abc&state=xyz&session_state=sess123",
        )
        .unwrap();
        assert_eq!(result.code, "abc");
        assert_eq!(result.state, "xyz");
    }

    #[test]
    fn parse_error_without_description() {
        let result =
            parse_callback("https://app.example.com/callback?error=server_error");
        match result {
            Err(OidcError::Callback { kind, description }) => {
                assert_eq!(kind, "server_error");
                assert!(description.is_empty());
            }
            other => panic!("expected Callback error, got {:?}", other),
        }
    }
}
