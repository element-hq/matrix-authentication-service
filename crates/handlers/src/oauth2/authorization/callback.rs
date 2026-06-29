// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use axum::response::{Html, IntoResponse, Redirect, Response};
use axum_extra::typed_header::TypedHeader;
use headers::{CacheControl, Pragma};
use mas_data_model::{AuthorizationGrant, Client};
use mas_i18n::DataLocale;
use mas_templates::{FormPostContext, RedirectContext, Templates};
use oauth2_types::requests::ResponseMode;
use serde::Serialize;
use thiserror::Error;
use url::Url;

#[derive(Debug, Clone)]
enum CallbackDestinationMode {
    Query {
        existing_params: HashMap<String, String>,
    },
    Fragment,
    FormPost,
}

#[derive(Debug, Clone)]
pub struct CallbackDestination {
    mode: CallbackDestinationMode,
    safe_redirect_uri: Url,
    state: Option<String>,
    client: Option<Client>,
}

#[derive(Debug, Error)]
pub enum IntoCallbackDestinationError {
    #[error("Redirect URI can't have a fragment")]
    RedirectUriFragmentNotAllowed,

    #[error("Existing query parameters are not valid")]
    RedirectUriInvalidQueryParams(#[from] serde_urlencoded::de::Error),

    #[error("Requested response_mode is not supported")]
    UnsupportedResponseMode,
}

#[derive(Debug, Error)]
pub enum CallbackDestinationError {
    #[error("Failed to render the callback destination template")]
    TemplateRender(#[from] mas_templates::TemplateError),

    #[error("Failed to serialize parameters query string")]
    ParamsSerialization(#[from] serde_urlencoded::ser::Error),
}

impl TryFrom<&AuthorizationGrant> for CallbackDestination {
    type Error = IntoCallbackDestinationError;

    fn try_from(value: &AuthorizationGrant) -> Result<Self, Self::Error> {
        Self::try_new(
            &value.response_mode,
            value.redirect_uri.clone(),
            value.state.clone(),
        )
    }
}

impl CallbackDestination {
    pub fn try_new(
        mode: &ResponseMode,
        mut redirect_uri: Url,
        state: Option<String>,
    ) -> Result<Self, IntoCallbackDestinationError> {
        if redirect_uri.fragment().is_some() {
            return Err(IntoCallbackDestinationError::RedirectUriFragmentNotAllowed);
        }

        let mode = match mode {
            ResponseMode::Query => {
                let existing_params = redirect_uri
                    .query()
                    .map(serde_urlencoded::from_str)
                    .transpose()?
                    .unwrap_or_default();

                // Remove the query from the URL
                redirect_uri.set_query(None);

                CallbackDestinationMode::Query { existing_params }
            }
            ResponseMode::Fragment => CallbackDestinationMode::Fragment,
            ResponseMode::FormPost => CallbackDestinationMode::FormPost,
            _ => return Err(IntoCallbackDestinationError::UnsupportedResponseMode),
        };

        Ok(Self {
            mode,
            safe_redirect_uri: redirect_uri,
            state,
            client: None,
        })
    }

    /// Set the client shown on the redirect interstitial.
    #[must_use]
    pub fn with_client(mut self, client: Client) -> Self {
        self.client = Some(client);
        self
    }

    /// Hand the parameters back to the client via the branded interstitial
    /// page (query/fragment modes) or the auto-submitting form (`form_post`).
    ///
    /// This is the interactive path: for query/fragment modes the link on the
    /// interstitial works better than a bare 302 for native-scheme redirect
    /// URIs.
    pub fn go<T: Serialize + Send + Sync>(
        self,
        templates: &Templates,
        locale: &DataLocale,
        params: T,
    ) -> Result<Response, CallbackDestinationError> {
        self.respond(templates, locale, params, true)
    }

    /// Hand the parameters back to the client with the original immediate 303
    /// redirect (query/fragment modes), bypassing the interstitial.
    ///
    /// Used for `prompt=none`: silent token renewal runs `/authorize` in a
    /// hidden iframe, but the router sets `X-Frame-Options: DENY`, so a framed
    /// browser refuses to render the HTML interstitial and the renewal breaks.
    /// The redirect must stay immediate. `form_post` is always an HTML page, so
    /// it is unaffected.
    pub fn go_immediate<T: Serialize + Send + Sync>(
        self,
        templates: &Templates,
        locale: &DataLocale,
        params: T,
    ) -> Result<Response, CallbackDestinationError> {
        self.respond(templates, locale, params, false)
    }

    fn respond<T: Serialize + Send + Sync>(
        self,
        templates: &Templates,
        locale: &DataLocale,
        params: T,
        interstitial: bool,
    ) -> Result<Response, CallbackDestinationError> {
        #[derive(Serialize)]
        struct AllParams<'s, T> {
            #[serde(flatten, skip_serializing_if = "Option::is_none")]
            existing: Option<&'s HashMap<String, String>>,

            #[serde(skip_serializing_if = "Option::is_none")]
            state: Option<String>,

            #[serde(flatten)]
            params: T,
        }

        let mut redirect_uri = self.safe_redirect_uri;
        let state = self.state;
        let client = self.client;

        match self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(&existing_params),
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_query(Some(&new_qs));
                if redirect_uri.fragment().is_none() {
                    // Ensure that the Location header (redirect target)
                    // includes a URL fragment (#) of some sort.
                    //
                    // Any fragment present in the Location header URL that the server redirects to
                    // (e.g., via a 303 response) will overwrite the client’s existing fragment,
                    // otherwise the fragment will be preserved across the
                    // redirect (and may contain sensitive information,
                    // or confuse the downstream client).
                    //
                    // If the redirect_uri already contains a fragment, that fragment will do the
                    // same job, so we leave it alone — we don't want to mangle the client's
                    // configured redirect URL by replacing it with a blank fragment.
                    // Otherwise, set a fragment of empty string (effectively appending `#` to the
                    // URL).
                    //
                    // Browser behaviour is documented as part of the 'location URL' algorithm at
                    // https://fetch.spec.whatwg.org/commit-snapshots/809904366f33a673a9489b81155ee9e3edd29c12#concept-response-location-url
                    redirect_uri.set_fragment(Some(""));
                }

                if interstitial {
                    render_redirect(templates, locale, redirect_uri, client)
                } else {
                    Ok(Redirect::to(redirect_uri.as_str()).into_response())
                }
            }

            CallbackDestinationMode::Fragment => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_fragment(Some(&new_qs));

                if interstitial {
                    render_redirect(templates, locale, redirect_uri, client)
                } else {
                    Ok(Redirect::to(redirect_uri.as_str()).into_response())
                }
            }

            CallbackDestinationMode::FormPost => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };
                let mut ctx = FormPostContext::new_for_url(redirect_uri, merged);
                if let Some(client) = client {
                    ctx = ctx.with_client(client);
                }
                let rendered = templates.render_form_post(&ctx.with_language(locale))?;
                // The body embeds the authorization code / tokens; keep it out of caches
                // (RFC 6749 §5.1).
                Ok((
                    TypedHeader(CacheControl::new().with_no_store()),
                    TypedHeader(Pragma::no_cache()),
                    Html(rendered),
                )
                    .into_response())
            }
        }
    }
}

/// Render the `redirect.html` interstitial (query and fragment response modes).
fn render_redirect(
    templates: &Templates,
    locale: &DataLocale,
    redirect_uri: Url,
    client: Option<Client>,
) -> Result<Response, CallbackDestinationError> {
    let mut ctx = RedirectContext::new(redirect_uri);
    if let Some(client) = client {
        ctx = ctx.with_client(client);
    }
    let rendered = templates.render_redirect(&ctx.with_language(locale))?;
    // The body embeds the authorization code / tokens; keep it out of caches
    // (RFC 6749 §5.1).
    Ok((
        TypedHeader(CacheControl::new().with_no_store()),
        TypedHeader(Pragma::no_cache()),
        Html(rendered),
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyper::{
        Request, StatusCode,
        header::{CACHE_CONTROL, LOCATION},
    };
    use mas_axum_utils::SessionInfoExt;
    use mas_data_model::AuthorizationCode;
    use mas_router::{Route, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::ResponseMode,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    /// Register a bare `authorization_code` client and return its client ID.
    async fn register_client(state: &TestState) -> String {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let registration: ClientRegistrationResponse = response.json();
        registration.client_id
    }

    /// An interactive (no `prompt=none`) query-mode error renders the redirect
    /// interstitial that bounces to the callback URL. Checks it carries that
    /// URL, keeps the empty-fragment (`#`) guard, and is marked `no-store`.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_query_mode_interstitial_redirect(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = register_client(&state).await;

        // The `request` parameter is unsupported, so this fails interactively with
        // `request_not_supported` through the CallbackDestinationMode::Query path.
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("scope", "openid")
            .append_pair("state", "test-state-value")
            .append_pair("response_mode", "query")
            .append_pair("request", "unsupported")
            .finish();

        let response = state
            .request(Request::get(format!("https://example.com/authorize?{query}")).empty())
            .await;

        response.assert_status(StatusCode::OK);
        // Token-bearing HTML must not be cached (RFC 6749 §5.1).
        response.assert_header_value(CACHE_CONTROL, "no-store");

        let body = response.body();
        // The page bounces to the callback URL carrying the error...
        assert!(body.contains("window.location.replace("));
        assert!(body.contains("error=request_not_supported"));
        // ...and the embedded URL keeps the trailing empty fragment guard: the
        // error_description ends with "parameter." immediately followed by `#`.
        assert!(body.contains("parameter.#"));
    }

    /// An interactive fragment-mode error renders the interstitial with the
    /// parameters in the URL fragment.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_fragment_mode_interstitial_redirect(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = register_client(&state).await;

        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("scope", "openid")
            .append_pair("state", "test-state-value")
            .append_pair("response_mode", "fragment")
            .append_pair("request", "unsupported")
            .finish();

        let response = state
            .request(Request::get(format!("https://example.com/authorize?{query}")).empty())
            .await;

        response.assert_status(StatusCode::OK);
        response.assert_header_value(CACHE_CONTROL, "no-store");

        let body = response.body();
        assert!(body.contains("window.location.replace("));
        // Parameters land in the fragment (after the `#`), not the query.
        assert!(body.contains("callback#"));
        assert!(body.contains("error=request_not_supported"));
    }

    /// `prompt=none` bypasses the interstitial and keeps the original immediate
    /// 303 redirect, so silent token renewal in a hidden iframe still works
    /// (the router sets `X-Frame-Options: DENY`, which would block the framed
    /// interstitial).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_prompt_none_immediate_redirect(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = register_client(&state).await;

        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &client_id)
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair("scope", "openid")
            .append_pair("state", "test-state-value")
            .append_pair("response_mode", "query")
            .append_pair("prompt", "none")
            .finish();

        let response = state
            .request(Request::get(format!("https://example.com/authorize?{query}")).empty())
            .await;

        // No session + prompt=none => login_required, delivered as an immediate
        // redirect rather than the HTML interstitial.
        response.assert_status(StatusCode::SEE_OTHER);
        let location = response
            .headers()
            .get(LOCATION)
            .expect("missing Location header")
            .to_str()
            .unwrap();
        assert!(location.contains("error=login_required"), "{location}");
    }

    /// The consent POST success path is always interactive and renders the
    /// interstitial carrying the authorization code.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_post_success_interstitial(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();
        let client_id = register_client(&state).await;

        // Provision a user, session and a pending grant directly via the repository.
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .find_by_client_id(&client_id)
            .await
            .unwrap()
            .unwrap();
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://example.com/callback".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "thisisaverysecurecode".to_owned(),
                    pkce: None,
                }),
                Some("test-state-value".to_owned()),
                None,
                ResponseMode::Query,
                false,
                None,
                None,
                BTreeMap::new(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Authenticate the browser session via its cookie.
        cookies.import(state.cookie_jar().set_session(&browser_session));

        let consent_path = mas_router::Consent(grant.id).path().into_owned();

        // Render the consent page to get a CSRF token.
        let request = cookies.with_cookies(Request::get(&consent_path).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
            .to_owned();

        // Submit the consent form.
        let request = cookies.with_cookies(
            Request::post(&consent_path).form(serde_json::json!({ "csrf": csrf_token })),
        );
        let response = state.request(request).await;

        response.assert_status(StatusCode::OK);
        response.assert_header_value(CACHE_CONTROL, "no-store");
        let body = response.body();
        assert!(body.contains("window.location.replace("));
        assert!(body.contains("code=thisisaverysecurecode"));
        // The interstitial heading ("Opening …").
        assert!(body.contains("Opening"));
    }
}
