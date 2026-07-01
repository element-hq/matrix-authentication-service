// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use axum::response::{Html, IntoResponse, Response};
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
    #[error("Failed to render the form_post template")]
    FormPostRender(#[from] mas_templates::TemplateError),

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

    pub fn go<T: Serialize + Send + Sync>(
        self,
        templates: &Templates,
        locale: &DataLocale,
        params: T,
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

                Ok(render_redirect(templates, locale, redirect_uri, client)?)
            }

            CallbackDestinationMode::Fragment => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_fragment(Some(&new_qs));

                Ok(render_redirect(templates, locale, redirect_uri, client)?)
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
                Ok(Html(rendered).into_response())
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
    Ok(Html(rendered).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_router::SimpleRoute;
    use oauth2_types::registration::ClientRegistrationResponse;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// The query response mode renders the interstitial page that bounces to
    /// the callback URL. Checks it carries that URL and keeps the
    /// empty-fragment (`#`) guard against fragment preservation.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_query_mode_interstitial_redirect(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Register an OAuth2 client
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
        let client_id = registration.client_id;

        // Send an authorization request with response_mode=query and prompt=none.
        // prompt=none always fails with login_required since there is no session,
        // which exercises the CallbackDestinationMode::Query path.

        // Build /authorize query parameters
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

        // The query response mode now renders the redirect interstitial page
        response.assert_status(StatusCode::OK);

        let body = response.body();
        // The page bounces to the callback URL carrying the error...
        assert!(body.contains("window.location.replace("));
        assert!(body.contains("error=login_required"));
        // ...and the embedded URL keeps the trailing empty fragment guard.
        assert!(body.contains("authentication.#"));
    }
}
