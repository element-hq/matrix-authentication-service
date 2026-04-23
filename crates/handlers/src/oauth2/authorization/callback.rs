// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

use std::collections::HashMap;

use axum::response::{Html, IntoResponse, Redirect, Response};
use mas_data_model::AuthorizationGrant;
use mas_i18n::DataLocale;
use mas_templates::{FormPostContext, Templates};
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
        })
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

        match self.mode {
            CallbackDestinationMode::Query { existing_params } => {
                let merged = AllParams {
                    existing: Some(&existing_params),
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_query(Some(&new_qs));

                Ok(Redirect::to(redirect_uri.as_str()).into_response())
            }

            CallbackDestinationMode::Fragment => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };

                let new_qs = serde_urlencoded::to_string(merged)?;

                redirect_uri.set_fragment(Some(&new_qs));

                Ok(Redirect::to(redirect_uri.as_str()).into_response())
            }

            CallbackDestinationMode::FormPost => {
                let merged = AllParams {
                    existing: None,
                    state,
                    params,
                };
                let ctx = FormPostContext::new_for_url(redirect_uri, merged).with_language(locale);
                let rendered = templates.render_form_post(&ctx)?;
                Ok(Html(rendered).into_response())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_router::SimpleRoute;
    use oauth2_types::registration::ClientRegistrationResponse;
    use sqlx::PgPool;
    use url::Url;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// Helper to build a GET request to the authorization endpoint with query
    /// parameters.
    fn authorize_get_request(
        client_id: &str,
        redirect_uri: &str,
        state: &str,
    ) -> hyper::Request<String> {
        let mut url = Url::parse("https://example.com/authorize").unwrap();
        url.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", "openid")
            .append_pair("state", state)
            .append_pair("response_mode", "query")
            .append_pair("prompt", "none");

        let path = url.path();
        let query = url.query().unwrap_or("");
        let uri = format!("{path}?{query}");
        Request::get(uri).empty()
    }

    /// Test that checks the content of the `Location` header
    /// in response to an authorization request.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_query_mode_location_header(pool: PgPool) {
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
        let request = authorize_get_request(
            &client_id,
            "https://example.com/callback",
            "test-state-value",
        );
        let response = state.request(request).await;

        response.assert_status(StatusCode::SEE_OTHER);

        // Check the form of the Location redirect
        response.assert_header_value(
            hyper::header::LOCATION,
            "https://example.com/callback?state=test-state-value&error=login_required&error_description=The+Authorization+Server+requires+End-User+authentication.",
        );
    }
}
