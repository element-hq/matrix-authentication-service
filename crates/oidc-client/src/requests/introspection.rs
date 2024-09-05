// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for [Token Introspection].
//!
//! [Token Introspection]: https://www.rfc-editor.org/rfc/rfc7662

use chrono::{DateTime, Utc};
use headers::{Authorization, HeaderMapExt};
use http::Request;
use mas_http::{CatchHttpCodesLayer, FormUrlencodedRequestLayer, JsonResponseLayer};
use mas_iana::oauth::OAuthTokenTypeHint;
use oauth2_types::requests::{IntrospectionRequest, IntrospectionResponse};
use rand::Rng;
use serde::Serialize;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::IntrospectionError,
    http_service::HttpService,
    types::client_credentials::{ClientCredentials, RequestWithClientCredentials},
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// The method used to authenticate at the introspection endpoint.
pub enum IntrospectionAuthentication<'a> {
    /// Using client authentication.
    Credentials(ClientCredentials),

    /// Using a bearer token.
    BearerToken(&'a str),
}

impl<'a> IntrospectionAuthentication<'a> {
    /// Constructs an `IntrospectionAuthentication` from the given client
    /// credentials.
    #[must_use]
    pub fn with_client_credentials(credentials: ClientCredentials) -> Self {
        Self::Credentials(credentials)
    }

    /// Constructs an `IntrospectionAuthentication` from the given bearer token.
    #[must_use]
    pub fn with_bearer_token(token: &'a str) -> Self {
        Self::BearerToken(token)
    }

    fn apply_to_request<T: Serialize>(
        self,
        request: Request<T>,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Result<Request<RequestWithClientCredentials<T>>, IntrospectionError> {
        let res = match self {
            IntrospectionAuthentication::Credentials(client_credentials) => {
                client_credentials.apply_to_request(request, now, rng)?
            }
            IntrospectionAuthentication::BearerToken(access_token) => {
                let (mut parts, body) = request.into_parts();

                parts
                    .headers
                    .typed_insert(Authorization::bearer(access_token)?);

                let body = RequestWithClientCredentials {
                    body,
                    credentials: None,
                };

                http::Request::from_parts(parts, body)
            }
        };

        Ok(res)
    }
}

impl<'a> From<ClientCredentials> for IntrospectionAuthentication<'a> {
    fn from(credentials: ClientCredentials) -> Self {
        Self::with_client_credentials(credentials)
    }
}

/// Obtain information about a token.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `authentication` - The method used to authenticate the request.
///
/// * `revocation_endpoint` - The URL of the issuer's Revocation endpoint.
///
/// * `token` - The token to introspect.
///
/// * `token_type_hint` - Hint about the type of the token.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(introspection_endpoint))]
pub async fn introspect_token(
    http_service: &HttpService,
    authentication: IntrospectionAuthentication<'_>,
    introspection_endpoint: &Url,
    token: String,
    token_type_hint: Option<OAuthTokenTypeHint>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<IntrospectionResponse, IntrospectionError> {
    tracing::debug!("Introspecting token…");

    let introspection_request = IntrospectionRequest {
        token,
        token_type_hint,
    };
    let introspection_request =
        http::Request::post(introspection_endpoint.as_str()).body(introspection_request)?;

    let introspection_request = authentication.apply_to_request(introspection_request, now, rng)?;

    let service = (
        FormUrlencodedRequestLayer::default(),
        JsonResponseLayer::<IntrospectionResponse>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let introspection_response = service
        .ready_oneshot()
        .await?
        .call(introspection_request)
        .await?
        .into_body();

    Ok(introspection_response)
}
