// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for the Token endpoint.

use chrono::{DateTime, Utc};
use mas_http::{CatchHttpCodesLayer, FormUrlencodedRequestLayer, JsonResponseLayer};
use oauth2_types::requests::{AccessTokenRequest, AccessTokenResponse};
use rand::Rng;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::TokenRequestError,
    http_service::HttpService,
    types::client_credentials::ClientCredentials,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Request an access token.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `token_endpoint` - The URL of the issuer's Token endpoint.
///
/// * `request` - The request to make at the Token endpoint.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(token_endpoint, request))]
pub async fn request_access_token(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    request: AccessTokenRequest,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<AccessTokenResponse, TokenRequestError> {
    tracing::debug!(?request, "Requesting access token...");

    let token_request = http::Request::post(token_endpoint.as_str()).body(request)?;

    let token_request = client_credentials.apply_to_request(token_request, now, rng)?;

    let service = (
        FormUrlencodedRequestLayer::default(),
        JsonResponseLayer::<AccessTokenResponse>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let res = service.ready_oneshot().await?.call(token_request).await?;

    let token_response = res.into_body();

    Ok(token_response)
}
