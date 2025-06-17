// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for the Token endpoint.

use chrono::{DateTime, Utc};
use http::header::ACCEPT;
use mas_http::RequestBuilderExt;
use mime::APPLICATION_JSON;
use oauth2_types::requests::{AccessTokenRequest, AccessTokenResponse};
use rand::Rng;
use url::Url;

use crate::{
    error::{ResponseExt, TokenRequestError},
    types::client_credentials::ClientCredentials,
};

/// Request an access token.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
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
    http_client: &reqwest::Client,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    request: AccessTokenRequest,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<AccessTokenResponse, TokenRequestError> {
    tracing::debug!(?request, "Requesting access token...");

    let token_request = http_client
        .post(token_endpoint.as_str())
        .header(ACCEPT, APPLICATION_JSON.as_ref());

    let token_response = client_credentials
        .authenticated_form(token_request, &request, now, rng)?
        .send_traced()
        .await?
        .error_from_oauth2_error_response()
        .await?
        .json()
        .await?;

    Ok(token_response)
}
