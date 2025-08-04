// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for the [Client Credentials flow].
//!
//! [Client Credentials flow]: https://www.rfc-editor.org/rfc/rfc6749#section-4.4

use chrono::{DateTime, Utc};
use oauth2_types::{
    requests::{AccessTokenRequest, AccessTokenResponse, ClientCredentialsGrant},
    scope::Scope,
};
use rand::Rng;
use url::Url;

use crate::{
    error::TokenRequestError, requests::token::request_access_token,
    types::client_credentials::ClientCredentials,
};

/// Exchange an authorization code for an access token.
///
/// This should be used as the first step for logging in, and to request a
/// token with a new scope.
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
/// * `scope` - The scope to authorize.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(token_endpoint))]
pub async fn access_token_with_client_credentials(
    http_client: &reqwest::Client,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    scope: Option<Scope>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<AccessTokenResponse, TokenRequestError> {
    tracing::debug!("Requesting access token with client credentials...");

    request_access_token(
        http_client,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::ClientCredentials(ClientCredentialsGrant { scope }),
        now,
        rng,
    )
    .await
}
