// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for [Token Revocation].
//!
//! [Token Revocation]: https://www.rfc-editor.org/rfc/rfc7009.html

use chrono::{DateTime, Utc};
use mas_http::{CatchHttpCodesLayer, FormUrlencodedRequestLayer};
use mas_iana::oauth::OAuthTokenTypeHint;
use oauth2_types::requests::IntrospectionRequest;
use rand::Rng;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::TokenRevokeError,
    http_service::HttpService,
    types::client_credentials::ClientCredentials,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Revoke a token.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `client_credentials` - The credentials obtained when registering the
///   client.
///
/// * `revocation_endpoint` - The URL of the issuer's Revocation endpoint.
///
/// * `token` - The token to revoke.
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
#[tracing::instrument(skip_all, fields(revocation_endpoint))]
pub async fn revoke_token(
    http_service: &HttpService,
    client_credentials: ClientCredentials,
    revocation_endpoint: &Url,
    token: String,
    token_type_hint: Option<OAuthTokenTypeHint>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(), TokenRevokeError> {
    tracing::debug!("Revoking token…");

    let request = IntrospectionRequest {
        token,
        token_type_hint,
    };

    let revocation_request = http::Request::post(revocation_endpoint.as_str()).body(request)?;

    let revocation_request = client_credentials.apply_to_request(revocation_request, now, rng)?;

    let service = (
        FormUrlencodedRequestLayer::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    service
        .ready_oneshot()
        .await?
        .call(revocation_request)
        .await?;

    Ok(())
}
