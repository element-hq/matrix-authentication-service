// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for using [Refresh Tokens].
//!
//! [Refresh Tokens]: https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens

use chrono::{DateTime, Utc};
use mas_jose::claims::{self, TokenHash};
use oauth2_types::{
    requests::{AccessTokenRequest, AccessTokenResponse, RefreshTokenGrant},
    scope::Scope,
};
use rand::Rng;
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{IdTokenError, TokenRefreshError},
    requests::{jose::verify_id_token, token::request_access_token},
    types::{IdToken, client_credentials::ClientCredentials},
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
/// * `refresh_token` - The token used to refresh the access token returned at
///   the Token endpoint.
///
/// * `scope` - The scope of the access token. The requested scope must not
///   include any scope not originally granted to the access token, and if
///   omitted is treated as equal to the scope originally granted by the issuer.
///
/// * `id_token_verification_data` - The data required to verify the ID Token in
///   the response.
///
///   The signing algorithm corresponds to the `id_token_signed_response_alg`
/// field in the client metadata.
///
///   If it is not provided, the ID Token won't be verified.
///
/// * `auth_id_token` - If an ID Token is expected in the response, the ID token
///   that was returned from the latest authorization request.
///
/// * `now` - The current time.
///
/// * `rng` - A random number generator.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// verification of the ID Token fails.
#[allow(clippy::too_many_arguments)]
#[tracing::instrument(skip_all, fields(token_endpoint))]
pub async fn refresh_access_token(
    http_client: &reqwest::Client,
    client_credentials: ClientCredentials,
    token_endpoint: &Url,
    refresh_token: String,
    scope: Option<Scope>,
    id_token_verification_data: Option<JwtVerificationData<'_>>,
    auth_id_token: Option<&IdToken<'_>>,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<(AccessTokenResponse, Option<IdToken<'static>>), TokenRefreshError> {
    tracing::debug!("Refreshing access token…");

    let token_response = request_access_token(
        http_client,
        client_credentials,
        token_endpoint,
        AccessTokenRequest::RefreshToken(RefreshTokenGrant {
            refresh_token,
            scope,
        }),
        now,
        rng,
    )
    .await?;

    let id_token = if let Some((verification_data, id_token)) =
        id_token_verification_data.zip(token_response.id_token.as_ref())
    {
        let auth_id_token = auth_id_token.ok_or(IdTokenError::MissingAuthIdToken)?;
        let signing_alg = verification_data.signing_algorithm;

        let id_token = verify_id_token(id_token, verification_data, Some(auth_id_token), now)?;

        let mut claims = id_token.payload().clone();

        // Access token hash must match.
        claims::AT_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(signing_alg, &token_response.access_token),
            )
            .map_err(IdTokenError::from)?;

        Some(id_token.into_owned())
    } else {
        None
    };

    Ok((token_response, id_token))
}
