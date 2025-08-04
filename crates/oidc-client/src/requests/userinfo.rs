// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for obtaining [Claims] about an end-user.
//!
//! [Claims]: https://openid.net/specs/openid-connect-core-1_0.html#Claims

use std::collections::HashMap;

use headers::{ContentType, HeaderMapExt, HeaderValue};
use http::header::ACCEPT;
use mas_http::RequestBuilderExt;
use mime::Mime;
use serde_json::Value;
use url::Url;

use super::jose::JwtVerificationData;
use crate::{
    error::{IdTokenError, ResponseExt, UserInfoError},
    requests::jose::verify_signed_jwt,
};

/// Obtain information about an authenticated end-user.
///
/// Returns a map of claims with their value, that should be extracted with
/// one of the [`Claim`] methods.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `userinfo_endpoint` - The URL of the issuer's User Info endpoint.
///
/// * `access_token` - The access token of the end-user.
///
/// * `jwt_verification_data` - The data required to verify the response if a
///   signed response was requested during client registration.
///
///   The signing algorithm corresponds to the `userinfo_signed_response_alg`
///   field in the client metadata.
///
/// * `auth_id_token` - The ID token that was returned from the latest
///   authorization request.
///
/// # Errors
///
/// Returns an error if the request fails, the response is invalid or the
/// validation of the signed response fails.
///
/// [`Claim`]: mas_jose::claims::Claim
#[tracing::instrument(skip_all, fields(userinfo_endpoint))]
pub async fn fetch_userinfo(
    http_client: &reqwest::Client,
    userinfo_endpoint: &Url,
    access_token: &str,
    jwt_verification_data: Option<JwtVerificationData<'_>>,
) -> Result<HashMap<String, Value>, UserInfoError> {
    tracing::debug!("Obtaining user info…");

    let expected_content_type = if jwt_verification_data.is_some() {
        "application/jwt"
    } else {
        mime::APPLICATION_JSON.as_ref()
    };

    let userinfo_request = http_client
        .get(userinfo_endpoint.as_str())
        .bearer_auth(access_token)
        .header(ACCEPT, HeaderValue::from_static(expected_content_type));

    let userinfo_response = userinfo_request
        .send_traced()
        .await?
        .error_from_oauth2_error_response()
        .await?;

    let content_type: Mime = userinfo_response
        .headers()
        .typed_try_get::<ContentType>()
        .map_err(|_| UserInfoError::InvalidResponseContentTypeValue)?
        .ok_or(UserInfoError::MissingResponseContentType)?
        .into();

    if content_type.essence_str() != expected_content_type {
        return Err(UserInfoError::UnexpectedResponseContentType {
            expected: expected_content_type.to_owned(),
            got: content_type.to_string(),
        });
    }

    let claims = if let Some(verification_data) = jwt_verification_data {
        let response_body = userinfo_response.text().await?;
        verify_signed_jwt(&response_body, verification_data)
            .map_err(IdTokenError::from)?
            .into_parts()
            .1
    } else {
        userinfo_response.json().await?
    };

    Ok(claims)
}
