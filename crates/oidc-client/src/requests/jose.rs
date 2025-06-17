// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests and method related to JSON Object Signing and Encryption.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use mas_http::RequestBuilderExt;
use mas_iana::jose::JsonWebSignatureAlg;
use mas_jose::{
    claims::{self, TimeOptions},
    jwk::PublicJsonWebKeySet,
    jwt::Jwt,
};
use serde_json::Value;
use url::Url;

use crate::{
    error::{IdTokenError, JwksError, JwtVerificationError},
    types::IdToken,
};

/// Fetch a JWKS at the given URL.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `jwks_uri` - The URL where the JWKS can be retrieved.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
#[tracing::instrument(skip_all, fields(jwks_uri))]
pub async fn fetch_jwks(
    client: &reqwest::Client,
    jwks_uri: &Url,
) -> Result<PublicJsonWebKeySet, JwksError> {
    tracing::debug!("Fetching JWKS...");

    let response: PublicJsonWebKeySet = client
        .get(jwks_uri.as_str())
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;

    Ok(response)
}

/// The data required to verify a JWT.
#[derive(Clone, Copy)]
pub struct JwtVerificationData<'a> {
    /// The URL of the issuer that generated the ID Token.
    pub issuer: Option<&'a str>,

    /// The issuer's JWKS.
    pub jwks: &'a PublicJsonWebKeySet,

    /// The ID obtained when registering the client.
    pub client_id: &'a String,

    /// The JWA that should have been used to sign the JWT, as set during
    /// client registration.
    pub signing_algorithm: &'a JsonWebSignatureAlg,
}

/// Decode and verify a signed JWT.
///
/// The following checks are performed:
///
/// * The signature is verified with the given JWKS.
///
/// * The `iss` claim must be present and match the issuer, if present
///
/// * The `aud` claim must be present and match the client ID.
///
/// * The `alg` in the header must match the signing algorithm.
///
/// # Arguments
///
/// * `jwt` - The serialized JWT to decode and verify.
///
/// * `jwks` - The JWKS that should contain the public key to verify the JWT's
///   signature.
///
/// * `issuer` - The issuer of the JWT.
///
/// * `audience` - The audience that the JWT is intended for.
///
/// * `signing_algorithm` - The JWA that should have been used to sign the JWT.
///
/// # Errors
///
/// Returns an error if the data is invalid or verification fails.
pub fn verify_signed_jwt<'a>(
    jwt: &'a str,
    verification_data: JwtVerificationData<'_>,
) -> Result<Jwt<'a, HashMap<String, Value>>, JwtVerificationError> {
    tracing::debug!("Validating JWT...");

    let JwtVerificationData {
        issuer,
        jwks,
        client_id,
        signing_algorithm,
    } = verification_data;

    let jwt: Jwt<HashMap<String, Value>> = jwt.try_into()?;

    jwt.verify_with_jwks(jwks)?;

    let (header, mut claims) = jwt.clone().into_parts();

    if let Some(issuer) = issuer {
        // Must have the proper issuer.
        claims::ISS.extract_required_with_options(&mut claims, issuer)?;
    }

    // Must have the proper audience.
    claims::AUD.extract_required_with_options(&mut claims, client_id)?;

    // Must use the proper algorithm.
    if header.alg() != signing_algorithm {
        return Err(JwtVerificationError::WrongSignatureAlg);
    }

    Ok(jwt)
}

/// Decode and verify an ID Token.
///
/// Besides the checks of [`verify_signed_jwt()`], the following checks are
/// performed:
///
/// * The `exp` claim must be present and the token must not have expired.
///
/// * The `iat` claim must be present must be in the past.
///
/// * The `sub` claim must be present.
///
/// If an authorization ID token is provided, these extra checks are performed:
///
/// * The `sub` claims must match.
///
/// * The `auth_time` claims must match.
///
/// # Arguments
///
/// * `id_token` - The serialized ID Token to decode and verify.
///
/// * `verification_data` - The data necessary to verify the ID Token.
///
/// * `auth_id_token` - If the ID Token is not verified during an authorization
///   request, the ID token that was returned from the latest authorization
///   request.
///
/// # Errors
///
/// Returns an error if the data is invalid or verification fails.
pub fn verify_id_token<'a>(
    id_token: &'a str,
    verification_data: JwtVerificationData<'_>,
    auth_id_token: Option<&IdToken<'_>>,
    now: DateTime<Utc>,
) -> Result<IdToken<'a>, IdTokenError> {
    let id_token = verify_signed_jwt(id_token, verification_data)?;

    let mut claims = id_token.payload().clone();

    let time_options = TimeOptions::new(now);
    // Must not have expired.
    claims::EXP.extract_required_with_options(&mut claims, &time_options)?;

    // `iat` claim must be present.
    claims::IAT.extract_required_with_options(&mut claims, time_options)?;

    // Subject identifier must be present.
    let sub = claims::SUB.extract_required(&mut claims)?;

    // More checks if there is a previous ID token.
    if let Some(auth_id_token) = auth_id_token {
        let mut auth_claims = auth_id_token.payload().clone();

        // Subject identifier must always be the same.
        let auth_sub = claims::SUB.extract_required(&mut auth_claims)?;
        if sub != auth_sub {
            return Err(IdTokenError::WrongSubjectIdentifier);
        }

        // If the authentication time is present, it must be unchanged.
        if let Some(auth_time) = claims::AUTH_TIME.extract_optional(&mut claims)? {
            let prev_auth_time = claims::AUTH_TIME.extract_required(&mut auth_claims)?;

            if prev_auth_time != auth_time {
                return Err(IdTokenError::WrongAuthTime);
            }
        }
    }

    Ok(id_token)
}
