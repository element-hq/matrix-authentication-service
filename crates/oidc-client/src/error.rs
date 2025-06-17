// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! The error types used in this crate.

use async_trait::async_trait;
use mas_jose::{
    claims::ClaimError,
    jwa::InvalidAlgorithm,
    jwt::{JwtDecodeError, JwtSignatureError, NoKeyWorked},
};
use oauth2_types::{oidc::ProviderMetadataVerificationError, pkce::CodeChallengeError};
use serde::Deserialize;
use thiserror::Error;

/// All possible errors when using this crate.
#[derive(Debug, Error)]
#[error(transparent)]
pub enum Error {
    /// An error occurred fetching provider metadata.
    Discovery(#[from] DiscoveryError),

    /// An error occurred fetching the provider JWKS.
    Jwks(#[from] JwksError),

    /// An error occurred building the authorization URL.
    Authorization(#[from] AuthorizationError),

    /// An error occurred exchanging an authorization code for an access token.
    TokenAuthorizationCode(#[from] TokenAuthorizationCodeError),

    /// An error occurred requesting an access token with client credentials.
    TokenClientCredentials(#[from] TokenRequestError),

    /// An error occurred refreshing an access token.
    TokenRefresh(#[from] TokenRefreshError),

    /// An error occurred requesting user info.
    UserInfo(#[from] UserInfoError),
}

/// All possible errors when fetching provider metadata.
#[derive(Debug, Error)]
#[error("Fetching provider metadata failed")]
pub enum DiscoveryError {
    /// An error occurred building the request's URL.
    IntoUrl(#[from] url::ParseError),

    /// The server returned an HTTP error status code.
    Http(#[from] reqwest::Error),

    /// An error occurred validating the metadata.
    Validation(#[from] ProviderMetadataVerificationError),

    /// The provider doesn't have an issuer set, which is required if discovery
    /// is enabled.
    #[error("Provider doesn't have an issuer set")]
    MissingIssuer,

    /// Discovery is disabled for this provider.
    #[error("Discovery is disabled for this provider")]
    Disabled,
}

/// All possible errors when authorizing the client.
#[derive(Debug, Error)]
#[error("Building the authorization URL failed")]
pub enum AuthorizationError {
    /// An error occurred constructing the PKCE code challenge.
    Pkce(#[from] CodeChallengeError),

    /// An error occurred serializing the request.
    UrlEncoded(#[from] serde_urlencoded::ser::Error),
}

/// All possible errors when requesting an access token.
#[derive(Debug, Error)]
#[error("Request to the token endpoint failed")]
pub enum TokenRequestError {
    /// The HTTP client returned an error.
    Http(#[from] reqwest::Error),

    /// The server returned an error
    OAuth2(#[from] OAuth2Error),

    /// Error while injecting the client credentials into the request.
    Credentials(#[from] CredentialsError),
}

/// All possible errors when exchanging a code for an access token.
#[derive(Debug, Error)]
pub enum TokenAuthorizationCodeError {
    /// An error occurred requesting the access token.
    #[error(transparent)]
    Token(#[from] TokenRequestError),

    /// An error occurred validating the ID Token.
    #[error("Verifying the 'id_token' returned by the provider failed")]
    IdToken(#[from] IdTokenError),
}

/// All possible errors when refreshing an access token.
#[derive(Debug, Error)]
pub enum TokenRefreshError {
    /// An error occurred requesting the access token.
    #[error(transparent)]
    Token(#[from] TokenRequestError),

    /// An error occurred validating the ID Token.
    #[error("Verifying the 'id_token' returned by the provider failed")]
    IdToken(#[from] IdTokenError),
}

/// All possible errors when requesting user info.
#[derive(Debug, Error)]
pub enum UserInfoError {
    /// The content-type header is missing from the response.
    #[error("missing response content-type")]
    MissingResponseContentType,

    /// The content-type is not valid.
    #[error("invalid response content-type")]
    InvalidResponseContentTypeValue,

    /// The content-type is not the one that was expected.
    #[error("unexpected response content-type {got:?}, expected {expected:?}")]
    UnexpectedResponseContentType {
        /// The expected content-type.
        expected: String,
        /// The returned content-type.
        got: String,
    },

    /// An error occurred verifying the Id Token.
    #[error("Verifying the 'id_token' returned by the provider failed")]
    IdToken(#[from] IdTokenError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// The server returned an error
    #[error(transparent)]
    OAuth2(#[from] OAuth2Error),
}

/// All possible errors when requesting a JWKS.
#[derive(Debug, Error)]
#[error("Failed to fetch JWKS")]
pub enum JwksError {
    /// An error occurred sending the request.
    Http(#[from] reqwest::Error),
}

/// All possible errors when verifying a JWT.
#[derive(Debug, Error)]
pub enum JwtVerificationError {
    /// An error occured decoding the JWT.
    #[error(transparent)]
    JwtDecode(#[from] JwtDecodeError),

    /// No key worked for verifying the JWT's signature.
    #[error(transparent)]
    JwtSignature(#[from] NoKeyWorked),

    /// An error occurred extracting a claim.
    #[error(transparent)]
    Claim(#[from] ClaimError),

    /// The algorithm used for signing the JWT is not the one that was
    /// requested.
    #[error("wrong signature alg")]
    WrongSignatureAlg,
}

/// All possible errors when verifying an ID token.
#[derive(Debug, Error)]
pub enum IdTokenError {
    /// No ID Token was found in the response although one was expected.
    #[error("ID token is missing")]
    MissingIdToken,

    /// The ID Token from the latest Authorization was not provided although
    /// this request expects to be verified against one.
    #[error("Authorization ID token is missing")]
    MissingAuthIdToken,

    #[error(transparent)]
    /// An error occurred validating the ID Token's signature and basic claims.
    Jwt(#[from] JwtVerificationError),

    #[error(transparent)]
    /// An error occurred extracting a claim.
    Claim(#[from] ClaimError),

    /// The subject identifier returned by the issuer is not the same as the one
    /// we got before.
    #[error("wrong subject identifier")]
    WrongSubjectIdentifier,

    /// The authentication time returned by the issuer is not the same as the
    /// one we got before.
    #[error("wrong authentication time")]
    WrongAuthTime,
}

/// All errors that can occur when adding client credentials to the request.
#[derive(Debug, Error)]
pub enum CredentialsError {
    /// Trying to use an unsupported authentication method.
    #[error("unsupported authentication method")]
    UnsupportedMethod,

    /// When authenticationg with `private_key_jwt`, no private key was found
    /// for the given algorithm.
    #[error("no private key was found for the given algorithm")]
    NoPrivateKeyFound,

    /// The signing algorithm is invalid for this authentication method.
    #[error("invalid algorithm: {0}")]
    InvalidSigningAlgorithm(#[from] InvalidAlgorithm),

    /// An error occurred when building the claims of the JWT.
    #[error(transparent)]
    JwtClaims(#[from] ClaimError),

    /// The key found cannot be used with the algorithm.
    #[error("Wrong algorithm for key")]
    JwtWrongAlgorithm,

    /// An error occurred when signing the JWT.
    #[error(transparent)]
    JwtSignature(#[from] JwtSignatureError),
}

#[derive(Debug, Deserialize)]
struct OAuth2ErrorResponse {
    error: String,
    error_description: Option<String>,
    error_uri: Option<String>,
}

impl std::fmt::Display for OAuth2ErrorResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.error)?;

        if let Some(error_uri) = &self.error_uri {
            write!(f, " (See {error_uri})")?;
        }

        if let Some(error_description) = &self.error_description {
            write!(f, ": {error_description}")?;
        }

        Ok(())
    }
}

/// An error returned by the OAuth 2.0 provider
#[derive(Debug, Error)]
pub struct OAuth2Error {
    error: Option<OAuth2ErrorResponse>,

    #[source]
    inner: reqwest::Error,
}

impl std::fmt::Display for OAuth2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(error) = &self.error {
            write!(
                f,
                "Request to the provider failed with the following error: {error}"
            )
        } else {
            write!(f, "Request to the provider failed")
        }
    }
}

impl From<reqwest::Error> for OAuth2Error {
    fn from(inner: reqwest::Error) -> Self {
        Self { error: None, inner }
    }
}

/// An extension trait to deal with error responses from the OAuth 2.0 provider
#[async_trait]
pub(crate) trait ResponseExt {
    async fn error_from_oauth2_error_response(self) -> Result<Self, OAuth2Error>
    where
        Self: Sized;
}

#[async_trait]
impl ResponseExt for reqwest::Response {
    async fn error_from_oauth2_error_response(self) -> Result<Self, OAuth2Error> {
        let Err(inner) = self.error_for_status_ref() else {
            return Ok(self);
        };

        let error: OAuth2ErrorResponse = self.json().await?;

        Err(OAuth2Error {
            error: Some(error),
            inner,
        })
    }
}
