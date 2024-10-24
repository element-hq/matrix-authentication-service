// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! The error types used in this crate.

use headers::authorization::InvalidBearerToken;
use http::StatusCode;
use mas_http::{catch_http_codes, form_urlencoded_request, json_response};
use mas_jose::{
    claims::ClaimError,
    jwa::InvalidAlgorithm,
    jwt::{JwtDecodeError, JwtSignatureError, NoKeyWorked},
};
use oauth2_types::{
    errors::ClientErrorCode, oidc::ProviderMetadataVerificationError, pkce::CodeChallengeError,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
pub use tower::BoxError;

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

    /// An error occurred introspecting a token.
    Introspection(#[from] IntrospectionError),
}

/// All possible errors when fetching provider metadata.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// An error occurred building the request's URL.
    #[error(transparent)]
    IntoUrl(#[from] url::ParseError),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// An error occurred validating the metadata.
    #[error(transparent)]
    Validation(#[from] ProviderMetadataVerificationError),

    /// Discovery is disabled for this provider.
    #[error("Discovery is disabled for this provider")]
    Disabled,
}

/// All possible errors when authorizing the client.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// An error occurred constructing the PKCE code challenge.
    #[error(transparent)]
    Pkce(#[from] CodeChallengeError),

    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),
}

/// All possible errors when requesting an access token.
#[derive(Debug, Error)]
pub enum TokenRequestError {
    /// The HTTP client returned an error.
    #[error(transparent)]
    Http(#[from] reqwest::Error),

    /// Error while injecting the client credentials into the request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),
}

/// All possible errors when exchanging a code for an access token.
#[derive(Debug, Error)]
pub enum TokenAuthorizationCodeError {
    /// An error occurred requesting the access token.
    #[error(transparent)]
    Token(#[from] TokenRequestError),

    /// An error occurred validating the ID Token.
    #[error(transparent)]
    IdToken(#[from] IdTokenError),
}

/// All possible errors when refreshing an access token.
#[derive(Debug, Error)]
pub enum TokenRefreshError {
    /// An error occurred requesting the access token.
    #[error(transparent)]
    Token(#[from] TokenRequestError),

    /// An error occurred validating the ID Token.
    #[error(transparent)]
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
    #[error(transparent)]
    IdToken(#[from] IdTokenError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Http(#[from] reqwest::Error),
}

/// All possible errors when introspecting a token.
#[derive(Debug, Error)]
pub enum IntrospectionError {
    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred adding the client credentials to the request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),

    /// The access token is invalid.
    #[error(transparent)]
    Token(#[from] InvalidBearerToken),

    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),

    /// An error occurred deserializing the JSON or error response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<form_urlencoded_request::Error<S>> for IntrospectionError
where
    S: Into<IntrospectionError>,
{
    fn from(err: form_urlencoded_request::Error<S>) -> Self {
        match err {
            form_urlencoded_request::Error::Serialize { inner } => inner.into(),
            form_urlencoded_request::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<json_response::Error<S>> for IntrospectionError
where
    S: Into<IntrospectionError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Deserialize { inner } => inner.into(),
            json_response::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for IntrospectionError
where
    S: Into<BoxError>,
{
    fn from(err: catch_http_codes::Error<S, Option<ErrorBody>>) -> Self {
        match err {
            catch_http_codes::Error::HttpError { status_code, inner } => {
                HttpError::new(status_code, inner).into()
            }
            catch_http_codes::Error::Service { inner } => Self::Service(inner.into()),
        }
    }
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

    /// An error occurred validating the ID Token's signature and basic claims.
    #[error(transparent)]
    Jwt(#[from] JwtVerificationError),

    /// An error occurred extracting a claim.
    #[error(transparent)]
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

/// An error that can be returned by an OpenID Provider.
#[derive(Debug, Clone, Error)]
#[error("{status}: {body:?}")]
pub struct HttpError {
    /// The status code of the error.
    pub status: StatusCode,

    /// The body of the error, if any.
    pub body: Option<ErrorBody>,
}

impl HttpError {
    /// Creates a new `HttpError` with the given status code and optional body.
    #[must_use]
    pub fn new(status: StatusCode, body: Option<ErrorBody>) -> Self {
        Self { status, body }
    }
}

/// The body of an error that can be returned by an OpenID Provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorBody {
    /// The error code.
    pub error: ClientErrorCode,

    /// Additional text description of the error for debugging.
    pub error_description: Option<String>,
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

    /// An error occurred with a custom signing method.
    #[error(transparent)]
    Custom(BoxError),
}
