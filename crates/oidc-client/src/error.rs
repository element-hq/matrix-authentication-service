// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! The error types used in this crate.

use std::{str::Utf8Error, sync::Arc};

use headers::authorization::InvalidBearerToken;
use http::{header::ToStrError, StatusCode};
use mas_http::{catch_http_codes, form_urlencoded_request, json_request, json_response};
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

    /// An error occurred during client registration.
    Registration(#[from] RegistrationError),

    /// An error occurred building the authorization URL.
    Authorization(#[from] AuthorizationError),

    /// An error occurred exchanging an authorization code for an access token.
    TokenAuthorizationCode(#[from] TokenAuthorizationCodeError),

    /// An error occurred requesting an access token with client credentials.
    TokenClientCredentials(#[from] TokenRequestError),

    /// An error occurred refreshing an access token.
    TokenRefresh(#[from] TokenRefreshError),

    /// An error occurred revoking a token.
    TokenRevoke(#[from] TokenRevokeError),

    /// An error occurred requesting user info.
    UserInfo(#[from] UserInfoError),

    /// An error occurred introspecting a token.
    Introspection(#[from] IntrospectionError),

    /// An error occurred building the account management URL.
    AccountManagement(#[from] AccountManagementError),
}

/// All possible errors when fetching provider metadata.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// An error occurred building the request's URL.
    #[error(transparent)]
    IntoUrl(#[from] url::ParseError),

    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred deserializing the response.
    #[error(transparent)]
    FromJson(#[from] serde_json::Error),

    /// An error occurred validating the metadata.
    #[error(transparent)]
    Validation(#[from] ProviderMetadataVerificationError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),

    /// Discovery is disabled for this provider.
    #[error("Discovery is disabled for this provider")]
    Disabled,
}

impl<S> From<json_response::Error<S>> for DiscoveryError
where
    S: Into<DiscoveryError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Deserialize { inner } => inner.into(),
            json_response::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for DiscoveryError
where
    S: Into<BoxError>,
{
    fn from(err: catch_http_codes::Error<S, Option<ErrorBody>>) -> Self {
        match err {
            catch_http_codes::Error::HttpError { status_code, inner } => {
                Self::Http(HttpError::new(status_code, inner))
            }
            catch_http_codes::Error::Service { inner } => Self::Service(inner.into()),
        }
    }
}

/// All possible errors when registering the client.
#[derive(Debug, Error)]
pub enum RegistrationError {
    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred serializing the request or deserializing the response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// No client secret was received although one was expected because of the
    /// authentication method.
    #[error("missing client secret in response")]
    MissingClientSecret,

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<json_request::Error<S>> for RegistrationError
where
    S: Into<RegistrationError>,
{
    fn from(err: json_request::Error<S>) -> Self {
        match err {
            json_request::Error::Serialize { inner } => inner.into(),
            json_request::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<json_response::Error<S>> for RegistrationError
where
    S: Into<RegistrationError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Deserialize { inner } => inner.into(),
            json_response::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for RegistrationError
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

/// All possible errors when making a pushed authorization request.
#[derive(Debug, Error)]
pub enum PushedAuthorizationError {
    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),

    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred adding the client credentials to the request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred deserializing the response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<form_urlencoded_request::Error<S>> for PushedAuthorizationError
where
    S: Into<PushedAuthorizationError>,
{
    fn from(err: form_urlencoded_request::Error<S>) -> Self {
        match err {
            form_urlencoded_request::Error::Serialize { inner } => inner.into(),
            form_urlencoded_request::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<json_response::Error<S>> for PushedAuthorizationError
where
    S: Into<PushedAuthorizationError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Deserialize { inner } => inner.into(),
            json_response::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for PushedAuthorizationError
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

/// All possible errors when authorizing the client.
#[derive(Debug, Error)]
pub enum AuthorizationError {
    /// An error occurred constructing the PKCE code challenge.
    #[error(transparent)]
    Pkce(#[from] CodeChallengeError),

    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),

    /// An error occurred making the PAR request.
    #[error(transparent)]
    PushedAuthorization(#[from] PushedAuthorizationError),
}

/// All possible errors when requesting an access token.
#[derive(Debug, Error)]
pub enum TokenRequestError {
    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred adding the client credentials to the request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),

    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred deserializing the response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<form_urlencoded_request::Error<S>> for TokenRequestError
where
    S: Into<TokenRequestError>,
{
    fn from(err: form_urlencoded_request::Error<S>) -> Self {
        match err {
            form_urlencoded_request::Error::Serialize { inner } => inner.into(),
            form_urlencoded_request::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<json_response::Error<S>> for TokenRequestError
where
    S: Into<TokenRequestError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Deserialize { inner } => inner.into(),
            json_response::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for TokenRequestError
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

/// All possible errors when revoking a token.
#[derive(Debug, Error)]
pub enum TokenRevokeError {
    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred adding the client credentials to the request.
    #[error(transparent)]
    Credentials(#[from] CredentialsError),

    /// An error occurred serializing the request.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),

    /// An error occurred deserializing the error response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<form_urlencoded_request::Error<S>> for TokenRevokeError
where
    S: Into<TokenRevokeError>,
{
    fn from(err: form_urlencoded_request::Error<S>) -> Self {
        match err {
            form_urlencoded_request::Error::Serialize { inner } => inner.into(),
            form_urlencoded_request::Error::Service { inner } => inner.into(),
        }
    }
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for TokenRevokeError
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

/// All possible errors when requesting user info.
#[derive(Debug, Error)]
pub enum UserInfoError {
    /// An error occurred getting the provider metadata.
    #[error(transparent)]
    Discovery(#[from] Arc<DiscoveryError>),

    /// The provider doesn't support requesting user info.
    #[error("missing UserInfo support")]
    MissingUserInfoSupport,

    /// No token is available to get info from.
    #[error("missing token")]
    MissingToken,

    /// No client metadata is available.
    #[error("missing client metadata")]
    MissingClientMetadata,

    /// The access token is invalid.
    #[error(transparent)]
    Token(#[from] InvalidBearerToken),

    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// The content-type header is missing from the response.
    #[error("missing response content-type")]
    MissingResponseContentType,

    /// The content-type header could not be decoded.
    #[error("could not decoded response content-type: {0}")]
    DecodeResponseContentType(#[from] ToStrError),

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

    /// An error occurred reading the response.
    #[error(transparent)]
    FromUtf8(#[from] Utf8Error),

    /// An error occurred deserializing the JSON or error response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// An error occurred verifying the Id Token.
    #[error(transparent)]
    IdToken(#[from] IdTokenError),

    /// The server returned an HTTP error status code.
    #[error(transparent)]
    Http(#[from] HttpError),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<catch_http_codes::Error<S, Option<ErrorBody>>> for UserInfoError
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
pub enum JwksError {
    /// An error occurred building the request.
    #[error(transparent)]
    IntoHttp(#[from] http::Error),

    /// An error occurred deserializing the response.
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    /// An error occurred sending the request.
    #[error(transparent)]
    Service(BoxError),
}

impl<S> From<json_response::Error<S>> for JwksError
where
    S: Into<BoxError>,
{
    fn from(err: json_response::Error<S>) -> Self {
        match err {
            json_response::Error::Service { inner } => Self::Service(inner.into()),
            json_response::Error::Deserialize { inner } => Self::Json(inner),
        }
    }
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

/// All errors that can occur when building the account management URL.
#[derive(Debug, Error)]
pub enum AccountManagementError {
    /// An error occurred serializing the parameters.
    #[error(transparent)]
    UrlEncoded(#[from] serde_urlencoded::ser::Error),
}
