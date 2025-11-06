// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, error::Error};

use axum::{
    extract::{
        Form, FromRequest, FromRequestParts,
        rejection::{FailedToDeserializeForm, FormRejection},
    },
    response::{IntoResponse, Response},
};
use axum_extra::typed_header::{TypedHeader, TypedHeaderRejectionReason};
use headers::{Authorization, Header, HeaderMapExt, HeaderName, authorization::Bearer};
use http::{HeaderMap, HeaderValue, Request, StatusCode, header::WWW_AUTHENTICATE};
use mas_data_model::{Clock, Session};
use mas_storage::{
    RepositoryAccess,
    oauth2::{OAuth2AccessTokenRepository, OAuth2SessionRepository},
};
use serde::{Deserialize, de::DeserializeOwned};
use thiserror::Error;

#[derive(Debug, Deserialize)]
struct AuthorizedForm<F> {
    #[serde(default)]
    access_token: Option<String>,

    #[serde(flatten)]
    inner: F,
}

#[derive(Debug)]
enum AccessToken {
    Form(String),
    Header(String),
    None,
}

impl AccessToken {
    async fn fetch<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<(mas_data_model::AccessToken, Session), AuthorizationVerificationError<E>> {
        let token = match self {
            AccessToken::Form(t) | AccessToken::Header(t) => t,
            AccessToken::None => return Err(AuthorizationVerificationError::MissingToken),
        };

        let token = repo
            .oauth2_access_token()
            .find_by_token(token.as_str())
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        let session = repo
            .oauth2_session()
            .lookup(token.session_id)
            .await?
            .ok_or(AuthorizationVerificationError::InvalidToken)?;

        Ok((token, session))
    }
}

#[derive(Debug)]
pub struct UserAuthorization<F = ()> {
    access_token: AccessToken,
    form: Option<F>,
}

impl<F: Send> UserAuthorization<F> {
    // TODO: take scopes to validate as parameter
    /// Verify a user authorization and return the session and the protected
    /// form value
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid, if the user session ended or
    /// if the form is missing
    pub async fn protected_form<E>(
        self,
        repo: &mut impl RepositoryAccess<Error = E>,
        clock: &impl Clock,
    ) -> Result<(Session, F), AuthorizationVerificationError<E>> {
        let Some(form) = self.form else {
            return Err(AuthorizationVerificationError::MissingForm);
        };

        let (token, session) = self.access_token.fetch(repo).await?;

        if !token.is_valid(clock.now()) || !session.is_valid() {
            return Err(AuthorizationVerificationError::InvalidToken);
        }

        Ok((session, form))
    }

    // TODO: take scopes to validate as parameter
    /// Verify a user authorization and return the session
    ///
    /// # Errors
    ///
    /// Returns an error if the token is invalid or if the user session ended
    pub async fn protected<E>(
        self,
        repo: &mut impl RepositoryAccess<Error = E>,
        clock: &impl Clock,
    ) -> Result<Session, AuthorizationVerificationError<E>> {
        let (token, session) = self.access_token.fetch(repo).await?;

        if !token.is_valid(clock.now()) || !session.is_valid() {
            return Err(AuthorizationVerificationError::InvalidToken);
        }

        if !token.is_used() {
            // Mark the token as used
            repo.oauth2_access_token().mark_used(clock, token).await?;
        }

        Ok(session)
    }
}

pub enum UserAuthorizationError {
    InvalidHeader,
    TokenInFormAndHeader,
    BadForm(FailedToDeserializeForm),
    Internal(Box<dyn Error>),
}

#[derive(Debug, Error)]
pub enum AuthorizationVerificationError<E> {
    #[error("missing token")]
    MissingToken,

    #[error("invalid token")]
    InvalidToken,

    #[error("missing form")]
    MissingForm,

    #[error(transparent)]
    Internal(#[from] E),
}

enum BearerError {
    InvalidRequest,
    InvalidToken,
    #[allow(dead_code)]
    InsufficientScope {
        scope: Option<HeaderValue>,
    },
}

impl BearerError {
    fn error(&self) -> HeaderValue {
        match self {
            BearerError::InvalidRequest => HeaderValue::from_static("invalid_request"),
            BearerError::InvalidToken => HeaderValue::from_static("invalid_token"),
            BearerError::InsufficientScope { .. } => HeaderValue::from_static("insufficient_scope"),
        }
    }

    fn params(&self) -> HashMap<&'static str, HeaderValue> {
        match self {
            BearerError::InsufficientScope { scope: Some(scope) } => {
                let mut m = HashMap::new();
                m.insert("scope", scope.clone());
                m
            }
            _ => HashMap::new(),
        }
    }
}

enum WwwAuthenticate {
    #[allow(dead_code)]
    Basic { realm: HeaderValue },
    Bearer {
        realm: Option<HeaderValue>,
        error: BearerError,
        error_description: Option<HeaderValue>,
    },
}

impl Header for WwwAuthenticate {
    fn name() -> &'static HeaderName {
        &WWW_AUTHENTICATE
    }

    fn decode<'i, I>(_values: &mut I) -> Result<Self, headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        Err(headers::Error::invalid())
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, values: &mut E) {
        let (scheme, params) = match self {
            WwwAuthenticate::Basic { realm } => {
                let mut params = HashMap::new();
                params.insert("realm", realm.clone());
                ("Basic", params)
            }
            WwwAuthenticate::Bearer {
                realm,
                error,
                error_description,
            } => {
                let mut params = error.params();
                params.insert("error", error.error());

                if let Some(realm) = realm {
                    params.insert("realm", realm.clone());
                }

                if let Some(error_description) = error_description {
                    params.insert("error_description", error_description.clone());
                }

                ("Bearer", params)
            }
        };

        let params = params.into_iter().map(|(k, v)| format!(" {k}={v:?}"));
        let value: String = std::iter::once(scheme.to_owned()).chain(params).collect();
        let value = HeaderValue::from_str(&value).unwrap();
        values.extend(std::iter::once(value));
    }
}

impl IntoResponse for UserAuthorizationError {
    fn into_response(self) -> Response {
        match self {
            Self::BadForm(_) | Self::InvalidHeader | Self::TokenInFormAndHeader => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

impl<E> IntoResponse for AuthorizationVerificationError<E>
where
    E: ToString,
{
    fn into_response(self) -> Response {
        match self {
            Self::MissingForm | Self::MissingToken => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidRequest,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::InvalidToken => {
                let mut headers = HeaderMap::new();

                headers.typed_insert(WwwAuthenticate::Bearer {
                    realm: None,
                    error: BearerError::InvalidToken,
                    error_description: None,
                });
                (StatusCode::BAD_REQUEST, headers).into_response()
            }
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        }
    }
}

impl<S, F> FromRequest<S> for UserAuthorization<F>
where
    F: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = UserAuthorizationError;

    async fn from_request(
        req: Request<axum::body::Body>,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let (mut parts, body) = req.into_parts();
        let header =
            TypedHeader::<Authorization<Bearer>>::from_request_parts(&mut parts, state).await;

        // Take the Authorization header
        let token_from_header = match header {
            Ok(header) => Some(header.token().to_owned()),
            Err(err) => match err.reason() {
                // If it's missing it is fine
                TypedHeaderRejectionReason::Missing => None,
                // If the header could not be parsed, return the error
                _ => return Err(UserAuthorizationError::InvalidHeader),
            },
        };

        let req = Request::from_parts(parts, body);

        // Take the form value
        let (token_from_form, form) =
            match Form::<AuthorizedForm<F>>::from_request(req, state).await {
                Ok(Form(form)) => (form.access_token, Some(form.inner)),
                // If it is not a form, continue
                Err(FormRejection::InvalidFormContentType(_err)) => (None, None),
                // If the form could not be read, return a Bad Request error
                Err(FormRejection::FailedToDeserializeForm(err)) => {
                    return Err(UserAuthorizationError::BadForm(err));
                }
                // Other errors (body read twice, byte stream broke) return an internal error
                Err(e) => return Err(UserAuthorizationError::Internal(Box::new(e))),
            };

        let access_token = match (token_from_header, token_from_form) {
            // Ensure the token should not be in both the form and the access token
            (Some(_), Some(_)) => return Err(UserAuthorizationError::TokenInFormAndHeader),
            (Some(t), None) => AccessToken::Header(t),
            (None, Some(t)) => AccessToken::Form(t),
            (None, None) => AccessToken::None,
        };

        Ok(UserAuthorization { access_token, form })
    }
}
