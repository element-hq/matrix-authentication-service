// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::convert::Infallible;

use aide::OperationIo;
use axum::{
    Json,
    extract::FromRequestParts,
    response::{IntoResponse, Response},
};
use axum_extra::TypedHeader;
use headers::{Authorization, authorization::Bearer};
use hyper::StatusCode;
use mas_axum_utils::record_error;
use mas_data_model::{
    BoxClock, Session, TokenFormatError, TokenType, User,
    personal::session::{PersonalSession, PersonalSessionOwner},
};
use mas_storage::{BoxRepository, RepositoryError};
use oauth2_types::scope::Scope;
use ulid::Ulid;

use super::response::ErrorResponse;
use crate::BoundActivityTracker;

#[derive(Debug, thiserror::Error)]
pub enum Rejection {
    /// The authorization header is missing
    #[error("Missing authorization header")]
    MissingAuthorizationHeader,

    /// The authorization header is invalid
    #[error("Invalid authorization header")]
    InvalidAuthorizationHeader,

    /// Couldn't load the database repository
    #[error("Couldn't load the database repository")]
    RepositorySetup(#[source] Box<dyn std::error::Error + Send + Sync + 'static>),

    /// A database operation failed
    #[error("Invalid repository operation")]
    Repository(#[from] RepositoryError),

    /// The access token was not of the correct type for the Admin API
    #[error("Invalid type of access token")]
    InvalidAccessTokenType(
        #[source]
        #[from]
        Option<TokenFormatError>,
    ),

    /// The access token could not be found in the database
    #[error("Unknown access token")]
    UnknownAccessToken,

    /// The access token provided expired
    #[error("Access token expired")]
    TokenExpired,

    /// The session associated with the access token was revoked
    #[error("Access token revoked")]
    SessionRevoked,

    /// The user associated with the session is locked
    #[error("User locked")]
    UserLocked,

    /// Failed to load the session
    #[error("Failed to load session {0}")]
    LoadSession(Ulid),

    /// Failed to load the user
    #[error("Failed to load user {0}")]
    LoadUser(Ulid),

    /// The session does not have the `urn:mas:admin` scope
    #[error("Missing urn:mas:admin scope")]
    MissingScope,
}

impl IntoResponse for Rejection {
    fn into_response(self) -> Response {
        let response = ErrorResponse::from_error(&self);
        let sentry_event_id = record_error!(
            self,
            Self::RepositorySetup(_)
                | Self::Repository(_)
                | Self::LoadSession(_)
                | Self::LoadUser(_)
        );

        let status = match &self {
            Rejection::InvalidAuthorizationHeader | Rejection::MissingAuthorizationHeader => {
                StatusCode::BAD_REQUEST
            }

            Rejection::UnknownAccessToken
            | Rejection::TokenExpired
            | Rejection::SessionRevoked
            | Rejection::UserLocked
            | Rejection::MissingScope
            | Rejection::InvalidAccessTokenType(_) => StatusCode::UNAUTHORIZED,

            Rejection::RepositorySetup(_)
            | Rejection::Repository(_)
            | Rejection::LoadSession(_)
            | Rejection::LoadUser(_) => StatusCode::INTERNAL_SERVER_ERROR,
        };

        (status, sentry_event_id, Json(response)).into_response()
    }
}

/// An extractor which authorizes the request
///
/// Because we need to load the database repository and the clock, we keep them
/// in the context to avoid creating two instances for each request.
#[non_exhaustive]
#[derive(OperationIo)]
#[aide(input)]
pub struct CallContext {
    pub repo: BoxRepository,
    pub clock: BoxClock,
    pub user: Option<User>,
    pub session: CallerSession,
}

impl<S> FromRequestParts<S> for CallContext
where
    S: Send + Sync,
    BoundActivityTracker: FromRequestParts<S, Rejection = Infallible>,
    BoxRepository: FromRequestParts<S>,
    BoxClock: FromRequestParts<S, Rejection = Infallible>,
    <BoxRepository as FromRequestParts<S>>::Rejection:
        Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    type Rejection = Rejection;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let Ok(activity_tracker) = BoundActivityTracker::from_request_parts(parts, state).await;
        let Ok(clock) = BoxClock::from_request_parts(parts, state).await;

        // Load the database repository
        let mut repo = BoxRepository::from_request_parts(parts, state)
            .await
            .map_err(Into::into)
            .map_err(Rejection::RepositorySetup)?;

        // Extract the access token from the authorization header
        let token = TypedHeader::<Authorization<Bearer>>::from_request_parts(parts, state)
            .await
            .map_err(|e| {
                // We map to two differentsson of errors depending on whether the header is
                // missing or invalid
                if e.is_missing() {
                    Rejection::MissingAuthorizationHeader
                } else {
                    Rejection::InvalidAuthorizationHeader
                }
            })?;

        let token = token.token();
        let token_type = TokenType::check(token)?;

        let session = match token_type {
            TokenType::AccessToken => {
                // Look for the access token in the database
                let token = repo
                    .oauth2_access_token()
                    .find_by_token(token)
                    .await?
                    .ok_or(Rejection::UnknownAccessToken)?;

                // Look for the associated session in the database
                let session = repo
                    .oauth2_session()
                    .lookup(token.session_id)
                    .await?
                    .ok_or_else(|| Rejection::LoadSession(token.session_id))?;

                if !session.is_valid() {
                    return Err(Rejection::SessionRevoked);
                }

                if !token.is_valid(clock.now()) {
                    return Err(Rejection::TokenExpired);
                }

                // Record the activity on the session
                activity_tracker
                    .record_oauth2_session(&clock, &session)
                    .await;

                CallerSession::OAuth2Session(session)
            }
            TokenType::PersonalAccessToken => {
                // Look for the access token in the database
                let token = repo
                    .personal_access_token()
                    .find_by_token(token)
                    .await?
                    .ok_or(Rejection::UnknownAccessToken)?;

                // Look for the associated session in the database
                let session = repo
                    .personal_session()
                    .lookup(token.session_id)
                    .await?
                    .ok_or_else(|| Rejection::LoadSession(token.session_id))?;

                if !session.is_valid() {
                    return Err(Rejection::SessionRevoked);
                }

                if !token.is_valid(clock.now()) {
                    return Err(Rejection::TokenExpired);
                }

                // Check the validity of the owner of the personal session
                match session.owner {
                    PersonalSessionOwner::User(owner_user_id) => {
                        let owner_user = repo
                            .user()
                            .lookup(owner_user_id)
                            .await?
                            .ok_or_else(|| Rejection::LoadUser(owner_user_id))?;
                        if !owner_user.is_valid() {
                            return Err(Rejection::UserLocked);
                        }
                    }
                    PersonalSessionOwner::OAuth2Client(_) => {
                        // nop: Client owners are always valid
                    }
                }

                // Record the activity on the session
                activity_tracker
                    .record_personal_session(&clock, &session)
                    .await;

                CallerSession::PersonalSession(session)
            }
            _other => {
                return Err(Rejection::InvalidAccessTokenType(None));
            }
        };

        // Load the user if there is one
        let user = if let Some(user_id) = session.user_id() {
            let user = repo
                .user()
                .lookup(user_id)
                .await?
                .ok_or_else(|| Rejection::LoadUser(user_id))?;
            Some(user)
        } else {
            None
        };

        // If there is a user for this session, check that it is not locked
        if let Some(user) = &user
            && !user.is_valid()
        {
            return Err(Rejection::UserLocked);
        }

        // For now, we only check that the session has the admin scope
        // Later we might want to check other route-specific scopes
        if !session.scope().contains("urn:mas:admin") {
            return Err(Rejection::MissingScope);
        }

        Ok(Self {
            repo,
            clock,
            user,
            session,
        })
    }
}

/// The session representing the caller of the Admin API;
/// could either be an OAuth session or a personal session.
pub enum CallerSession {
    OAuth2Session(Session),
    PersonalSession(PersonalSession),
}

impl CallerSession {
    pub fn scope(&self) -> &Scope {
        match self {
            CallerSession::OAuth2Session(session) => &session.scope,
            CallerSession::PersonalSession(session) => &session.scope,
        }
    }

    pub fn user_id(&self) -> Option<Ulid> {
        match self {
            CallerSession::OAuth2Session(session) => session.user_id,
            CallerSession::PersonalSession(session) => Some(session.actor_user_id),
        }
    }
}
