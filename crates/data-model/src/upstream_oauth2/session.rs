// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

use super::UpstreamOAuthLink;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum UpstreamOAuthAuthorizationSessionState {
    #[default]
    Pending,
    Completed {
        completed_at: DateTime<Utc>,
        link_id: Ulid,
        id_token: Option<String>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    },
    Consumed {
        completed_at: DateTime<Utc>,
        consumed_at: DateTime<Utc>,
        link_id: Ulid,
        id_token: Option<String>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    },
}

impl UpstreamOAuthAuthorizationSessionState {
    /// Mark the upstream OAuth 2.0 authorization session as completed.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream OAuth 2.0 authorization session state
    /// is not [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    pub fn complete(
        self,
        completed_at: DateTime<Utc>,
        link: &UpstreamOAuthLink,
        id_token: Option<String>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Completed {
                completed_at,
                link_id: link.id,
                id_token,
                extra_callback_parameters,
                userinfo,
            }),
            Self::Completed { .. } | Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }

    /// Mark the upstream OAuth 2.0 authorization session as consumed.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream OAuth 2.0 authorization session state
    /// is not [`Completed`].
    ///
    /// [`Completed`]: UpstreamOAuthAuthorizationSessionState::Completed
    pub fn consume(self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Completed {
                completed_at,
                link_id,
                id_token,
                extra_callback_parameters,
                userinfo,
            } => Ok(Self::Consumed {
                completed_at,
                link_id,
                consumed_at,
                id_token,
                extra_callback_parameters,
                userinfo,
            }),
            Self::Pending | Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }

    /// Get the link ID for the upstream OAuth 2.0 authorization session.
    ///
    /// Returns `None` if the upstream OAuth 2.0 authorization session state is
    /// [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn link_id(&self) -> Option<Ulid> {
        match self {
            Self::Pending => None,
            Self::Completed { link_id, .. } | Self::Consumed { link_id, .. } => Some(*link_id),
        }
    }

    /// Get the time at which the upstream OAuth 2.0 authorization session was
    /// completed.
    ///
    /// Returns `None` if the upstream OAuth 2.0 authorization session state is
    /// [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn completed_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending => None,
            Self::Completed { completed_at, .. } | Self::Consumed { completed_at, .. } => {
                Some(*completed_at)
            }
        }
    }

    /// Get the ID token for the upstream OAuth 2.0 authorization session.
    ///
    /// Returns `None` if the upstream OAuth 2.0 authorization session state is
    /// [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn id_token(&self) -> Option<&str> {
        match self {
            Self::Pending => None,
            Self::Completed { id_token, .. } | Self::Consumed { id_token, .. } => {
                id_token.as_deref()
            }
        }
    }

    /// Get the extra query parameters that were sent to the upstream provider.
    ///
    /// Returns `None` if the upstream OAuth 2.0 authorization session state is
    /// not [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn extra_callback_parameters(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Pending => None,
            Self::Completed {
                extra_callback_parameters,
                ..
            }
            | Self::Consumed {
                extra_callback_parameters,
                ..
            } => extra_callback_parameters.as_ref(),
        }
    }

    #[must_use]
    pub fn userinfo(&self) -> Option<&serde_json::Value> {
        match self {
            Self::Pending => None,
            Self::Completed { userinfo, .. } | Self::Consumed { userinfo, .. } => userinfo.as_ref(),
        }
    }

    /// Get the time at which the upstream OAuth 2.0 authorization session was
    /// consumed.
    ///
    /// Returns `None` if the upstream OAuth 2.0 authorization session state is
    /// not [`Consumed`].
    ///
    /// [`Consumed`]: UpstreamOAuthAuthorizationSessionState::Consumed
    #[must_use]
    pub fn consumed_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Pending | Self::Completed { .. } => None,
            Self::Consumed { consumed_at, .. } => Some(*consumed_at),
        }
    }

    /// Returns `true` if the upstream OAuth 2.0 authorization session state is
    /// [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the upstream OAuth 2.0 authorization session state is
    /// [`Completed`].
    ///
    /// [`Completed`]: UpstreamOAuthAuthorizationSessionState::Completed
    #[must_use]
    pub fn is_completed(&self) -> bool {
        matches!(self, Self::Completed { .. })
    }

    /// Returns `true` if the upstream OAuth 2.0 authorization session state is
    /// [`Consumed`].
    ///
    /// [`Consumed`]: UpstreamOAuthAuthorizationSessionState::Consumed
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        matches!(self, Self::Consumed { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthAuthorizationSession {
    pub id: Ulid,
    pub state: UpstreamOAuthAuthorizationSessionState,
    pub provider_id: Ulid,
    pub state_str: String,
    pub code_challenge_verifier: Option<String>,
    pub nonce: String,
    pub created_at: DateTime<Utc>,
}

impl std::ops::Deref for UpstreamOAuthAuthorizationSession {
    type Target = UpstreamOAuthAuthorizationSessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl UpstreamOAuthAuthorizationSession {
    /// Mark the upstream OAuth 2.0 authorization session as completed. Returns
    /// the updated session.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream OAuth 2.0 authorization session state
    /// is not [`Pending`].
    ///
    /// [`Pending`]: UpstreamOAuthAuthorizationSessionState::Pending
    pub fn complete(
        mut self,
        completed_at: DateTime<Utc>,
        link: &UpstreamOAuthLink,
        id_token: Option<String>,
        extra_callback_parameters: Option<serde_json::Value>,
        userinfo: Option<serde_json::Value>,
    ) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.complete(
            completed_at,
            link,
            id_token,
            extra_callback_parameters,
            userinfo,
        )?;
        Ok(self)
    }

    /// Mark the upstream OAuth 2.0 authorization session as consumed. Returns
    /// the updated session.
    ///
    /// # Errors
    ///
    /// Returns an error if the upstream OAuth 2.0 authorization session state
    /// is not [`Completed`].
    ///
    /// [`Completed`]: UpstreamOAuthAuthorizationSessionState::Completed
    pub fn consume(mut self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.consume(consumed_at)?;
        Ok(self)
    }
}
