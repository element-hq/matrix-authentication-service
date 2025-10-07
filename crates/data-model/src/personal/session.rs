// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use serde::Serialize;
use ulid::Ulid;

use crate::{Client, InvalidTransitionError, User};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum SessionState {
    #[default]
    Valid,
    Revoked {
        revoked_at: DateTime<Utc>,
    },
}

impl SessionState {
    /// Returns `true` if the session state is [`Valid`].
    ///
    /// [`Valid`]: SessionState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the session state is [`Revoked`].
    ///
    /// [`Revoked`]: SessionState::Revoked
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }

    /// Transitions the session state to [`Revoked`].
    ///
    /// # Parameters
    ///
    /// * `revoked_at` - The time at which the session was revoked.
    ///
    /// # Errors
    ///
    /// Returns an error if the session state is already [`Revoked`].
    ///
    /// [`Revoked`]: SessionState::Revoked
    pub fn revoke(self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Revoked { revoked_at }),
            Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns the time the session was revoked, if any
    ///
    /// Returns `None` if the session is still [`Valid`].
    ///
    /// [`Valid`]: SessionState::Valid
    #[must_use]
    pub fn revoked_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Valid => None,
            Self::Revoked { revoked_at } => Some(*revoked_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PersonalSession {
    pub id: Ulid,
    pub state: SessionState,
    pub owner: PersonalSessionOwner,
    pub actor_user_id: Ulid,
    pub human_name: String,
    /// The scope for the session, identical to OAuth 2 sessions.
    /// May or may not include a device scope
    /// (personal sessions can be deviceless).
    pub scope: Scope,
    pub created_at: DateTime<Utc>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Serialize)]
pub enum PersonalSessionOwner {
    /// The personal session is owned by the user with the given `user_id`.
    User(Ulid),
    /// The personal session is owned by the OAuth 2 Client with the given
    /// `oauth2_client_id`.
    OAuth2Client(Ulid),
}

impl<'a> From<&'a User> for PersonalSessionOwner {
    fn from(value: &'a User) -> Self {
        PersonalSessionOwner::User(value.id)
    }
}

impl<'a> From<&'a Client> for PersonalSessionOwner {
    fn from(value: &'a Client) -> Self {
        PersonalSessionOwner::OAuth2Client(value.id)
    }
}

impl std::ops::Deref for PersonalSession {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl PersonalSession {
    /// Marks the session as revoked.
    ///
    /// # Parameters
    ///
    /// * `revoked_at` - The time at which the session was finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is already finished.
    pub fn finish(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.revoke(revoked_at)?;
        Ok(self)
    }
}
