// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use serde::Serialize;
use ulid::Ulid;

use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum SessionState {
    #[default]
    Valid,
    Finished {
        finished_at: DateTime<Utc>,
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

    /// Returns `true` if the session state is [`Finished`].
    ///
    /// [`Finished`]: SessionState::Finished
    #[must_use]
    pub fn is_finished(&self) -> bool {
        matches!(self, Self::Finished { .. })
    }

    /// Transitions the session state to [`Finished`].
    ///
    /// # Parameters
    ///
    /// * `finished_at` - The time at which the session was finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the session state is already [`Finished`].
    ///
    /// [`Finished`]: SessionState::Finished
    pub fn finish(self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Finished { finished_at }),
            Self::Finished { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns the time the session was finished, if any
    ///
    /// Returns `None` if the session is still [`Valid`].
    ///
    /// [`Valid`]: SessionState::Valid
    #[must_use]
    pub fn finished_at(&self) -> Option<DateTime<Utc>> {
        match self {
            Self::Valid => None,
            Self::Finished { finished_at } => Some(*finished_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Session {
    pub id: Ulid,
    pub state: SessionState,
    pub created_at: DateTime<Utc>,
    pub user_id: Option<Ulid>,
    pub user_session_id: Option<Ulid>,
    pub client_id: Ulid,
    pub scope: Scope,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl std::ops::Deref for Session {
    type Target = SessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl Session {
    /// Marks the session as finished.
    ///
    /// # Parameters
    ///
    /// * `finished_at` - The time at which the session was finished.
    ///
    /// # Errors
    ///
    /// Returns an error if the session is already finished.
    pub fn finish(mut self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.finish(finished_at)?;
        Ok(self)
    }
}
