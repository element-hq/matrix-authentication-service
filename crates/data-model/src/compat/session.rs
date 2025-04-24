// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

use super::Device;
use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub enum CompatSessionState {
    #[default]
    Valid,
    Finished {
        finished_at: DateTime<Utc>,
    },
}

impl CompatSessionState {
    /// Returns `true` if the compat session state is [`Valid`].
    ///
    /// [`Valid`]: CompatSessionState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the compat session state is [`Finished`].
    ///
    /// [`Finished`]: CompatSessionState::Finished
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
    /// [`Finished`]: CompatSessionState::Finished
    pub fn finish(self, finished_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Finished { finished_at }),
            Self::Finished { .. } => Err(InvalidTransitionError),
        }
    }

    #[must_use]
    pub fn finished_at(&self) -> Option<DateTime<Utc>> {
        match self {
            CompatSessionState::Valid => None,
            CompatSessionState::Finished { finished_at } => Some(*finished_at),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CompatSession {
    pub id: Ulid,
    pub state: CompatSessionState,
    pub user_id: Ulid,
    pub device: Option<Device>,
    pub human_name: Option<String>,
    pub user_session_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
    pub is_synapse_admin: bool,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl std::ops::Deref for CompatSession {
    type Target = CompatSessionState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl CompatSession {
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
