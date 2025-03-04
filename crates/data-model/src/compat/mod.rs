// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Utc};
use ulid::Ulid;

mod device;
mod session;
mod sso_login;

pub use self::{
    device::{Device, ToScopeTokenError},
    session::{CompatSession, CompatSessionState},
    sso_login::{CompatSsoLogin, CompatSsoLoginState},
};
use crate::InvalidTransitionError;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatAccessToken {
    pub id: Ulid,
    pub session_id: Ulid,
    pub token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl CompatAccessToken {
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        if let Some(expires_at) = self.expires_at {
            expires_at > now
        } else {
            true
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum CompatRefreshTokenState {
    #[default]
    Valid,
    Consumed {
        consumed_at: DateTime<Utc>,
    },
}

impl CompatRefreshTokenState {
    /// Returns `true` if the compat refresh token state is [`Valid`].
    ///
    /// [`Valid`]: CompatRefreshTokenState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the compat refresh token state is [`Consumed`].
    ///
    /// [`Consumed`]: CompatRefreshTokenState::Consumed
    #[must_use]
    pub fn is_consumed(&self) -> bool {
        matches!(self, Self::Consumed { .. })
    }

    /// Consume the refresh token, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is already consumed.
    pub fn consume(self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Consumed { consumed_at }),
            Self::Consumed { .. } => Err(InvalidTransitionError),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatRefreshToken {
    pub id: Ulid,
    pub state: CompatRefreshTokenState,
    pub session_id: Ulid,
    pub access_token_id: Ulid,
    pub token: String,
    pub created_at: DateTime<Utc>,
}

impl std::ops::Deref for CompatRefreshToken {
    type Target = CompatRefreshTokenState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl CompatRefreshToken {
    /// Consume the refresh token and return the consumed token.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is already consumed.
    pub fn consume(mut self, consumed_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.consume(consumed_at)?;
        Ok(self)
    }
}
