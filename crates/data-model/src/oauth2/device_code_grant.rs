// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use serde::Serialize;
use ulid::Ulid;

use crate::{BrowserSession, InvalidTransitionError, Session};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DeviceCodeGrantState {
    /// The device code grant is pending.
    Pending,

    /// The device code grant has been fulfilled by a user.
    Fulfilled {
        /// The browser session which was used to complete this device code
        /// grant.
        browser_session_id: Ulid,

        /// The time at which this device code grant was fulfilled.
        fulfilled_at: DateTime<Utc>,
    },

    /// The device code grant has been rejected by a user.
    Rejected {
        /// The browser session which was used to reject this device code grant.
        browser_session_id: Ulid,

        /// The time at which this device code grant was rejected.
        rejected_at: DateTime<Utc>,
    },

    /// The device code grant was exchanged for an access token.
    Exchanged {
        /// The browser session which was used to exchange this device code
        /// grant.
        browser_session_id: Ulid,

        /// The time at which the device code grant was fulfilled.
        fulfilled_at: DateTime<Utc>,

        /// The time at which this device code grant was exchanged.
        exchanged_at: DateTime<Utc>,

        /// The OAuth 2.0 session ID which was created by this device code
        /// grant.
        session_id: Ulid,
    },
}

impl DeviceCodeGrantState {
    /// Mark this device code grant as fulfilled, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn fulfill(
        self,
        browser_session: &BrowserSession,
        fulfilled_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Pending => Ok(DeviceCodeGrantState::Fulfilled {
                browser_session_id: browser_session.id,
                fulfilled_at,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Mark this device code grant as rejected, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn reject(
        self,
        browser_session: &BrowserSession,
        rejected_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Pending => Ok(DeviceCodeGrantState::Rejected {
                browser_session_id: browser_session.id,
                rejected_at,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Mark this device code grant as exchanged, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Fulfilled`]
    /// state.
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    pub fn exchange(
        self,
        session: &Session,
        exchanged_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Fulfilled {
                fulfilled_at,
                browser_session_id,
                ..
            } => Ok(DeviceCodeGrantState::Exchanged {
                browser_session_id,
                fulfilled_at,
                exchanged_at,
                session_id: session.id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the device code grant state is [`Pending`].
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the device code grant state is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the device code grant state is [`Rejected`].
    ///
    /// [`Rejected`]: DeviceCodeGrantState::Rejected
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// Returns `true` if the device code grant state is [`Exchanged`].
    ///
    /// [`Exchanged`]: DeviceCodeGrantState::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCodeGrant {
    pub id: Ulid,
    #[serde(flatten)]
    pub state: DeviceCodeGrantState,

    /// The client ID which requested this device code grant.
    pub client_id: Ulid,

    /// The scope which was requested by this device code grant.
    pub scope: Scope,

    /// The user code which was generated for this device code grant.
    /// This is the one that the user will enter into their client.
    pub user_code: String,

    /// The device code which was generated for this device code grant.
    /// This is the one that the client will use to poll for an access token.
    pub device_code: String,

    /// The time at which this device code grant was created.
    pub created_at: DateTime<Utc>,

    /// The time at which this device code grant will expire.
    pub expires_at: DateTime<Utc>,

    /// The IP address of the client which requested this device code grant.
    pub ip_address: Option<IpAddr>,

    /// The user agent used to request this device code grant.
    pub user_agent: Option<String>,
}

impl std::ops::Deref for DeviceCodeGrant {
    type Target = DeviceCodeGrantState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DeviceCodeGrant {
    /// Mark this device code grant as fulfilled, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn fulfill(
        self,
        browser_session: &BrowserSession,
        fulfilled_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.fulfill(browser_session, fulfilled_at)?,
            ..self
        })
    }

    /// Mark this device code grant as rejected, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn reject(
        self,
        browser_session: &BrowserSession,
        rejected_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.reject(browser_session, rejected_at)?,
            ..self
        })
    }

    /// Mark this device code grant as exchanged, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Fulfilled`]
    /// state.
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    pub fn exchange(
        self,
        session: &Session,
        exchanged_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.exchange(session, exchanged_at)?,
            ..self
        })
    }
}
