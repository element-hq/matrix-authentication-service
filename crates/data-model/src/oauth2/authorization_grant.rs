// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr as _;

use chrono::{DateTime, Utc};
use mas_iana::oauth::PkceCodeChallengeMethod;
use oauth2_types::{
    pkce::{CodeChallengeError, CodeChallengeMethodExt},
    requests::ResponseMode,
    scope::{OPENID, PROFILE, Scope},
};
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};
use ruma_common::UserId;
use serde::Serialize;
use ulid::Ulid;
use url::Url;

use super::session::Session;
use crate::{BrowserSession, InvalidTransitionError};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Pkce {
    pub challenge_method: PkceCodeChallengeMethod,
    pub challenge: String,
}

impl Pkce {
    /// Create a new PKCE challenge, with the given method and challenge.
    #[must_use]
    pub fn new(challenge_method: PkceCodeChallengeMethod, challenge: String) -> Self {
        Pkce {
            challenge_method,
            challenge,
        }
    }

    /// Verify the PKCE challenge.
    ///
    /// # Errors
    ///
    /// Returns an error if the verifier is invalid.
    pub fn verify(&self, verifier: &str) -> Result<(), CodeChallengeError> {
        self.challenge_method.verify(&self.challenge, verifier)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationCode {
    pub code: String,
    pub pkce: Option<Pkce>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Default)]
#[serde(tag = "stage", rename_all = "lowercase")]
pub enum AuthorizationGrantStage {
    #[default]
    Pending,
    Fulfilled {
        browser_session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
    },
    Exchanged {
        session_id: Ulid,
        browser_session_id: Ulid,
        fulfilled_at: DateTime<Utc>,
        exchanged_at: DateTime<Utc>,
    },
    Cancelled {
        cancelled_at: DateTime<Utc>,
    },
}

impl AuthorizationGrantStage {
    #[must_use]
    pub fn new() -> Self {
        Self::Pending
    }

    fn fulfill(
        self,
        fulfilled_at: DateTime<Utc>,
        browser_session: &BrowserSession,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Fulfilled {
                fulfilled_at,
                browser_session_id: browser_session.id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    fn exchange(
        self,
        exchanged_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Fulfilled {
                fulfilled_at,
                browser_session_id,
            } => Ok(Self::Exchanged {
                fulfilled_at,
                exchanged_at,
                session_id: session.id,
                browser_session_id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    fn cancel(self, cancelled_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Pending => Ok(Self::Cancelled { cancelled_at }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the authorization grant stage is [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the authorization grant stage is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the authorization grant stage is [`Exchanged`].
    ///
    /// [`Exchanged`]: AuthorizationGrantStage::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }
}

pub enum LoginHint<'a> {
    MXID(&'a UserId),
    Email(lettre::Address),
    None,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuthorizationGrant {
    pub id: Ulid,
    #[serde(flatten)]
    pub stage: AuthorizationGrantStage,
    pub code: Option<AuthorizationCode>,
    pub client_id: Ulid,
    pub redirect_uri: Url,
    pub scope: Scope,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub response_mode: ResponseMode,
    pub response_type_id_token: bool,
    pub created_at: DateTime<Utc>,
    pub login_hint: Option<String>,
    pub locale: Option<String>,
}

impl std::ops::Deref for AuthorizationGrant {
    type Target = AuthorizationGrantStage;

    fn deref(&self) -> &Self::Target {
        &self.stage
    }
}

impl AuthorizationGrant {
    /// Parse a `login_hint`
    ///
    /// Returns `LoginHint::MXID` for valid mxid 'mxid:@john.doe:example.com'
    ///
    /// Returns `LoginHint::Email` for valid email 'john.doe@example.com'
    ///
    /// Otherwise returns `LoginHint::None`
    #[must_use]
    pub fn parse_login_hint(&self, homeserver: &str) -> LoginHint<'_> {
        let Some(login_hint) = &self.login_hint else {
            return LoginHint::None;
        };

        if let Some(value) = login_hint.strip_prefix("mxid:")
            && let Ok(mxid) = <&UserId>::try_from(value)
            && mxid.server_name() == homeserver
        {
            LoginHint::MXID(mxid)
        } else if let Ok(email) = lettre::Address::from_str(login_hint) {
            LoginHint::Email(email)
        } else {
            LoginHint::None
        }
    }

    /// Mark the authorization grant as exchanged.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Fulfilled`].
    ///
    /// [`Fulfilled`]: AuthorizationGrantStage::Fulfilled
    pub fn exchange(
        mut self,
        exchanged_at: DateTime<Utc>,
        session: &Session,
    ) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.exchange(exchanged_at, session)?;
        Ok(self)
    }

    /// Mark the authorization grant as fulfilled.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    pub fn fulfill(
        mut self,
        fulfilled_at: DateTime<Utc>,
        browser_session: &BrowserSession,
    ) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.fulfill(fulfilled_at, browser_session)?;
        Ok(self)
    }

    /// Mark the authorization grant as cancelled.
    ///
    /// # Errors
    ///
    /// Returns an error if the authorization grant is not [`Pending`].
    ///
    /// [`Pending`]: AuthorizationGrantStage::Pending
    ///
    /// # TODO
    ///
    /// This appears to be unused
    pub fn cancel(mut self, canceld_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.stage = self.stage.cancel(canceld_at)?;
        Ok(self)
    }

    #[doc(hidden)]
    pub fn sample(now: DateTime<Utc>, rng: &mut impl RngCore) -> Self {
        Self {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            stage: AuthorizationGrantStage::Pending,
            code: Some(AuthorizationCode {
                code: Alphanumeric.sample_string(rng, 10),
                pkce: None,
            }),
            client_id: Ulid::from_datetime_with_source(now.into(), rng),
            redirect_uri: Url::parse("http://localhost:8080").unwrap(),
            scope: Scope::from_iter([OPENID, PROFILE]),
            state: Some(Alphanumeric.sample_string(rng, 10)),
            nonce: Some(Alphanumeric.sample_string(rng, 10)),
            response_mode: ResponseMode::Query,
            response_type_id_token: false,
            created_at: now,
            login_hint: Some(String::from("mxid:@example-user:example.com")),
            locale: Some(String::from("fr")),
        }
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::clock::{Clock, MockClock};

    #[test]
    fn no_login_hint() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: None,
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn valid_login_hint() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("mxid:@example-user:example.com")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::MXID(mxid) if mxid.localpart() == "example-user"));
    }

    #[test]
    fn valid_login_hint_with_email() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("example@user")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::Email(email) if email.to_string() == "example@user"));
    }

    #[test]
    fn invalid_login_hint() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("example-user")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn valid_login_hint_for_wrong_homeserver() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("mxid:@example-user:matrix.org")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn unknown_login_hint_type() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let grant = AuthorizationGrant {
            login_hint: Some(String::from("something:anything")),
            ..AuthorizationGrant::sample(now, &mut rng)
        };

        let hint = grant.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }
}
