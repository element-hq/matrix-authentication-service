// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::{net::IpAddr, ops::Deref};

use chrono::{DateTime, Duration, Utc};
use rand::{Rng, SeedableRng};
use serde::Serialize;
use ulid::Ulid;

use crate::UserAgent;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: Ulid,
    pub username: String,
    pub sub: String,
    pub primary_user_email_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
}

impl User {
    /// Returns `true` unless the user is locked.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.locked_at.is_none()
    }
}

impl User {
    #[doc(hidden)]
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        vec![User {
            id: Ulid::from_datetime_with_source(now.into(), rng),
            username: "john".to_owned(),
            sub: "123-456".to_owned(),
            primary_user_email_id: None,
            created_at: now,
            locked_at: None,
            can_request_admin: false,
        }]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Password {
    pub id: Ulid,
    pub hashed_password: String,
    pub version: u16,
    pub upgraded_from_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub authentication_method: AuthenticationMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AuthenticationMethod {
    Password { user_password_id: Ulid },
    UpstreamOAuth2 { upstream_oauth2_session_id: Ulid },
    Unknown,
}

/// A session to recover a user if they have lost their credentials
///
/// For each session intiated, there may be multiple [`UserRecoveryTicket`]s
/// sent to the user, either because multiple [`User`] have the same email
/// address, or because the user asked to send the recovery email again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoverySession {
    pub id: Ulid,
    pub email: String,
    pub user_agent: UserAgent,
    pub ip_address: Option<IpAddr>,
    pub locale: String,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// A single recovery ticket for a user recovery session
///
/// Whenever a new recovery session is initiated, a new ticket is created for
/// each email address matching in the database. That ticket is sent by email,
/// as a link that the user can click to recover their account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoveryTicket {
    pub id: Ulid,
    pub user_recovery_session_id: Ulid,
    pub user_email_id: Ulid,
    pub ticket: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl UserRecoveryTicket {
    #[must_use]
    pub fn active(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserSession {
    pub id: Ulid,
    pub user: User,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub user_agent: Option<UserAgent>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl BrowserSession {
    #[must_use]
    pub fn active(&self) -> bool {
        self.finished_at.is_none() && self.user.is_valid()
    }
}

impl BrowserSession {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        User::samples(now, rng)
            .into_iter()
            .map(|user| BrowserSession {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                user,
                created_at: now,
                finished_at: None,
                user_agent: Some(UserAgent::parse(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()
                )),
                last_active_at: Some(now),
                last_active_ip: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmail {
    pub id: Ulid,
    pub user_id: Ulid,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub confirmed_at: Option<DateTime<Utc>>,
}

impl UserEmail {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        vec![
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                user_id: Ulid::from_datetime_with_source(now.into(), rng),
                email: "alice@example.com".to_owned(),
                created_at: now,
                confirmed_at: Some(now),
            },
            Self {
                id: Ulid::from_datetime_with_source(now.into(), rng),
                user_id: Ulid::from_datetime_with_source(now.into(), rng),
                email: "bob@example.com".to_owned(),
                created_at: now,
                confirmed_at: None,
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum UserEmailVerificationState {
    AlreadyUsed { when: DateTime<Utc> },
    Expired { when: DateTime<Utc> },
    Valid,
}

impl UserEmailVerificationState {
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailVerification {
    pub id: Ulid,
    pub user_email_id: Ulid,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub state: UserEmailVerificationState,
}

impl Deref for UserEmailVerification {
    type Target = UserEmailVerificationState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl UserEmailVerification {
    #[doc(hidden)]
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl Rng) -> Vec<Self> {
        let states = [
            UserEmailVerificationState::AlreadyUsed {
                when: now - Duration::microseconds(5 * 60 * 1000 * 1000),
            },
            UserEmailVerificationState::Expired {
                when: now - Duration::microseconds(5 * 60 * 1000 * 1000),
            },
            UserEmailVerificationState::Valid,
        ];

        states
            .into_iter()
            .flat_map(move |state| {
                let mut rng =
                    rand_chacha::ChaChaRng::from_rng(&mut *rng).expect("could not seed rng");
                UserEmail::samples(now, &mut rng)
                    .into_iter()
                    .map(move |email| Self {
                        id: Ulid::from_datetime_with_source(now.into(), &mut rng),
                        user_email_id: email.id,
                        code: "123456".to_owned(),
                        created_at: now - Duration::microseconds(10 * 60 * 1000 * 1000),
                        state: state.clone(),
                    })
            })
            .collect()
    }
}
