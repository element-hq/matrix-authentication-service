// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// TODO: move that to a standalone cookie manager

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use mas_axum_utils::cookies::CookieJar;
use mas_data_model::UserRegistration;
use mas_storage::Clock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Name of the cookie
static COOKIE_NAME: &str = "user-registration-sessions";

/// Sessions expire after an hour
static SESSION_MAX_TIME: Duration = Duration::hours(1);

/// The content of the cookie, which stores a list of user registration IDs
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct UserRegistrationSessions(BTreeSet<Ulid>);

#[derive(Debug, Error, PartialEq, Eq)]
#[error("user registration session not found")]
pub struct UserRegistrationSessionNotFound;

impl UserRegistrationSessions {
    /// Load the user registration sessions cookie
    pub fn load(cookie_jar: &CookieJar) -> Self {
        match cookie_jar.load(COOKIE_NAME) {
            Ok(Some(sessions)) => sessions,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "Invalid upstream sessions cookie"
                );
                Self::default()
            }
        }
    }

    /// Returns true if the cookie is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Save the user registration sessions to the cookie jar
    pub fn save<C>(self, cookie_jar: CookieJar, clock: &C) -> CookieJar
    where
        C: Clock,
    {
        let this = self.expire(clock.now());

        if this.is_empty() {
            cookie_jar.remove(COOKIE_NAME)
        } else {
            cookie_jar.save(COOKIE_NAME, &this, false)
        }
    }

    fn expire(mut self, now: DateTime<Utc>) -> Self {
        self.0.retain(|id| {
            let Ok(ts) = id.timestamp_ms().try_into() else {
                return false;
            };
            let Some(when) = DateTime::from_timestamp_millis(ts) else {
                return false;
            };
            now - when < SESSION_MAX_TIME
        });

        self
    }

    /// Add a new session, for a provider and a random state
    pub fn add(mut self, user_registration: &UserRegistration) -> Self {
        self.0.insert(user_registration.id);
        self
    }

    /// Check if the session is in the list
    pub fn contains(&self, user_registration: &UserRegistration) -> bool {
        self.0.contains(&user_registration.id)
    }

    /// Mark a link as consumed to avoid replay
    pub fn consume_session(
        mut self,
        user_registration: &UserRegistration,
    ) -> Result<Self, UserRegistrationSessionNotFound> {
        if !self.0.remove(&user_registration.id) {
            return Err(UserRegistrationSessionNotFound);
        }

        Ok(self)
    }
}
