// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::BTreeSet;

use chrono::{DateTime, Duration, Utc};
use mas_axum_utils::cookies::CookieJar;
use mas_data_model::{Clock, UserPasskeyChallenge};
use serde::{Deserialize, Serialize};
use ulid::Ulid;

/// Name of the cookie
static COOKIE_NAME: &str = "user-passkey-challenges";

/// Sessions expire after an hour
static SESSION_MAX_TIME: Duration = Duration::hours(1);

/// The content of the cookie, which stores a list of user passkey challenge IDs
#[derive(Serialize, Deserialize, Default, Debug)]
pub struct UserPasskeyChallenges(BTreeSet<Ulid>);

impl UserPasskeyChallenges {
    /// Load the user passkey challenges cookie
    pub fn load(cookie_jar: &CookieJar) -> Self {
        match cookie_jar.load(COOKIE_NAME) {
            Ok(Some(challenges)) => challenges,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "Invalid passkey challenges cookie"
                );
                Self::default()
            }
        }
    }

    /// Returns true if the cookie is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Save the user passkey challenges to the cookie jar
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

    /// Add a new challenge
    pub fn add(mut self, passkey_challenge: &UserPasskeyChallenge) -> Self {
        self.0.insert(passkey_challenge.id);
        self
    }

    /// Check if the challenge is in the list
    pub fn contains(&self, passkey_challenge_id: &Ulid) -> bool {
        self.0.contains(passkey_challenge_id)
    }

    /// Mark a challenge as consumed to avoid replay
    pub fn consume_challenge(mut self, passkey_challenge_id: &Ulid) -> Self {
        self.0.remove(passkey_challenge_id);
        self
    }
}
