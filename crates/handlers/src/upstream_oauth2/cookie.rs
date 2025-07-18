// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// TODO: move that to a standalone cookie manager

use chrono::{DateTime, Duration, Utc};
use mas_axum_utils::cookies::CookieJar;
use mas_router::PostAuthAction;
use mas_storage::Clock;
use serde::{Deserialize, Serialize};
use thiserror::Error;
use ulid::Ulid;

/// Name of the cookie
static COOKIE_NAME: &str = "upstream-oauth2-sessions";

/// Sessions expire after 10 minutes
static SESSION_MAX_TIME: Duration = Duration::microseconds(10 * 60 * 1000 * 1000);

#[derive(Serialize, Deserialize, Debug)]
pub struct Payload {
    session: Ulid,
    provider: Ulid,
    state: String,
    link: Option<Ulid>,
    post_auth_action: Option<PostAuthAction>,
}

impl Payload {
    fn expired(&self, now: DateTime<Utc>) -> bool {
        let Ok(ts) = self.session.timestamp_ms().try_into() else {
            return true;
        };
        let Some(when) = DateTime::from_timestamp_millis(ts) else {
            return true;
        };
        now - when > SESSION_MAX_TIME
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
pub struct UpstreamSessions(Vec<Payload>);

#[derive(Debug, Error, PartialEq, Eq)]
#[error("upstream session not found")]
pub struct UpstreamSessionNotFound;

impl UpstreamSessions {
    /// Load the upstreams sessions cookie
    pub fn load(cookie_jar: &CookieJar) -> Self {
        match cookie_jar.load(COOKIE_NAME) {
            Ok(Some(sessions)) => sessions,
            Ok(None) => Self::default(),
            Err(e) => {
                tracing::warn!("Invalid upstream sessions cookie: {}", e);
                Self::default()
            }
        }
    }

    /// Returns true if the cookie is empty
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Save the upstreams sessions to the cookie jar
    pub fn save<C>(self, cookie_jar: CookieJar, clock: &C) -> CookieJar
    where
        C: Clock,
    {
        let this = self.expire(clock.now());
        cookie_jar.save(COOKIE_NAME, &this, false)
    }

    fn expire(mut self, now: DateTime<Utc>) -> Self {
        self.0.retain(|p| !p.expired(now));
        self
    }

    /// Add a new session, for a provider and a random state
    pub fn add(
        mut self,
        session: Ulid,
        provider: Ulid,
        state: String,
        post_auth_action: Option<PostAuthAction>,
    ) -> Self {
        self.0.push(Payload {
            session,
            provider,
            state,
            link: None,
            post_auth_action,
        });
        self
    }

    // Find a session ID from the provider and the state
    pub fn find_session(
        &self,
        provider: Ulid,
        state: &str,
    ) -> Result<(Ulid, Option<&PostAuthAction>), UpstreamSessionNotFound> {
        self.0
            .iter()
            .find(|p| p.provider == provider && p.state == state && p.link.is_none())
            .map(|p| (p.session, p.post_auth_action.as_ref()))
            .ok_or(UpstreamSessionNotFound)
    }

    /// Save the link generated by a session
    pub fn add_link_to_session(
        mut self,
        session: Ulid,
        link: Ulid,
    ) -> Result<Self, UpstreamSessionNotFound> {
        let payload = self
            .0
            .iter_mut()
            .find(|p| p.session == session && p.link.is_none())
            .ok_or(UpstreamSessionNotFound)?;

        payload.link = Some(link);
        Ok(self)
    }

    /// Find a session from its link
    pub fn lookup_link(
        &self,
        link_id: Ulid,
    ) -> Result<(Ulid, Option<&PostAuthAction>), UpstreamSessionNotFound> {
        self.0
            .iter()
            .filter(|p| p.link == Some(link_id))
            // Find the session with the highest ID, aka. the most recent one
            .reduce(|a, b| if a.session > b.session { a } else { b })
            .map(|p| (p.session, p.post_auth_action.as_ref()))
            .ok_or(UpstreamSessionNotFound)
    }

    /// Mark a link as consumed to avoid replay
    pub fn consume_link(mut self, link_id: Ulid) -> Result<Self, UpstreamSessionNotFound> {
        let pos = self
            .0
            .iter()
            .position(|p| p.link == Some(link_id))
            .ok_or(UpstreamSessionNotFound)?;

        self.0.remove(pos);

        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use chrono::TimeZone;
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;

    use super::*;

    #[test]
    fn test_session_cookie() {
        let now = chrono::Utc
            .with_ymd_and_hms(2018, 1, 18, 1, 30, 22)
            .unwrap();
        let mut rng = ChaChaRng::seed_from_u64(42);

        let sessions = UpstreamSessions::default();

        let provider_a = Ulid::from_datetime_with_source(now.into(), &mut rng);
        let provider_b = Ulid::from_datetime_with_source(now.into(), &mut rng);

        let first_session = Ulid::from_datetime_with_source(now.into(), &mut rng);
        let first_state = "first-state";
        let sessions = sessions.add(first_session, provider_a, first_state.into(), None);

        let now = now + Duration::microseconds(5 * 60 * 1000 * 1000);

        let second_session = Ulid::from_datetime_with_source(now.into(), &mut rng);
        let second_state = "second-state";
        let sessions = sessions.add(second_session, provider_b, second_state.into(), None);

        let sessions = sessions.expire(now);
        assert_eq!(
            sessions.find_session(provider_a, first_state).unwrap().0,
            first_session,
        );
        assert_eq!(
            sessions.find_session(provider_b, second_state).unwrap().0,
            second_session
        );
        assert!(sessions.find_session(provider_b, first_state).is_err());
        assert!(sessions.find_session(provider_a, second_state).is_err());

        // Make the first session expire
        let now = now + Duration::microseconds(6 * 60 * 1000 * 1000);
        let sessions = sessions.expire(now);
        assert!(sessions.find_session(provider_a, first_state).is_err());
        assert_eq!(
            sessions.find_session(provider_b, second_state).unwrap().0,
            second_session
        );

        // Associate a link with the second
        let second_link = Ulid::from_datetime_with_source(now.into(), &mut rng);
        let sessions = sessions
            .add_link_to_session(second_session, second_link)
            .unwrap();

        // Now the session can't be found with its state
        assert!(sessions.find_session(provider_b, second_state).is_err());

        // But it can be looked up by its link
        assert_eq!(sessions.lookup_link(second_link).unwrap().0, second_session);
        // And it can be consumed
        let sessions = sessions.consume_link(second_link).unwrap();
        // But only once
        assert!(sessions.consume_link(second_link).is_err());
    }
}
