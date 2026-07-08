// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{convert::Infallible, net::IpAddr};

use axum::extract::FromRequestParts;
use mas_data_model::{
    BrowserSession, Clock, CompatSession, Session, personal::session::PersonalSession,
};

use crate::{ClientIp, activity_tracker::ActivityTracker};

/// An activity tracker with an IP address bound to it.
#[derive(Clone)]
pub struct Bound {
    tracker: ActivityTracker,
    ip: Option<IpAddr>,
}

impl Bound {
    /// Create a new bound activity tracker.
    #[must_use]
    pub fn new(tracker: ActivityTracker, ip: Option<IpAddr>) -> Self {
        Self { tracker, ip }
    }

    /// Get the IP address bound to this activity tracker.
    #[must_use]
    pub fn ip(&self) -> Option<IpAddr> {
        self.ip
    }

    /// Record activity in an OAuth 2.0 session.
    pub async fn record_oauth2_session(&self, clock: &dyn Clock, session: &Session) {
        self.tracker
            .record_oauth2_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a personal session.
    pub async fn record_personal_session(&self, clock: &dyn Clock, session: &PersonalSession) {
        self.tracker
            .record_personal_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a compatibility session.
    pub async fn record_compat_session(&self, clock: &dyn Clock, session: &CompatSession) {
        self.tracker
            .record_compat_session(clock, session, self.ip)
            .await;
    }

    /// Record activity in a browser session.
    pub async fn record_browser_session(&self, clock: &dyn Clock, session: &BrowserSession) {
        self.tracker
            .record_browser_session(clock, session, self.ip)
            .await;
    }
}

/// Extracts a [`Bound`] activity tracker for any state that can provide an
/// [`ActivityTracker`]. The client IP is read from the [`ClientIp`] request
/// extension (set by the IP-detection middleware), defaulting to `None` when it
/// is absent.
impl<S> FromRequestParts<S> for Bound
where
    S: Send + Sync,
    ActivityTracker: FromRequestParts<S, Rejection = Infallible>,
{
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let ip = parts.extensions.get::<ClientIp>().and_then(|ip| ip.0);
        let tracker = match ActivityTracker::from_request_parts(parts, state).await {
            Ok(tracker) => tracker,
            Err(infallible) => match infallible {},
        };
        Ok(tracker.bind(ip))
    }
}
