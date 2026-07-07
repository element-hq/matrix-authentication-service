// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use mas_data_model::BrowserSession;
use mas_storage::RepositoryAccess;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{cookies::CookieJar, log_context::RecordAsRequester};

/// An encrypted cookie to save the session ID
#[derive(Serialize, Deserialize, Debug, Default, Clone)]
pub struct SessionInfo {
    current: Option<Ulid>,

    /// When the browser was last signed out, if it was.
    ///
    /// This is set when the session cookie is cleared (either through an
    /// explicit logout, or because the session was ended out from under the
    /// user), and is cleared again whenever a new session is established, since
    /// [`SessionInfo::from_session`] leaves it unset. It lets us tell that the
    /// current, anonymous browser used to be signed in — which is used to force
    /// a fresh prompt at the upstream provider on the next login.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    logged_out_at: Option<DateTime<Utc>>,
}

impl SessionInfo {
    /// Forge the cookie from a [`BrowserSession`]
    #[must_use]
    pub fn from_session(session: &BrowserSession) -> Self {
        Self {
            current: Some(session.id),
            logged_out_at: None,
        }
    }

    /// Mark the session as ended
    #[must_use]
    pub fn mark_session_ended(mut self, now: DateTime<Utc>) -> Self {
        self.current = None;
        self.logged_out_at = Some(now);
        self
    }

    /// Load the active [`BrowserSession`] from database
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying repository fails to load the session.
    pub async fn load_active_session<E>(
        &self,
        repo: &mut impl RepositoryAccess<Error = E>,
    ) -> Result<Option<BrowserSession>, E> {
        let Some(session_id) = self.current else {
            return Ok(None);
        };

        let maybe_session = repo
            .browser_session()
            .lookup(session_id)
            .await?
            // Ensure that the session is still active
            .filter(BrowserSession::active);

        if let Some(session) = &maybe_session {
            session.maybe_record_as_requester();
        }

        Ok(maybe_session)
    }

    /// Get the current session ID, if any
    #[must_use]
    pub fn current_session_id(&self) -> Option<Ulid> {
        self.current
    }

    /// Get the time at which the browser was last signed out, if it currently
    /// has no active session.
    ///
    /// Returns [`None`] if the browser has never been signed out or has since
    /// signed back in.
    #[must_use]
    pub fn logged_out_at(&self) -> Option<DateTime<Utc>> {
        self.logged_out_at
    }
}

pub trait SessionInfoExt {
    #[must_use]
    fn session_info(self) -> (SessionInfo, Self);

    #[must_use]
    fn update_session_info(self, info: &SessionInfo) -> Self;

    #[must_use]
    fn set_session(self, session: &BrowserSession) -> Self
    where
        Self: Sized,
    {
        let session_info = SessionInfo::from_session(session);
        self.update_session_info(&session_info)
    }
}

impl SessionInfoExt for CookieJar {
    fn session_info(self) -> (SessionInfo, Self) {
        let info = match self.load("session") {
            Ok(Some(s)) => s,
            Ok(None) => SessionInfo::default(),
            Err(e) => {
                tracing::error!("failed to load session cookie: {}", e);
                SessionInfo::default()
            }
        };

        let jar = self.update_session_info(&info);
        (info, jar)
    }

    fn update_session_info(self, info: &SessionInfo) -> Self {
        self.save("session", info, true)
    }
}
