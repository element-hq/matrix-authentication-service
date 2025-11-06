// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

pub mod session;

use chrono::{DateTime, Utc};
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersonalAccessToken {
    pub id: Ulid,
    pub session_id: Ulid,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl PersonalAccessToken {
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        if self.revoked_at.is_some() {
            return false;
        }
        if let Some(expires_at) = self.expires_at {
            expires_at > now
        } else {
            true
        }
    }
}
