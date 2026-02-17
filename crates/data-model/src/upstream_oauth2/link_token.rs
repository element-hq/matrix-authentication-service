// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

/// Stored upstream OAuth access/refresh token pair for a link
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthLinkToken {
    pub id: Ulid,
    pub link_id: Ulid,
    pub encrypted_access_token: String,
    pub encrypted_refresh_token: Option<String>,
    pub access_token_expires_at: Option<DateTime<Utc>>,
    pub token_scope: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl UpstreamOAuthLinkToken {
    /// Whether the access token is expired
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.access_token_expires_at {
            Some(expires_at) => expires_at < now,
            None => false,
        }
    }

    /// Whether a refresh token is available
    #[must_use]
    pub fn has_refresh_token(&self) -> bool {
        self.encrypted_refresh_token.is_some()
    }
}
