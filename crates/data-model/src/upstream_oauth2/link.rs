// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UpstreamOAuthLink {
    pub id: Ulid,
    pub provider_id: Ulid,
    pub user_id: Option<Ulid>,
    pub subject: String,
    pub human_account_name: Option<String>,
    pub created_at: DateTime<Utc>,
}
