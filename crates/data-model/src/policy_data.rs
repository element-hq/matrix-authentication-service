// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::{DateTime, Utc};
use serde::Serialize;
use ulid::Ulid;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PolicyData {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub data: serde_json::Value,
}
