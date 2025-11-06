// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{ID, Object};

/// An anonymous viewer
#[derive(Default, Clone, Copy)]
pub struct Anonymous;

#[Object]
impl Anonymous {
    pub async fn id(&self) -> ID {
        "anonymous".into()
    }
}
