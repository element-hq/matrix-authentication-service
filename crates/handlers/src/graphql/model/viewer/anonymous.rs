// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Object, ID};

/// An anonymous viewer
#[derive(Default, Clone, Copy)]
pub struct Anonymous;

#[Object]
impl Anonymous {
    pub async fn id(&self) -> ID {
        "anonymous".into()
    }
}
