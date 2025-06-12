// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::connection::OpaqueCursor;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

pub use super::NodeType;

#[derive(Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeCursor(pub NodeType, pub Ulid);

impl NodeCursor {
    pub fn extract_for_types(&self, node_types: &[NodeType]) -> Result<Ulid, async_graphql::Error> {
        if node_types.contains(&self.0) {
            Ok(self.1)
        } else {
            Err(async_graphql::Error::new("invalid cursor"))
        }
    }

    pub fn extract_for_type(&self, node_type: NodeType) -> Result<Ulid, async_graphql::Error> {
        if self.0 == node_type {
            Ok(self.1)
        } else {
            Err(async_graphql::Error::new("invalid cursor"))
        }
    }
}

pub type Cursor = OpaqueCursor<NodeCursor>;
