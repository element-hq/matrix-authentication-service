// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::SimpleObject;
use mas_matrix::HomeserverConnection;

#[derive(SimpleObject)]
pub struct MatrixUser {
    /// The Matrix ID of the user.
    mxid: String,

    /// The display name of the user, if any.
    display_name: Option<String>,

    /// The avatar URL of the user, if any.
    avatar_url: Option<String>,

    /// Whether the user is deactivated on the homeserver.
    deactivated: bool,
}

impl MatrixUser {
    pub(crate) async fn load<C: HomeserverConnection + ?Sized>(
        conn: &C,
        user: &str,
    ) -> Result<MatrixUser, anyhow::Error> {
        let info = conn.query_user(user).await?;

        let mxid = conn.mxid(user);

        Ok(MatrixUser {
            mxid,
            display_name: info.displayname,
            avatar_url: info.avatar_url,
            deactivated: info.deactivated,
        })
    }
}
