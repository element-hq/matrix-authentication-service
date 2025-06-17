// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{Context, Object};

use crate::graphql::{
    model::{Viewer, ViewerSession},
    state::ContextExt,
};

#[derive(Default)]
pub struct ViewerQuery;

#[Object]
impl ViewerQuery {
    /// Get the viewer
    async fn viewer(&self, ctx: &Context<'_>) -> Viewer {
        let requester = ctx.requester();

        if let Some(user) = requester.user() {
            return Viewer::user(user.clone());
        }

        Viewer::anonymous()
    }

    /// Get the viewer's session
    async fn viewer_session(&self, ctx: &Context<'_>) -> ViewerSession {
        let requester = ctx.requester();

        if let Some(session) = requester.browser_session() {
            return ViewerSession::browser_session(session.clone());
        }

        if let Some(session) = requester.oauth2_session() {
            return ViewerSession::oauth2_session(session.clone());
        }

        ViewerSession::anonymous()
    }
}
