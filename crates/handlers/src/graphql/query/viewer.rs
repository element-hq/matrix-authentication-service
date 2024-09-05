// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Context, Object};

use crate::graphql::{
    model::{Viewer, ViewerSession},
    state::ContextExt,
    Requester,
};

#[derive(Default)]
pub struct ViewerQuery;

#[Object]
impl ViewerQuery {
    /// Get the viewer
    async fn viewer(&self, ctx: &Context<'_>) -> Viewer {
        let requester = ctx.requester();

        match requester {
            Requester::BrowserSession(session) => Viewer::user(session.user.clone()),
            Requester::OAuth2Session(tuple) => match &tuple.1 {
                Some(user) => Viewer::user(user.clone()),
                None => Viewer::anonymous(),
            },
            Requester::Anonymous => Viewer::anonymous(),
        }
    }

    /// Get the viewer's session
    async fn viewer_session(&self, ctx: &Context<'_>) -> ViewerSession {
        let requester = ctx.requester();

        match requester {
            Requester::BrowserSession(session) => ViewerSession::browser_session(*session.clone()),
            Requester::OAuth2Session(tuple) => ViewerSession::oauth2_session(tuple.0.clone()),
            Requester::Anonymous => ViewerSession::anonymous(),
        }
    }
}
