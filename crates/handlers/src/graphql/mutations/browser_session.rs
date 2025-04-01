// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_graphql::{Context, Enum, ID, InputObject, Object};
use mas_storage::RepositoryAccess;

use crate::graphql::{
    model::{BrowserSession, NodeType},
    state::ContextExt,
};

#[derive(Default)]
pub struct BrowserSessionMutations {
    _private: (),
}

/// The input of the `endBrowserSession` mutation.
#[derive(InputObject)]
pub struct EndBrowserSessionInput {
    /// The ID of the session to end.
    browser_session_id: ID,
}

/// The payload of the `endBrowserSession` mutation.
pub enum EndBrowserSessionPayload {
    NotFound,
    Ended(Box<mas_data_model::BrowserSession>),
}

/// The status of the `endBrowserSession` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndBrowserSessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndBrowserSessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndBrowserSessionStatus {
        match self {
            Self::Ended(_) => EndBrowserSessionStatus::Ended,
            Self::NotFound => EndBrowserSessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn browser_session(&self) -> Option<BrowserSession> {
        match self {
            Self::Ended(session) => Some(BrowserSession(*session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl BrowserSessionMutations {
    async fn end_browser_session(
        &self,
        ctx: &Context<'_>,
        input: EndBrowserSessionInput,
    ) -> Result<EndBrowserSessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let browser_session_id =
            NodeType::BrowserSession.extract_ulid(&input.browser_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let clock = state.clock();

        let session = repo.browser_session().lookup(browser_session_id).await?;

        let Some(session) = session else {
            return Ok(EndBrowserSessionPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(EndBrowserSessionPayload::NotFound);
        }

        let session = repo.browser_session().finish(&clock, session).await?;

        repo.save().await?;

        // If we are ending the *current* session, we need to clear the session cookie
        // as well
        if requester
            .browser_session()
            .is_some_and(|s| s.id == session.id)
        {
            ctx.mark_session_ended();
        }

        Ok(EndBrowserSessionPayload::Ended(Box::new(session)))
    }
}
