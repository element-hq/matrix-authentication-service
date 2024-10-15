// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Enum, InputObject, Object, ID};
use mas_storage::{
    compat::CompatSessionRepository, job::JobRepositoryExt, queue::SyncDevicesJob, RepositoryAccess,
};

use crate::graphql::{
    model::{CompatSession, NodeType},
    state::ContextExt,
};

#[derive(Default)]
pub struct CompatSessionMutations {
    _private: (),
}

/// The input of the `endCompatSession` mutation.
#[derive(InputObject)]
pub struct EndCompatSessionInput {
    /// The ID of the session to end.
    compat_session_id: ID,
}

/// The payload of the `endCompatSession` mutation.
pub enum EndCompatSessionPayload {
    NotFound,
    Ended(Box<mas_data_model::CompatSession>),
}

/// The status of the `endCompatSession` mutation.
#[derive(Enum, Copy, Clone, PartialEq, Eq, Debug)]
enum EndCompatSessionStatus {
    /// The session was ended.
    Ended,

    /// The session was not found.
    NotFound,
}

#[Object]
impl EndCompatSessionPayload {
    /// The status of the mutation.
    async fn status(&self) -> EndCompatSessionStatus {
        match self {
            Self::Ended(_) => EndCompatSessionStatus::Ended,
            Self::NotFound => EndCompatSessionStatus::NotFound,
        }
    }

    /// Returns the ended session.
    async fn compat_session(&self) -> Option<CompatSession> {
        match self {
            Self::Ended(session) => Some(CompatSession::new(*session.clone())),
            Self::NotFound => None,
        }
    }
}

#[Object]
impl CompatSessionMutations {
    async fn end_compat_session(
        &self,
        ctx: &Context<'_>,
        input: EndCompatSessionInput,
    ) -> Result<EndCompatSessionPayload, async_graphql::Error> {
        let state = ctx.state();
        let compat_session_id = NodeType::CompatSession.extract_ulid(&input.compat_session_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let clock = state.clock();

        let session = repo.compat_session().lookup(compat_session_id).await?;
        let Some(session) = session else {
            return Ok(EndCompatSessionPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&session) {
            return Ok(EndCompatSessionPayload::NotFound);
        }

        let user = repo
            .user()
            .lookup(session.user_id)
            .await?
            .context("Could not load user")?;

        // Schedule a job to sync the devices of the user with the homeserver
        repo.job().schedule_job(SyncDevicesJob::new(&user)).await?;

        let session = repo.compat_session().finish(&clock, session).await?;

        repo.save().await?;

        Ok(EndCompatSessionPayload::Ended(Box::new(session)))
    }
}
