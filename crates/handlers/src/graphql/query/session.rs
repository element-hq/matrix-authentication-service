// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{Context, ID, Object, Union};
use mas_data_model::Device;
use mas_storage::{
    Pagination, RepositoryAccess,
    compat::{CompatSessionFilter, CompatSessionRepository},
    oauth2::OAuth2SessionFilter,
};
use oauth2_types::scope::Scope;

use crate::graphql::{
    UserId,
    model::{CompatSession, NodeType, OAuth2Session},
    state::ContextExt,
};

#[derive(Default)]
pub struct SessionQuery;

/// A client session, either compat or OAuth 2.0
#[derive(Union)]
enum Session {
    CompatSession(Box<CompatSession>),
    OAuth2Session(Box<OAuth2Session>),
}

#[Object]
impl SessionQuery {
    /// Lookup a compat or OAuth 2.0 session
    async fn session(
        &self,
        ctx: &Context<'_>,
        user_id: ID,
        device_id: String,
    ) -> Result<Option<Session>, async_graphql::Error> {
        let user_id = NodeType::User.extract_ulid(&user_id)?;
        let requester = ctx.requester();
        if !requester.is_owner_or_admin(&UserId(user_id)) {
            return Ok(None);
        }

        let device = Device::from(device_id);
        let state = ctx.state();
        let mut repo = state.repository().await?;

        // Lookup the user
        let Some(user) = repo.user().lookup(user_id).await? else {
            return Ok(None);
        };

        // First, try to find a compat session
        let filter = CompatSessionFilter::new()
            .for_user(&user)
            .active_only()
            .for_device(&device);
        // We only want most recent session
        let pagination = Pagination::last(1);
        let compat_sessions = repo.compat_session().list(filter, pagination).await?;

        if compat_sessions.has_previous_page {
            // XXX: should we bail out?
            tracing::warn!(
                "Found more than one active session with device {device} for user {user_id}"
            );
        }

        if let Some((compat_session, sso_login)) = compat_sessions.edges.into_iter().next() {
            repo.cancel().await?;

            return Ok(Some(Session::CompatSession(Box::new(
                CompatSession::new(compat_session).with_loaded_sso_login(sso_login),
            ))));
        }

        // Then, try to find an OAuth 2.0 session. Because we don't have any dedicated
        // device column, we're looking up using the device scope.
        // All device IDs can't necessarily be encoded as a scope. If it's not the case,
        // we'll skip looking for OAuth 2.0 sessions.
        let Ok(scope_token) = device.to_scope_token() else {
            repo.cancel().await?;

            return Ok(None);
        };
        let scope = Scope::from_iter([scope_token]);
        let filter = OAuth2SessionFilter::new()
            .for_user(&user)
            .active_only()
            .with_scope(&scope);
        let sessions = repo.oauth2_session().list(filter, pagination).await?;

        // It's possible to have multiple active OAuth 2.0 sessions. For now, we just
        // log it if it is the case
        if sessions.has_previous_page {
            // XXX: should we bail out?
            tracing::warn!(
                "Found more than one active session with device {device} for user {user_id}"
            );
        }

        if let Some(session) = sessions.edges.into_iter().next() {
            repo.cancel().await?;
            return Ok(Some(Session::OAuth2Session(Box::new(OAuth2Session(
                session,
            )))));
        }
        repo.cancel().await?;

        Ok(None)
    }
}
