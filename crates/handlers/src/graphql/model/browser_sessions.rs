// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{
    Context, Description, ID, Object,
    connection::{Connection, Edge, OpaqueCursor, query},
};
use chrono::{DateTime, Utc};
use mas_data_model::Device;
use mas_storage::{
    Pagination, RepositoryAccess, app_session::AppSessionFilter, user::BrowserSessionRepository,
};

use super::{
    AppSession, CompatSession, Cursor, NodeCursor, NodeType, OAuth2Session, PreloadedTotalCount,
    SessionState, User, UserAgent,
};
use crate::graphql::state::ContextExt;

/// A browser session represents a logged in user in a browser.
#[derive(Description)]
pub struct BrowserSession(pub mas_data_model::BrowserSession);

impl From<mas_data_model::BrowserSession> for BrowserSession {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v)
    }
}

#[Object(use_type_description)]
impl BrowserSession {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::BrowserSession.id(self.0.id)
    }

    /// The user logged in this session.
    async fn user(&self) -> User {
        User(self.0.user.clone())
    }

    /// The most recent authentication of this session.
    async fn last_authentication(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<Authentication>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&self.0)
            .await?;

        repo.cancel().await?;

        Ok(last_authentication.map(Authentication))
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the session was finished.
    pub async fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.0.finished_at
    }

    /// The state of the session.
    pub async fn state(&self) -> SessionState {
        if self.0.finished_at.is_some() {
            SessionState::Finished
        } else {
            SessionState::Active
        }
    }

    /// The user-agent with which the session was created.
    pub async fn user_agent(&self) -> Option<UserAgent> {
        self.0
            .user_agent
            .clone()
            .map(mas_data_model::UserAgent::parse)
            .map(UserAgent::from)
    }

    /// The last IP address used by the session.
    pub async fn last_active_ip(&self) -> Option<String> {
        self.0.last_active_ip.map(|ip| ip.to_string())
    }

    /// The last time the session was active.
    pub async fn last_active_at(&self) -> Option<DateTime<Utc>> {
        self.0.last_active_at
    }

    /// Get the list of both compat and OAuth 2.0 sessions started by this
    /// browser session, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn app_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<SessionState>,

        #[graphql(name = "device", desc = "List only sessions for the given device.")]
        device_param: Option<String>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, AppSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_types(&[NodeType::OAuth2Session, NodeType::CompatSession])
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_types(&[NodeType::OAuth2Session, NodeType::CompatSession])
                    })
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let device_param = device_param.map(Device::try_from).transpose()?;

                let filter = AppSessionFilter::new().for_browser_session(&self.0);

                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match device_param.as_ref() {
                    Some(device) => filter.for_device(device),
                    None => filter,
                };

                let page = repo.app_session().list(filter, pagination).await?;

                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.app_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );

                connection
                    .edges
                    .extend(page.edges.into_iter().map(|edge| match edge.node {
                        mas_storage::app_session::AppSession::Compat(session) => Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::CompatSession, session.id)),
                            AppSession::CompatSession(Box::new(CompatSession::new(*session))),
                        ),
                        mas_storage::app_session::AppSession::OAuth2(session) => Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::OAuth2Session, session.id)),
                            AppSession::OAuth2Session(Box::new(OAuth2Session(*session))),
                        ),
                    }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }
}

/// An authentication records when a user enter their credential in a browser
/// session.
#[derive(Description)]
pub struct Authentication(pub mas_data_model::Authentication);

#[Object(use_type_description)]
impl Authentication {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::Authentication.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }
}
