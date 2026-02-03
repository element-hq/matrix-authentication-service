// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{
    Context, Description, Enum, ID, Object, Union,
    connection::{Connection, Edge, OpaqueCursor, query},
};
use chrono::{DateTime, Utc};
use mas_data_model::Device;
use mas_storage::{
    Pagination, RepositoryAccess,
    app_session::AppSessionFilter,
    compat::{CompatSessionFilter, CompatSsoLoginFilter, CompatSsoLoginRepository},
    oauth2::{OAuth2SessionFilter, OAuth2SessionRepository},
    upstream_oauth2::{UpstreamOAuthLinkFilter, UpstreamOAuthLinkRepository},
    user::{
        BrowserSessionFilter, BrowserSessionRepository, UserEmailFilter, UserEmailRepository,
        UserPasskeyFilter,
    },
};
use webauthn_rp::{
    bin::Decode,
    response::register::bin::{AaguidOwned, MetadataOwned},
};

use super::{
    BrowserSession, CompatSession, Cursor, NodeCursor, NodeType, OAuth2Session,
    PreloadedTotalCount, SessionState, UpstreamOAuth2Link,
    compat_sessions::{CompatSessionType, CompatSsoLogin},
    matrix::MatrixUser,
};
use crate::graphql::{DateFilter, state::ContextExt};

#[derive(Description)]
/// A user is an individual's account.
pub struct User(pub mas_data_model::User);

impl From<mas_data_model::User> for User {
    fn from(v: mas_data_model::User) -> Self {
        Self(v)
    }
}

impl From<mas_data_model::BrowserSession> for User {
    fn from(v: mas_data_model::BrowserSession) -> Self {
        Self(v.user)
    }
}

#[Object(use_type_description)]
impl User {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::User.id(self.0.id)
    }

    /// Username chosen by the user.
    async fn username(&self) -> &str {
        &self.0.username
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the user was locked out.
    pub async fn locked_at(&self) -> Option<DateTime<Utc>> {
        self.0.locked_at
    }

    /// Whether the user can request admin privileges.
    pub async fn can_request_admin(&self) -> bool {
        self.0.can_request_admin
    }

    /// Access to the user's Matrix account information.
    async fn matrix(&self, ctx: &Context<'_>) -> Result<MatrixUser, async_graphql::Error> {
        let state = ctx.state();
        let conn = state.homeserver_connection();
        Ok(MatrixUser::load(conn, &self.0.username).await?)
    }

    /// Get the list of compatibility SSO logins, chronologically sorted
    async fn compat_sso_logins(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, CompatSsoLogin, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSsoLogin))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = CompatSsoLoginFilter::new().for_user(&self.0);

                let page = repo.compat_sso_login().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.compat_sso_login().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::CompatSsoLogin, edge.cursor)),
                        CompatSsoLogin(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of compatibility sessions, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn compat_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions with the given state.")]
        state_param: Option<SessionState>,

        #[graphql(name = "type", desc = "List only sessions with the given type.")]
        type_param: Option<CompatSessionType>,

        #[graphql(
            name = "lastActive",
            desc = "List only sessions with a last active time is between the given bounds."
        )]
        last_active: Option<DateFilter>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, CompatSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let last_active = last_active.unwrap_or_default();

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSession))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::CompatSession))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                // Build the query filter
                let filter = CompatSessionFilter::new().for_user(&self.0);
                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };
                let filter = match type_param {
                    Some(CompatSessionType::SsoLogin) => filter.sso_login_only(),
                    Some(CompatSessionType::Unknown) => filter.unknown_only(),
                    None => filter,
                };

                let filter = match last_active.after {
                    Some(after) => filter.with_last_active_after(after),
                    None => filter,
                };
                let filter = match last_active.before {
                    Some(before) => filter.with_last_active_before(before),
                    None => filter,
                };

                let page = repo.compat_session().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.compat_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    let (session, sso_login) = edge.node;
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::CompatSession, session.id)),
                        CompatSession::new(session).with_loaded_sso_login(sso_login),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of active browser sessions, chronologically sorted
    async fn browser_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<SessionState>,

        #[graphql(
            name = "lastActive",
            desc = "List only sessions with a last active time is between the given bounds."
        )]
        last_active: Option<DateFilter>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, BrowserSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let last_active = last_active.unwrap_or_default();

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::BrowserSession))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = BrowserSessionFilter::new().for_user(&self.0);
                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match last_active.after {
                    Some(after) => filter.with_last_active_after(after),
                    None => filter,
                };
                let filter = match last_active.before {
                    Some(before) => filter.with_last_active_before(before),
                    None => filter,
                };

                let page = repo.browser_session().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.browser_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::BrowserSession, edge.cursor)),
                        BrowserSession(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of emails, chronologically sorted
    async fn emails(
        &self,
        ctx: &Context<'_>,

        #[graphql(
            deprecation = "Emails are always confirmed, and have only one state",
            name = "state",
            desc = "List only emails in the given state."
        )]
        state_param: Option<UserEmailState>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UserEmail, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let _ = state_param;

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserEmail))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = UserEmailFilter::new().for_user(&self.0);

                let page = repo.user_email().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.user_email().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UserEmail, edge.cursor)),
                        UserEmail(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of OAuth 2.0 sessions, chronologically sorted
    #[allow(clippy::too_many_arguments)]
    async fn oauth2_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<SessionState>,

        #[graphql(desc = "List only sessions for the given client.")] client: Option<ID>,

        #[graphql(
            name = "lastActive",
            desc = "List only sessions with a last active time is between the given bounds."
        )]
        last_active: Option<DateFilter>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, OAuth2Session, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let last_active = last_active.unwrap_or_default();

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::OAuth2Session))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let client = if let Some(id) = client {
                    // Load the client if we're filtering by it
                    let id = NodeType::OAuth2Client.extract_ulid(&id)?;
                    let client = repo
                        .oauth2_client()
                        .lookup(id)
                        .await?
                        .ok_or(async_graphql::Error::new("Unknown client ID"))?;

                    Some(client)
                } else {
                    None
                };

                let filter = OAuth2SessionFilter::new().for_user(&self.0);

                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match client.as_ref() {
                    Some(client) => filter.for_client(client),
                    None => filter,
                };

                let filter = match last_active.after {
                    Some(after) => filter.with_last_active_after(after),
                    None => filter,
                };
                let filter = match last_active.before {
                    Some(before) => filter.with_last_active_before(before),
                    None => filter,
                };

                let page = repo.oauth2_session().list(filter, pagination).await?;

                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.oauth2_session().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );

                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::OAuth2Session, edge.cursor)),
                        OAuth2Session(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of upstream OAuth 2.0 links
    async fn upstream_oauth2_links(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UpstreamOAuth2Link, PreloadedTotalCount>, async_graphql::Error>
    {
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
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| {
                        x.extract_for_type(NodeType::UpstreamOAuth2Link)
                    })
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = UpstreamOAuthLinkFilter::new()
                    .for_user(&self.0)
                    .enabled_providers_only();

                let page = repo.upstream_oauth_link().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.upstream_oauth_link().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|edge| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UpstreamOAuth2Link, edge.cursor)),
                        UpstreamOAuth2Link::new(edge.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of both compat and OAuth 2.0 sessions, chronologically
    /// sorted
    #[allow(clippy::too_many_arguments)]
    async fn app_sessions(
        &self,
        ctx: &Context<'_>,

        #[graphql(name = "state", desc = "List only sessions in the given state.")]
        state_param: Option<SessionState>,

        #[graphql(name = "device", desc = "List only sessions for the given device.")]
        device_param: Option<String>,

        #[graphql(
            name = "lastActive",
            desc = "List only sessions with a last active time is between the given bounds."
        )]
        last_active: Option<DateFilter>,

        #[graphql(
            name = "browserSession",
            desc = "List only sessions for the given session."
        )]
        browser_session_param: Option<ID>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, AppSession, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let requester = ctx.requester();
        let mut repo = state.repository().await?;
        let last_active = last_active.unwrap_or_default();

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

                let filter = AppSessionFilter::new().for_user(&self.0);

                let filter = match state_param {
                    Some(SessionState::Active) => filter.active_only(),
                    Some(SessionState::Finished) => filter.finished_only(),
                    None => filter,
                };

                let filter = match device_param.as_ref() {
                    Some(device) => filter.for_device(device),
                    None => filter,
                };

                let maybe_session = match browser_session_param {
                    Some(id) => {
                        // This might fail, but we're probably alright with it
                        let id = NodeType::BrowserSession
                            .extract_ulid(&id)
                            .context("Invalid browser_session parameter")?;

                        let Some(session) = repo
                            .browser_session()
                            .lookup(id)
                            .await?
                            .filter(|u| requester.is_owner_or_admin(u))
                        else {
                            // If we couldn't find the session or if the requester can't access it,
                            // return an empty list
                            return Ok(Connection::with_additional_fields(
                                false,
                                false,
                                PreloadedTotalCount(Some(0)),
                            ));
                        };

                        Some(session)
                    }
                    None => None,
                };

                let filter = match maybe_session {
                    Some(ref session) => filter.for_browser_session(session),
                    None => filter,
                };

                let filter = match last_active.after {
                    Some(after) => filter.with_last_active_after(after),
                    None => filter,
                };
                let filter = match last_active.before {
                    Some(before) => filter.with_last_active_before(before),
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
                            OpaqueCursor(NodeCursor(NodeType::CompatSession, edge.cursor)),
                            AppSession::CompatSession(Box::new(CompatSession::new(*session))),
                        ),
                        mas_storage::app_session::AppSession::OAuth2(session) => Edge::new(
                            OpaqueCursor(NodeCursor(NodeType::OAuth2Session, edge.cursor)),
                            AppSession::OAuth2Session(Box::new(OAuth2Session(*session))),
                        ),
                    }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Get the list of passkeys, chronologically sorted
    async fn passkeys(
        &self,
        ctx: &Context<'_>,

        #[graphql(desc = "Returns the elements in the list that come after the cursor.")]
        after: Option<String>,
        #[graphql(desc = "Returns the elements in the list that come before the cursor.")]
        before: Option<String>,
        #[graphql(desc = "Returns the first *n* elements from the list.")] first: Option<i32>,
        #[graphql(desc = "Returns the last *n* elements from the list.")] last: Option<i32>,
    ) -> Result<Connection<Cursor, UserPasskey, PreloadedTotalCount>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        query(
            after,
            before,
            first,
            last,
            async |after, before, first, last| {
                let after_id = after
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserPasskey))
                    .transpose()?;
                let before_id = before
                    .map(|x: OpaqueCursor<NodeCursor>| x.extract_for_type(NodeType::UserPasskey))
                    .transpose()?;
                let pagination = Pagination::try_new(before_id, after_id, first, last)?;

                let filter = UserPasskeyFilter::new().for_user(&self.0);

                let page = repo.user_passkey().list(filter, pagination).await?;

                // Preload the total count if requested
                let count = if ctx.look_ahead().field("totalCount").exists() {
                    Some(repo.user_passkey().count(filter).await?)
                } else {
                    None
                };

                repo.cancel().await?;

                let mut connection = Connection::with_additional_fields(
                    page.has_previous_page,
                    page.has_next_page,
                    PreloadedTotalCount(count),
                );
                connection.edges.extend(page.edges.into_iter().map(|u| {
                    Edge::new(
                        OpaqueCursor(NodeCursor(NodeType::UserPasskey, u.cursor)),
                        UserPasskey(u.node),
                    )
                }));

                Ok::<_, async_graphql::Error>(connection)
            },
        )
        .await
    }

    /// Check if the user has a password set.
    async fn has_password(&self, ctx: &Context<'_>) -> Result<bool, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let password = repo.user_password().active(&self.0).await?;

        Ok(password.is_some())
    }
}

/// A session in an application, either a compatibility or an OAuth 2.0 one
#[derive(Union)]
pub enum AppSession {
    CompatSession(Box<CompatSession>),
    OAuth2Session(Box<OAuth2Session>),
}

/// A user email address
#[derive(Description)]
pub struct UserEmail(pub mas_data_model::UserEmail);

#[Object(use_type_description)]
impl UserEmail {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UserEmail.id(self.0.id)
    }

    /// Email address
    async fn email(&self) -> &str {
        &self.0.email
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the email address was confirmed. Is `null` if the email was never
    /// verified by the user.
    #[graphql(deprecation = "Emails are always confirmed now.")]
    async fn confirmed_at(&self) -> Option<DateTime<Utc>> {
        Some(self.0.created_at)
    }
}

/// The state of a compatibility session.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum UserEmailState {
    /// The email address is pending confirmation.
    Pending,

    /// The email address has been confirmed.
    Confirmed,
}

/// A recovery ticket
#[derive(Description)]
pub struct UserRecoveryTicket(pub mas_data_model::UserRecoveryTicket);

/// The status of a recovery ticket
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum UserRecoveryTicketStatus {
    /// The ticket is valid
    Valid,

    /// The ticket has expired
    Expired,

    /// The ticket has been consumed
    Consumed,
}

#[Object(use_type_description)]
impl UserRecoveryTicket {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UserRecoveryTicket.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// The status of the ticket
    pub async fn status(
        &self,
        context: &Context<'_>,
    ) -> Result<UserRecoveryTicketStatus, async_graphql::Error> {
        let state = context.state();
        let clock = state.clock();
        let mut repo = state.repository().await?;

        // Lookup the session associated with the ticket
        let session = repo
            .user_recovery()
            .lookup_session(self.0.user_recovery_session_id)
            .await?
            .context("Failed to lookup session")?;
        repo.cancel().await?;

        if session.consumed_at.is_some() {
            return Ok(UserRecoveryTicketStatus::Consumed);
        }

        if self.0.expires_at < clock.now() {
            return Ok(UserRecoveryTicketStatus::Expired);
        }

        Ok(UserRecoveryTicketStatus::Valid)
    }

    /// The username associated with this ticket
    pub async fn username(&self, ctx: &Context<'_>) -> Result<String, async_graphql::Error> {
        // We could expose the UserEmail, then the User, but this is unauthenticated, so
        // we don't want to risk leaking too many objects. Instead, we just give the
        // username as a property of the UserRecoveryTicket
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let user_email = repo
            .user_email()
            .lookup(self.0.user_email_id)
            .await?
            .context("Failed to lookup user email")?;

        let user = repo
            .user()
            .lookup(user_email.user_id)
            .await?
            .context("Failed to lookup user")?;
        repo.cancel().await?;

        Ok(user.username)
    }

    /// The email address associated with this ticket
    pub async fn email(&self, ctx: &Context<'_>) -> Result<String, async_graphql::Error> {
        // We could expose the UserEmail directly, but this is unauthenticated, so we
        // don't want to risk leaking too many objects. Instead, we just give
        // the email as a property of the UserRecoveryTicket
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let user_email = repo
            .user_email()
            .lookup(self.0.user_email_id)
            .await?
            .context("Failed to lookup user email")?;
        repo.cancel().await?;

        Ok(user_email.email)
    }
}

/// A email authentication session
#[derive(Description)]
pub struct UserEmailAuthentication(pub mas_data_model::UserEmailAuthentication);

#[Object(use_type_description)]
impl UserEmailAuthentication {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UserEmailAuthentication.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the object was last updated.
    pub async fn completed_at(&self) -> Option<DateTime<Utc>> {
        self.0.completed_at
    }

    /// The email address associated with this session
    pub async fn email(&self) -> &str {
        &self.0.email
    }
}

/// An attestation authority GUID
#[derive(Description)]
pub struct Aaguid(AaguidOwned);

#[Object(use_type_description)]
impl Aaguid {
    /// The AAGUID as a string
    pub async fn id(&self) -> String {
        let id = uuid::Uuid::from_bytes(self.0.0);
        id.as_hyphenated().to_string()
    }

    /// A known name for the AAGUID
    pub async fn name(&self) -> Option<&'static str> {
        let uuid = uuid::Uuid::from_bytes(self.0.0);
        mas_aaguid::lookup(&uuid)
    }
}

/// A passkey
#[derive(Description)]
pub struct UserPasskey(pub mas_data_model::UserPasskey);

#[Object(use_type_description)]
impl UserPasskey {
    /// ID of the object
    pub async fn id(&self) -> ID {
        NodeType::UserPasskey.id(self.0.id)
    }

    /// Name of the passkey
    pub async fn name(&self) -> &str {
        &self.0.name
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the passkey was last used
    pub async fn last_used_at(&self) -> Option<DateTime<Utc>> {
        self.0.last_used_at
    }

    /// The AAGUID of the passkey
    pub async fn aaguid(&self) -> Result<Aaguid, async_graphql::Error> {
        let metadata =
            MetadataOwned::decode(&self.0.metadata).context("Failed to decode metadata")?;
        Ok(Aaguid(metadata.aaguid))
    }
}
