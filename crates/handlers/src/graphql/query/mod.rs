// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_graphql::{Context, ID, MergedObject, Object};

use crate::graphql::{
    model::{
        Anonymous, BrowserSession, CompatSession, Node, NodeType, OAuth2Client, OAuth2Session,
        SiteConfig, User, UserEmail, UserRecoveryTicket,
    },
    state::ContextExt,
};

mod session;
mod upstream_oauth;
mod user;
mod viewer;

use self::{
    session::SessionQuery, upstream_oauth::UpstreamOAuthQuery, user::UserQuery, viewer::ViewerQuery,
};
use super::model::UserEmailAuthentication;

/// The query root of the GraphQL interface.
#[derive(Default, MergedObject)]
pub struct Query(
    BaseQuery,
    UserQuery,
    UpstreamOAuthQuery,
    SessionQuery,
    ViewerQuery,
);

impl Query {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Default)]
struct BaseQuery;

// TODO: move the rest of the queries in separate modules
#[Object]
impl BaseQuery {
    /// Get the current logged in browser session
    #[graphql(deprecation = "Use `viewerSession` instead.")]
    async fn current_browser_session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let requester = ctx.requester();
        Ok(requester
            .browser_session()
            .cloned()
            .map(BrowserSession::from))
    }

    /// Get the current logged in user
    #[graphql(deprecation = "Use `viewer` instead.")]
    async fn current_user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let requester = ctx.requester();
        Ok(requester.user().cloned().map(User::from))
    }

    /// Fetch an OAuth 2.0 client by its ID.
    async fn oauth2_client(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<OAuth2Client>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::OAuth2Client.extract_ulid(&id)?;

        let mut repo = state.repository().await?;
        let client = repo.oauth2_client().lookup(id).await?;
        repo.cancel().await?;

        Ok(client.map(OAuth2Client))
    }

    /// Fetch a browser session by its ID.
    async fn browser_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::BrowserSession.extract_ulid(&id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let browser_session = repo.browser_session().lookup(id).await?;
        repo.cancel().await?;

        let Some(browser_session) = browser_session else {
            return Ok(None);
        };

        if !requester.is_owner_or_admin(&browser_session) {
            return Ok(None);
        }

        Ok(Some(BrowserSession(browser_session)))
    }

    /// Fetch a compatible session by its ID.
    async fn compat_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<CompatSession>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::CompatSession.extract_ulid(&id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let compat_session = repo.compat_session().lookup(id).await?;
        repo.cancel().await?;

        let Some(compat_session) = compat_session else {
            return Ok(None);
        };

        if !requester.is_owner_or_admin(&compat_session) {
            return Ok(None);
        }

        Ok(Some(CompatSession::new(compat_session)))
    }

    /// Fetch an OAuth 2.0 session by its ID.
    async fn oauth2_session(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<OAuth2Session>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::OAuth2Session.extract_ulid(&id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let oauth2_session = repo.oauth2_session().lookup(id).await?;
        repo.cancel().await?;

        let Some(oauth2_session) = oauth2_session else {
            return Ok(None);
        };

        if !requester.is_owner_or_admin(&oauth2_session) {
            return Ok(None);
        }

        Ok(Some(OAuth2Session(oauth2_session)))
    }

    /// Fetch a user email by its ID.
    async fn user_email(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UserEmail>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::UserEmail.extract_ulid(&id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;
        let user_email = repo.user_email().lookup(id).await?;
        repo.cancel().await?;

        let Some(user_email) = user_email else {
            return Ok(None);
        };

        if !requester.is_owner_or_admin(&user_email) {
            return Ok(None);
        }

        Ok(Some(UserEmail(user_email)))
    }

    /// Fetch a user recovery ticket.
    async fn user_recovery_ticket(
        &self,
        ctx: &Context<'_>,
        ticket: String,
    ) -> Result<Option<UserRecoveryTicket>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let ticket = repo.user_recovery().find_ticket(&ticket).await?;
        repo.cancel().await?;

        Ok(ticket.map(UserRecoveryTicket))
    }

    /// Fetch a user email authentication session
    async fn user_email_authentication(
        &self,
        ctx: &Context<'_>,
        id: ID,
    ) -> Result<Option<UserEmailAuthentication>, async_graphql::Error> {
        let state = ctx.state();
        let id = NodeType::UserEmailAuthentication.extract_ulid(&id)?;
        let requester = ctx.requester();
        let mut repo = state.repository().await?;
        let authentication = repo.user_email().lookup_authentication(id).await?;
        let Some(authentication) = authentication else {
            return Ok(None);
        };

        let Some(browser_session) = requester.browser_session() else {
            return Ok(None);
        };

        if authentication.user_session_id != Some(browser_session.id) {
            return Ok(None);
        }

        Ok(Some(UserEmailAuthentication(authentication)))
    }

    /// Fetches an object given its ID.
    async fn node(&self, ctx: &Context<'_>, id: ID) -> Result<Option<Node>, async_graphql::Error> {
        // Special case for the anonymous user
        if id.as_str() == "anonymous" {
            return Ok(Some(Node::Anonymous(Box::new(Anonymous))));
        }

        if id.as_str() == crate::graphql::model::SITE_CONFIG_ID {
            return Ok(Some(Node::SiteConfig(Box::new(SiteConfig::new(
                ctx.state().site_config(),
            )))));
        }

        let (node_type, _id) = NodeType::from_id(&id)?;

        let ret = match node_type {
            // TODO
            NodeType::Authentication | NodeType::CompatSsoLogin | NodeType::UserRecoveryTicket => {
                None
            }

            NodeType::UpstreamOAuth2Provider => UpstreamOAuthQuery
                .upstream_oauth2_provider(ctx, id)
                .await?
                .map(|c| Node::UpstreamOAuth2Provider(Box::new(c))),

            NodeType::UpstreamOAuth2Link => UpstreamOAuthQuery
                .upstream_oauth2_link(ctx, id)
                .await?
                .map(|c| Node::UpstreamOAuth2Link(Box::new(c))),

            NodeType::OAuth2Client => self
                .oauth2_client(ctx, id)
                .await?
                .map(|c| Node::OAuth2Client(Box::new(c))),

            NodeType::UserEmail => self
                .user_email(ctx, id)
                .await?
                .map(|e| Node::UserEmail(Box::new(e))),

            NodeType::UserEmailAuthentication => self
                .user_email_authentication(ctx, id)
                .await?
                .map(|e| Node::UserEmailAuthentication(Box::new(e))),

            NodeType::CompatSession => self
                .compat_session(ctx, id)
                .await?
                .map(|s| Node::CompatSession(Box::new(s))),

            NodeType::OAuth2Session => self
                .oauth2_session(ctx, id)
                .await?
                .map(|s| Node::OAuth2Session(Box::new(s))),

            NodeType::BrowserSession => self
                .browser_session(ctx, id)
                .await?
                .map(|s| Node::BrowserSession(Box::new(s))),

            NodeType::User => UserQuery
                .user(ctx, id)
                .await?
                .map(|u| Node::User(Box::new(u))),
        };

        Ok(ret)
    }

    /// Get the current site configuration
    async fn site_config(&self, ctx: &Context<'_>) -> SiteConfig {
        SiteConfig::new(ctx.state().site_config())
    }
}
