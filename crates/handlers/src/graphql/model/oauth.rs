// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, Object};
use chrono::{DateTime, Utc};
use mas_storage::{oauth2::OAuth2ClientRepository, user::BrowserSessionRepository};
use oauth2_types::{oidc::ApplicationType, scope::Scope};
use ulid::Ulid;
use url::Url;

use super::{BrowserSession, NodeType, SessionState, User, UserAgent};
use crate::graphql::{UserId, state::ContextExt};

/// An OAuth 2.0 session represents a client session which used the OAuth APIs
/// to login.
#[derive(Description)]
pub struct OAuth2Session(pub mas_data_model::Session);

#[Object(use_type_description)]
impl OAuth2Session {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::OAuth2Session.id(self.0.id)
    }

    /// OAuth 2.0 client used by this session.
    pub async fn client(&self, ctx: &Context<'_>) -> Result<OAuth2Client, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let client = repo
            .oauth2_client()
            .lookup(self.0.client_id)
            .await?
            .context("Could not load client")?;
        repo.cancel().await?;

        Ok(OAuth2Client(client))
    }

    /// Scope granted for this session.
    pub async fn scope(&self) -> String {
        self.0.scope.to_string()
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// When the session ended.
    pub async fn finished_at(&self) -> Option<DateTime<Utc>> {
        match &self.0.state {
            mas_data_model::SessionState::Valid => None,
            mas_data_model::SessionState::Finished { finished_at } => Some(*finished_at),
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

    /// The state of the session.
    pub async fn state(&self) -> SessionState {
        match &self.0.state {
            mas_data_model::SessionState::Valid => SessionState::Active,
            mas_data_model::SessionState::Finished { .. } => SessionState::Finished,
        }
    }

    /// The browser session which started this OAuth 2.0 session.
    pub async fn browser_session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let Some(user_session_id) = self.0.user_session_id else {
            return Ok(None);
        };

        let state = ctx.state();
        let mut repo = state.repository().await?;
        let browser_session = repo
            .browser_session()
            .lookup(user_session_id)
            .await?
            .context("Could not load browser session")?;
        repo.cancel().await?;

        Ok(Some(BrowserSession(browser_session)))
    }

    /// User authorized for this session.
    pub async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let Some(user_id) = self.0.user_id else {
            return Ok(None);
        };

        if !ctx.requester().is_owner_or_admin(&UserId(user_id)) {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let mut repo = state.repository().await?;
        let user = repo
            .user()
            .lookup(user_id)
            .await?
            .context("Could not load user")?;
        repo.cancel().await?;

        Ok(Some(User(user)))
    }

    /// The last IP address used by the session.
    pub async fn last_active_ip(&self) -> Option<String> {
        self.0.last_active_ip.map(|ip| ip.to_string())
    }

    /// The last time the session was active.
    pub async fn last_active_at(&self) -> Option<DateTime<Utc>> {
        self.0.last_active_at
    }
}

/// The application type advertised by the client.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum OAuth2ApplicationType {
    /// Client is a web application.
    Web,

    /// Client is a native application.
    Native,
}

/// An OAuth 2.0 client
#[derive(Description)]
pub struct OAuth2Client(pub mas_data_model::Client);

#[Object(use_type_description)]
impl OAuth2Client {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::OAuth2Client.id(self.0.id)
    }

    /// OAuth 2.0 client ID
    pub async fn client_id(&self) -> &str {
        &self.0.client_id
    }

    /// Client name advertised by the client.
    pub async fn client_name(&self) -> Option<&str> {
        self.0.client_name.as_deref()
    }

    /// Client URI advertised by the client.
    pub async fn client_uri(&self) -> Option<&Url> {
        self.0.client_uri.as_ref()
    }

    /// Logo URI advertised by the client.
    pub async fn logo_uri(&self) -> Option<&Url> {
        self.0.logo_uri.as_ref()
    }

    /// Terms of services URI advertised by the client.
    pub async fn tos_uri(&self) -> Option<&Url> {
        self.0.tos_uri.as_ref()
    }

    /// Privacy policy URI advertised by the client.
    pub async fn policy_uri(&self) -> Option<&Url> {
        self.0.policy_uri.as_ref()
    }

    /// List of redirect URIs used for authorization grants by the client.
    pub async fn redirect_uris(&self) -> &[Url] {
        &self.0.redirect_uris
    }

    /// The application type advertised by the client.
    pub async fn application_type(&self) -> Option<OAuth2ApplicationType> {
        match self.0.application_type.as_ref()? {
            ApplicationType::Web => Some(OAuth2ApplicationType::Web),
            ApplicationType::Native => Some(OAuth2ApplicationType::Native),
            ApplicationType::Unknown(_) => None,
        }
    }
}

/// An OAuth 2.0 consent represents the scope a user consented to grant to a
/// client.
#[derive(Description)]
pub struct OAuth2Consent {
    scope: Scope,
    client_id: Ulid,
}

#[Object(use_type_description)]
impl OAuth2Consent {
    /// Scope consented by the user for this client.
    pub async fn scope(&self) -> String {
        self.scope.to_string()
    }

    /// OAuth 2.0 client for which the user granted access.
    pub async fn client(&self, ctx: &Context<'_>) -> Result<OAuth2Client, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let client = repo
            .oauth2_client()
            .lookup(self.client_id)
            .await?
            .context("Could not load client")?;
        repo.cancel().await?;

        Ok(OAuth2Client(client))
    }
}
