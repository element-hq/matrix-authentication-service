// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, ID, Object};
use chrono::{DateTime, Utc};
use mas_data_model::Device;
use mas_storage::{compat::CompatSessionRepository, user::UserRepository};
use url::Url;

use super::{BrowserSession, NodeType, SessionState, User, UserAgent};
use crate::graphql::state::ContextExt;

/// Lazy-loaded reverse reference.
///
/// XXX: maybe we want to stick that in a utility module
#[derive(Clone, Debug, Default)]
enum ReverseReference<T> {
    Loaded(T),
    #[default]
    Lazy,
}

/// A compat session represents a client session which used the legacy Matrix
/// login API.
#[derive(Description)]
pub struct CompatSession {
    session: mas_data_model::CompatSession,
    sso_login: ReverseReference<Option<mas_data_model::CompatSsoLogin>>,
}

impl CompatSession {
    pub fn new(session: mas_data_model::CompatSession) -> Self {
        Self {
            session,
            sso_login: ReverseReference::Lazy,
        }
    }

    /// Save an eagerly loaded SSO login.
    pub fn with_loaded_sso_login(
        mut self,
        sso_login: Option<mas_data_model::CompatSsoLogin>,
    ) -> Self {
        self.sso_login = ReverseReference::Loaded(sso_login);
        self
    }
}

/// The type of a compatibility session.
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
pub enum CompatSessionType {
    /// The session was created by a SSO login.
    SsoLogin,

    /// The session was created by an unknown method.
    Unknown,
}

#[Object(use_type_description)]
impl CompatSession {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::CompatSession.id(self.session.id)
    }

    /// The user authorized for this session.
    async fn user(&self, ctx: &Context<'_>) -> Result<User, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let user = repo
            .user()
            .lookup(self.session.user_id)
            .await?
            .context("Could not load user")?;
        repo.cancel().await?;

        Ok(User(user))
    }

    /// The Matrix Device ID of this session.
    async fn device_id(&self) -> Option<&str> {
        self.session.device.as_ref().map(Device::as_str)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.session.created_at
    }

    /// When the session ended.
    pub async fn finished_at(&self) -> Option<DateTime<Utc>> {
        self.session.finished_at()
    }

    /// The user-agent with which the session was created.
    pub async fn user_agent(&self) -> Option<UserAgent> {
        self.session
            .user_agent
            .clone()
            .map(mas_data_model::UserAgent::parse)
            .map(UserAgent::from)
    }

    /// The associated SSO login, if any.
    pub async fn sso_login(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<CompatSsoLogin>, async_graphql::Error> {
        if let ReverseReference::Loaded(sso_login) = &self.sso_login {
            return Ok(sso_login.clone().map(CompatSsoLogin));
        }

        // We need to load it on the fly
        let state = ctx.state();
        let mut repo = state.repository().await?;
        let sso_login = repo
            .compat_sso_login()
            .find_for_session(&self.session)
            .await
            .context("Could not load SSO login")?;
        repo.cancel().await?;

        Ok(sso_login.map(CompatSsoLogin))
    }

    /// The browser session which started this session, if any.
    pub async fn browser_session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<BrowserSession>, async_graphql::Error> {
        let Some(user_session_id) = self.session.user_session_id else {
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

    /// The state of the session.
    pub async fn state(&self) -> SessionState {
        match &self.session.state {
            mas_data_model::CompatSessionState::Valid => SessionState::Active,
            mas_data_model::CompatSessionState::Finished { .. } => SessionState::Finished,
        }
    }

    /// The last IP address used by the session.
    pub async fn last_active_ip(&self) -> Option<String> {
        self.session.last_active_ip.map(|ip| ip.to_string())
    }

    /// The last time the session was active.
    pub async fn last_active_at(&self) -> Option<DateTime<Utc>> {
        self.session.last_active_at
    }

    /// A human-provided name for the session.
    pub async fn human_name(&self) -> Option<&str> {
        self.session.human_name.as_deref()
    }
}

/// A compat SSO login represents a login done through the legacy Matrix login
/// API, via the `m.login.sso` login method.
#[derive(Description)]
pub struct CompatSsoLogin(pub mas_data_model::CompatSsoLogin);

#[Object(use_type_description)]
impl CompatSsoLogin {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::CompatSsoLogin.id(self.0.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.0.created_at
    }

    /// The redirect URI used during the login.
    async fn redirect_uri(&self) -> &Url {
        &self.0.redirect_uri
    }

    /// When the login was fulfilled, and the user was redirected back to the
    /// client.
    async fn fulfilled_at(&self) -> Option<DateTime<Utc>> {
        self.0.fulfilled_at()
    }

    /// When the client exchanged the login token sent during the redirection.
    async fn exchanged_at(&self) -> Option<DateTime<Utc>> {
        self.0.exchanged_at()
    }

    /// The compat session which was started by this login.
    async fn session(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<CompatSession>, async_graphql::Error> {
        let Some(session_id) = self.0.session_id() else {
            return Ok(None);
        };

        let state = ctx.state();
        let mut repo = state.repository().await?;
        let session = repo
            .compat_session()
            .lookup(session_id)
            .await?
            .context("Could not load compat session")?;
        repo.cancel().await?;

        Ok(Some(
            CompatSession::new(session).with_loaded_sso_login(Some(self.0.clone())),
        ))
    }
}
