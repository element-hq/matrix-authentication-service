// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, ID, Object};
use chrono::{DateTime, Utc};
use mas_storage::{upstream_oauth2::UpstreamOAuthProviderRepository, user::UserRepository};
use url::Url;

use super::{NodeType, User};
use crate::graphql::state::ContextExt;

#[derive(Debug, Clone)]
pub struct UpstreamOAuth2Provider {
    provider: mas_data_model::UpstreamOAuthProvider,
}

impl UpstreamOAuth2Provider {
    #[must_use]
    pub const fn new(provider: mas_data_model::UpstreamOAuthProvider) -> Self {
        Self { provider }
    }
}

#[Object]
impl UpstreamOAuth2Provider {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UpstreamOAuth2Provider.id(self.provider.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.provider.created_at
    }

    /// OpenID Connect issuer URL.
    pub async fn issuer(&self) -> Option<&str> {
        self.provider.issuer.as_deref()
    }

    /// Client ID used for this provider.
    pub async fn client_id(&self) -> &str {
        &self.provider.client_id
    }

    /// A human-readable name for this provider.
    pub async fn human_name(&self) -> Option<&str> {
        self.provider.human_name.as_deref()
    }

    /// A brand identifier for this provider.
    ///
    /// One of `google`, `github`, `gitlab`, `apple` or `facebook`.
    pub async fn brand_name(&self) -> Option<&str> {
        self.provider.brand_name.as_deref()
    }

    /// URL to start the linking process of the current user with this provider.
    pub async fn link_url(&self, context: &Context<'_>) -> Url {
        let state = context.state();
        let url_builder = state.url_builder();
        let route = mas_router::UpstreamOAuth2Authorize::new(self.provider.id);
        url_builder.absolute_url_for(&route)
    }
}

impl UpstreamOAuth2Link {
    #[must_use]
    pub const fn new(link: mas_data_model::UpstreamOAuthLink) -> Self {
        Self {
            link,
            provider: None,
            user: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UpstreamOAuth2Link {
    link: mas_data_model::UpstreamOAuthLink,
    provider: Option<mas_data_model::UpstreamOAuthProvider>,
    user: Option<mas_data_model::User>,
}

#[Object]
impl UpstreamOAuth2Link {
    /// ID of the object.
    pub async fn id(&self) -> ID {
        NodeType::UpstreamOAuth2Link.id(self.link.id)
    }

    /// When the object was created.
    pub async fn created_at(&self) -> DateTime<Utc> {
        self.link.created_at
    }

    /// Subject used for linking
    pub async fn subject(&self) -> &str {
        &self.link.subject
    }

    /// A human-readable name for the link subject.
    pub async fn human_account_name(&self) -> Option<&str> {
        self.link.human_account_name.as_deref()
    }

    /// The provider for which this link is.
    pub async fn provider(
        &self,
        ctx: &Context<'_>,
    ) -> Result<UpstreamOAuth2Provider, async_graphql::Error> {
        let state = ctx.state();
        let provider = if let Some(provider) = &self.provider {
            // Cached
            provider.clone()
        } else {
            // Fetch on-the-fly
            let mut repo = state.repository().await?;

            let provider = repo
                .upstream_oauth_provider()
                .lookup(self.link.provider_id)
                .await?
                .context("Upstream OAuth 2.0 provider not found")?;
            repo.cancel().await?;

            provider
        };

        Ok(UpstreamOAuth2Provider::new(provider))
    }

    /// The user to which this link is associated.
    pub async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let user = if let Some(user) = &self.user {
            // Cached
            user.clone()
        } else if let Some(user_id) = &self.link.user_id {
            // Fetch on-the-fly
            let mut repo = state.repository().await?;

            let user = repo
                .user()
                .lookup(*user_id)
                .await?
                .context("User not found")?;
            repo.cancel().await?;

            user
        } else {
            return Ok(None);
        };

        Ok(Some(User(user)))
    }
}
