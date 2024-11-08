// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Object, ID};
use chrono::{DateTime, Utc};
use mas_storage::{
    upstream_oauth2::{UpstreamOAuthLinkFilter, UpstreamOAuthProviderRepository},
    user::UserRepository,
    Pagination,
};

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
    pub async fn issuer(&self) -> &str {
        &self.provider.issuer
    }

    /// Client ID used for this provider.
    pub async fn client_id(&self) -> &str {
        &self.provider.client_id
    }

    /// The human-readable name of the provider.
    pub async fn human_name(&self) -> Option<&str> {
        self.provider.human_name.as_deref()
    }

    /// UpstreamOAuth2Links associated with this provider for the current user.
    pub async fn upstream_oauth2_links_for_user(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Vec<UpstreamOAuth2Link>, async_graphql::Error> {
        let state = ctx.state();
        let user = ctx
            .requester()
            .user()
            .ok_or_else(|| async_graphql::Error::new("User ID not found in the request context"))?;

        let mut repo = state.repository().await?;
        let filter = UpstreamOAuthLinkFilter::new()
            .for_provider(&self.provider)
            .for_user(user);
        let links = repo
            .upstream_oauth_link()
            // Hardcoded limit of 100 links. We do not expect reasonably more links
            // See also https://github.com/element-hq/matrix-authentication-service/pull/3245#discussion_r1776850096
            .list(filter, Pagination::first(100))
            .await?;
        repo.cancel().await?;

        Ok(links
            .edges
            .into_iter()
            .map(UpstreamOAuth2Link::new)
            .collect())
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
