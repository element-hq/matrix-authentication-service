// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use anyhow::Context as _;
use async_graphql::{Context, Description, Enum, InputObject, Object, ID};
use mas_storage::{user::UserRepository, RepositoryAccess};

use crate::graphql::{
    model::{NodeType, UpstreamOAuth2Link, UpstreamOAuth2Provider, User},
    state::ContextExt,
};

#[derive(Default)]
pub struct UpstreamOauthMutations {
    _private: (),
}

/// The input for the `removeEmail` mutation
#[derive(InputObject)]
struct RemoveUpstreamLinkInput {
    /// The ID of the upstream link to remove
    upstream_link_id: ID,
}

/// The status of the `removeEmail` mutation
#[derive(Enum, Copy, Clone, Eq, PartialEq)]
enum RemoveUpstreamLinkStatus {
    /// The upstream link was removed
    Removed,

    /// The upstream link was not found
    NotFound,
}

/// The payload of the `removeEmail` mutation
#[derive(Description)]
enum RemoveUpstreamLinkPayload {
    Removed(mas_data_model::UpstreamOAuthLink),
    NotFound,
}

#[Object(use_type_description)]
impl RemoveUpstreamLinkPayload {
    /// Status of the operation
    async fn status(&self) -> RemoveUpstreamLinkStatus {
        match self {
            RemoveUpstreamLinkPayload::Removed(_) => RemoveUpstreamLinkStatus::Removed,
            RemoveUpstreamLinkPayload::NotFound => RemoveUpstreamLinkStatus::NotFound,
        }
    }

    /// The upstream link that was removed
    async fn upstream_link(&self) -> Option<UpstreamOAuth2Link> {
        match self {
            RemoveUpstreamLinkPayload::Removed(link) => Some(UpstreamOAuth2Link::new(link.clone())),
            RemoveUpstreamLinkPayload::NotFound => None,
        }
    }

    /// The provider to which the upstream link belonged
    async fn provider(
        &self,
        ctx: &Context<'_>,
    ) -> Result<Option<UpstreamOAuth2Provider>, async_graphql::Error> {
        let state = ctx.state();
        let provider_id = match self {
            RemoveUpstreamLinkPayload::Removed(link) => link.provider_id,
            RemoveUpstreamLinkPayload::NotFound => return Ok(None),
        };

        let mut repo = state.repository().await?;
        let provider = repo
            .upstream_oauth_provider()
            .lookup(provider_id)
            .await?
            .context("Upstream OAuth 2.0 provider not found")?;

        Ok(Some(UpstreamOAuth2Provider::new(provider)))
    }

    /// The user to whom the upstream link belonged
    async fn user(&self, ctx: &Context<'_>) -> Result<Option<User>, async_graphql::Error> {
        let state = ctx.state();
        let mut repo = state.repository().await?;

        let user_id = match self {
            RemoveUpstreamLinkPayload::Removed(link) => link.user_id,
            RemoveUpstreamLinkPayload::NotFound => return Ok(None),
        };

        match user_id {
            None => Ok(None),
            Some(user_id) => {
                let user = repo
                    .user()
                    .lookup(user_id)
                    .await?
                    .context("User not found")?;

                Ok(Some(User(user)))
            }
        }
    }
}

#[Object]
impl UpstreamOauthMutations {
    /// Remove an upstream linked account
    async fn remove_upstream_link(
        &self,
        ctx: &Context<'_>,
        input: RemoveUpstreamLinkInput,
    ) -> Result<RemoveUpstreamLinkPayload, async_graphql::Error> {
        let state = ctx.state();
        let upstream_link_id =
            NodeType::UpstreamOAuth2Link.extract_ulid(&input.upstream_link_id)?;
        let requester = ctx.requester();

        let mut repo = state.repository().await?;

        let upstream_link = repo.upstream_oauth_link().lookup(upstream_link_id).await?;
        let Some(upstream_link) = upstream_link else {
            return Ok(RemoveUpstreamLinkPayload::NotFound);
        };

        if !requester.is_owner_or_admin(&upstream_link) {
            return Ok(RemoveUpstreamLinkPayload::NotFound);
        }

        // Allow non-admins to remove their email address if the site config allows it
        if !requester.is_admin() && !state.site_config().email_change_allowed {
            return Err(async_graphql::Error::new("Unauthorized"));
        }

        let upstream_link = repo
            .upstream_oauth_link()
            .lookup(upstream_link.id)
            .await?
            .context("Failed to load user")?;

        repo.upstream_oauth_link()
            .remove(upstream_link.clone())
            .await?;

        repo.save().await?;

        Ok(RemoveUpstreamLinkPayload::Removed(upstream_link))
    }
}
