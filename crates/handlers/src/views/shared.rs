// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context;
use mas_router::{PostAuthAction, Route, UrlBuilder};
use mas_storage::{
    RepositoryAccess,
    compat::CompatSsoLoginRepository,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
};
use mas_templates::{PostAuthContext, PostAuthContextInner};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Default, Debug, Clone)]
pub(crate) struct OptionalPostAuthAction {
    #[serde(flatten)]
    pub post_auth_action: Option<PostAuthAction>,
}

impl From<Option<PostAuthAction>> for OptionalPostAuthAction {
    fn from(post_auth_action: Option<PostAuthAction>) -> Self {
        Self { post_auth_action }
    }
}

impl OptionalPostAuthAction {
    pub fn go_next_or_default<T: Route>(
        &self,
        url_builder: &UrlBuilder,
        default: &T,
    ) -> axum::response::Redirect {
        self.post_auth_action.as_ref().map_or_else(
            || url_builder.redirect(default),
            |action| action.go_next(url_builder),
        )
    }

    pub fn go_next(&self, url_builder: &UrlBuilder) -> axum::response::Redirect {
        self.go_next_or_default(url_builder, &mas_router::Index)
    }

    pub async fn load_context<'a>(
        &'a self,
        repo: &'a mut impl RepositoryAccess,
    ) -> anyhow::Result<Option<PostAuthContext>> {
        let Some(action) = self.post_auth_action.clone() else {
            return Ok(None);
        };
        let ctx = match action {
            PostAuthAction::ContinueAuthorizationGrant { id } => {
                let grant = repo
                    .oauth2_authorization_grant()
                    .lookup(id)
                    .await?
                    .context("Failed to load authorization grant")?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueAuthorizationGrant { grant }
            }

            PostAuthAction::ContinueDeviceCodeGrant { id } => {
                let grant = repo
                    .oauth2_device_code_grant()
                    .lookup(id)
                    .await?
                    .context("Failed to load device code grant")?;
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueDeviceCodeGrant { grant }
            }

            PostAuthAction::ContinueCompatSsoLogin { id } => {
                let login = repo
                    .compat_sso_login()
                    .lookup(id)
                    .await?
                    .context("Failed to load compat SSO login")?;
                let login = Box::new(login);
                PostAuthContextInner::ContinueCompatSsoLogin { login }
            }

            PostAuthAction::ChangePassword => PostAuthContextInner::ChangePassword,

            PostAuthAction::LinkUpstream { id } => {
                let link = repo
                    .upstream_oauth_link()
                    .lookup(id)
                    .await?
                    .context("Failed to load upstream OAuth 2.0 link")?;

                let provider = repo
                    .upstream_oauth_provider()
                    .lookup(link.provider_id)
                    .await?
                    .context("Failed to load upstream OAuth 2.0 provider")?;

                let provider = Box::new(provider);
                let link = Box::new(link);
                PostAuthContextInner::LinkUpstream { provider, link }
            }

            PostAuthAction::ManageAccount { .. } => PostAuthContextInner::ManageAccount,
        };

        Ok(Some(PostAuthContext {
            params: action.clone(),
            ctx,
        }))
    }
}
