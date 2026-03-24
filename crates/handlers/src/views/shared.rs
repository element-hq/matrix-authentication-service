// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::str::FromStr as _;

use anyhow::Context;
use mas_router::{PostAuthAction, Route, UrlBuilder};
use mas_storage::{
    RepositoryAccess,
    compat::CompatSsoLoginRepository,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository},
};
use mas_templates::{PostAuthContext, PostAuthContextInner};
use ruma_common::UserId;
use serde::{Deserialize, Serialize};
use tracing::warn;

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
                let Some(grant) = repo.oauth2_authorization_grant().lookup(id).await? else {
                    warn!(%id, "Failed to load authorization grant, it was likely deleted or is an invalid ID");
                    return Ok(None);
                };
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueAuthorizationGrant { grant }
            }

            PostAuthAction::ContinueDeviceCodeGrant { id } => {
                let Some(grant) = repo.oauth2_device_code_grant().lookup(id).await? else {
                    warn!(%id, "Failed to load device code grant, it was likely deleted or is an invalid ID");
                    return Ok(None);
                };
                let grant = Box::new(grant);
                PostAuthContextInner::ContinueDeviceCodeGrant { grant }
            }

            PostAuthAction::ContinueCompatSsoLogin { id } => {
                let Some(login) = repo.compat_sso_login().lookup(id).await? else {
                    warn!(%id, "Failed to load compat SSO login, it was likely deleted or is an invalid ID");
                    return Ok(None);
                };
                let login = Box::new(login);
                PostAuthContextInner::ContinueCompatSsoLogin { login }
            }

            PostAuthAction::ChangePassword => PostAuthContextInner::ChangePassword,

            PostAuthAction::LinkUpstream { id } => {
                let Some(link) = repo.upstream_oauth_link().lookup(id).await? else {
                    warn!(%id, "Failed to load upstream OAuth 2.0 link, it was likely deleted or is an invalid ID");
                    return Ok(None);
                };

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

pub enum LoginHint<'a> {
    Mxid(&'a UserId),
    Email(lettre::Address),
    None,
}

#[derive(Debug, Deserialize)]
pub(crate) struct QueryLoginHint {
    login_hint: Option<String>,
}

impl QueryLoginHint {
    /// Parse a `login_hint`
    ///
    /// Returns `LoginHint::MXID` for valid mxid 'mxid:@john.doe:example.com'
    ///
    /// Returns `LoginHint::Email` for valid email 'john.doe@example.com'
    ///
    /// Otherwise returns `LoginHint::None`
    pub fn parse_login_hint(&self, homeserver: &str) -> LoginHint<'_> {
        let Some(login_hint) = &self.login_hint else {
            return LoginHint::None;
        };

        if let Some(value) = login_hint.strip_prefix("mxid:")
            && let Ok(mxid) = <&UserId>::try_from(value)
            && mxid.server_name() == homeserver
        {
            LoginHint::Mxid(mxid)
        } else if let Ok(email) = lettre::Address::from_str(login_hint) {
            LoginHint::Email(email)
        } else {
            LoginHint::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_login_hint() {
        let query_login_hint = QueryLoginHint { login_hint: None };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn valid_login_hint() {
        let query_login_hint = QueryLoginHint {
            login_hint: Some(String::from("mxid:@example-user:example.com")),
        };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::Mxid(mxid) if mxid.localpart() == "example-user"));
    }

    #[test]
    fn valid_login_hint_with_email() {
        let query_login_hint = QueryLoginHint {
            login_hint: Some(String::from("example@user")),
        };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::Email(email) if email.to_string() == "example@user"));
    }

    #[test]
    fn invalid_login_hint() {
        let query_login_hint = QueryLoginHint {
            login_hint: Some(String::from("example-user")),
        };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn valid_login_hint_for_wrong_homeserver() {
        let query_login_hint = QueryLoginHint {
            login_hint: Some(String::from("mxid:@example-user:matrix.org")),
        };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }

    #[test]
    fn unknown_login_hint_type() {
        let query_login_hint = QueryLoginHint {
            login_hint: Some(String::from("something:anything")),
        };

        let hint = query_login_hint.parse_login_hint("example.com");

        assert!(matches!(hint, LoginHint::None));
    }
}
