// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use mas_data_model::{AuthenticationMethod, BrowserSession};
use mas_router::UrlBuilder;
use mas_storage::{RepositoryAccess, upstream_oauth2::UpstreamOAuthProviderRepository};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::error;

use super::cache::LazyProviderInfos;
use crate::{MetadataCache, impl_from_error_for_route};

#[derive(Serialize, Deserialize)]
struct LogoutToken {
    logout_token: String,
}

/// Structure to collect upstream RP-initiated logout endpoints for a user
#[derive(Debug, Default)]
pub struct UpstreamLogoutInfo {
    /// Collection of logout endpoints that the user needs to be redirected to
    pub logout_endpoints: String,
    /// Optional post-logout redirect URI to come back to our app
    pub post_logout_redirect_uri: Option<String>,
}

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("provider was not found")]
    ProviderNotFound,

    #[error("session was not found")]
    SessionNotFound,
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);

impl From<reqwest::Error> for RouteError {
    fn from(err: reqwest::Error) -> Self {
        Self::Internal(Box::new(err))
    }
}

/// Get RP-initiated logout URLs for a user's upstream providers
///
/// This retrieves logout endpoints from all connected upstream providers that
/// support RP-initiated logout.
///
/// # Parameters
///
/// * `repo`: The repository to use
/// * `url_builder`: URL builder for constructing redirect URIs
/// * `cookie_jar`: Cookie from user's browser session
///
/// # Returns
///
/// Information about upstream logout endpoints the user should be redirected to
///
/// # Errors
///
/// Returns a `RouteError` if there's an issue accessing the repository
pub async fn get_rp_initiated_logout_endpoints<E>(
    url_builder: &UrlBuilder,
    metadata_cache: &MetadataCache,
    client: &reqwest::Client,
    repo: &mut impl RepositoryAccess<Error = E>,
    browser_session: &BrowserSession,
) -> Result<UpstreamLogoutInfo, RouteError>
where
    RouteError: std::convert::From<E>,
{
    let mut result: UpstreamLogoutInfo = UpstreamLogoutInfo::default();
    let post_logout_redirect_uri = url_builder
        .absolute_url_for(&mas_router::Login::default())
        .to_string();
    result.post_logout_redirect_uri = Some(post_logout_redirect_uri.clone());

    let upstream_oauth2_session_id = repo
        .browser_session()
        .get_last_authentication(browser_session)
        .await?
        .ok_or(RouteError::SessionNotFound)
        .map(|auth| match auth.authentication_method {
            AuthenticationMethod::UpstreamOAuth2 {
                upstream_oauth2_session_id,
            } => Some(upstream_oauth2_session_id),
            _ => None,
        })?
        .ok_or(RouteError::SessionNotFound)?;

    let upstream_session = repo
        .upstream_oauth_session()
        .lookup(upstream_oauth2_session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    let provider = repo
        .upstream_oauth_provider()
        .lookup(upstream_session.provider_id)
        .await?
        .filter(|provider| provider.allow_rp_initiated_logout)
        .ok_or(RouteError::ProviderNotFound)?;

    // Add post_logout_redirect_uri
    if let Some(post_uri) = &result.post_logout_redirect_uri {
        let mut lazy_metadata = LazyProviderInfos::new(metadata_cache, &provider, client);
        let mut end_session_url = lazy_metadata.end_session_endpoint().await?.clone();
        end_session_url
            .query_pairs_mut()
            .append_pair("post_logout_redirect_uri", post_uri);
        end_session_url
            .query_pairs_mut()
            .append_pair("client_id", &provider.client_id);
        // Add id_token_hint if available
        if let Some(id_token) = upstream_session.id_token() {
            end_session_url
                .query_pairs_mut()
                .append_pair("id_token_hint", id_token);
        }
        result
            .logout_endpoints
            .clone_from(&end_session_url.to_string());
    }

    Ok(result)
}
