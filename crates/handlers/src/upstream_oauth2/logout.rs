// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use mas_axum_utils::cookies::CookieJar;
use mas_router::UrlBuilder;
use mas_storage::{RepositoryAccess, upstream_oauth2::UpstreamOAuthProviderRepository};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::{error, warn};
use url::Url;

use super::UpstreamSessionsCookie;
use crate::impl_from_error_for_route;

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
    repo: &mut impl RepositoryAccess<Error = E>,
    cookie_jar: &CookieJar,
) -> Result<UpstreamLogoutInfo, RouteError>
where
    RouteError: std::convert::From<E>,
{
    let mut result: UpstreamLogoutInfo = UpstreamLogoutInfo::default();
    // Set the post-logout redirect URI to our app's logout completion page
    let post_logout_redirect_uri = url_builder
        .absolute_url_for(&mas_router::Login::default())
        .to_string();
    result.post_logout_redirect_uri = Some(post_logout_redirect_uri.clone());

    let sessions_cookie = UpstreamSessionsCookie::load(cookie_jar);
    // Standard location for OIDC end session endpoint
    let session_ids = sessions_cookie.session_ids();
    if session_ids.is_empty() {
        return Ok(result);
    }
    // We only support the first upstream session
    let mut provider = None;
    let mut upstream_session = None;
    for session_id in session_ids {
        // Get the session and assign its value, wrapped in Some
        let session = repo
            .upstream_oauth_session()
            .lookup(session_id)
            .await?
            .ok_or(RouteError::SessionNotFound)?;
        // Get the provider and assign its value, wrapped in Some
        let prov = repo
            .upstream_oauth_provider()
            .lookup(session.provider_id)
            .await?
            .ok_or(RouteError::ProviderNotFound)?;

        if prov.allow_rp_initiated_logout {
            upstream_session = Some(session);
            provider = Some(prov);
            break;
        }
    }

    // Check if we found a provider with allow_rp_initiated_logout
    if let Some(provider) = provider {
        // Look for end session endpoint
        // In a real implementation, we'd have end_session_endpoint fields in the
        // provider For now, we'll try to construct one from the issuer if
        // available
        if let Some(issuer) = &provider.issuer {
            let end_session_endpoint = format!("{issuer}/protocol/openid-connect/logout");
            let mut logout_url = end_session_endpoint;
            // Add post_logout_redirect_uri
            if let Some(post_uri) = &result.post_logout_redirect_uri {
                if let Ok(mut url) = Url::parse(&logout_url) {
                    url.query_pairs_mut()
                        .append_pair("post_logout_redirect_uri", post_uri);
                    url.query_pairs_mut()
                        .append_pair("client_id", &provider.client_id);
                    // Add id_token_hint if available
                    if let Some(session) = &upstream_session {
                        if let Some(id_token) = session.id_token() {
                            url.query_pairs_mut().append_pair("id_token_hint", id_token);
                        }
                    }
                    logout_url = url.to_string();
                }
            }
            result.logout_endpoints.clone_from(&logout_url);
        } else {
            warn!(
                upstream_oauth_provider.id = %provider.id,
                "Provider has no issuer defined, cannot construct RP-initiated logout URL"
            );
        }
    }
    Ok(result)
}
