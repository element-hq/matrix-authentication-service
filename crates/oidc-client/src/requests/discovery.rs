// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Requests for OpenID Connect Provider [Discovery].
//!
//! [Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html

use mas_http::RequestBuilderExt;
use oauth2_types::oidc::{ProviderMetadata, VerifiedProviderMetadata};
use url::Url;

use crate::error::DiscoveryError;

/// Fetch the provider metadata.
async fn discover_inner(
    client: &reqwest::Client,
    issuer: Url,
) -> Result<ProviderMetadata, DiscoveryError> {
    tracing::debug!("Fetching provider metadata...");

    let mut config_url = issuer;

    // If the path doesn't end with a slash, the last segment is removed when
    // using `join`.
    if !config_url.path().ends_with('/') {
        let mut path = config_url.path().to_owned();
        path.push('/');
        config_url.set_path(&path);
    }

    let config_url = config_url.join(".well-known/openid-configuration")?;

    let response = client
        .get(config_url.as_str())
        .send_traced()
        .await?
        .error_for_status()?
        .json()
        .await?;

    tracing::debug!(?response);

    Ok(response)
}

/// Fetch the provider metadata and validate it.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
#[tracing::instrument(skip_all, fields(issuer))]
pub async fn discover(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(client, issuer.parse()?).await?;

    Ok(provider_metadata.validate(issuer)?)
}

/// Fetch the [provider metadata] and make basic checks.
///
/// Contrary to [`discover()`], this uses
/// [`ProviderMetadata::insecure_verify_metadata()`] to check the received
/// metadata instead of validating it according to the specification.
///
/// # Arguments
///
/// * `http_client` - The reqwest client to use for making HTTP requests.
///
/// * `issuer` - The URL of the OpenID Connect Provider to fetch metadata for.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
///
/// # Warning
///
/// It is not recommended to use this method in production as it doesn't
/// ensure that the issuer implements the proper security practices.
///
/// [provider metadata]: https://openid.net/specs/openid-connect-discovery-1_0.html
#[tracing::instrument(skip_all, fields(issuer))]
pub async fn insecure_discover(
    client: &reqwest::Client,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(client, issuer.parse()?).await?;

    Ok(provider_metadata.insecure_verify_metadata()?)
}
