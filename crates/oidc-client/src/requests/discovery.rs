// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for OpenID Connect Provider [Discovery].
//!
//! [Discovery]: https://openid.net/specs/openid-connect-discovery-1_0.html

use bytes::Bytes;
use mas_http::{CatchHttpCodesLayer, JsonResponseLayer};
use oauth2_types::oidc::{ProviderMetadata, VerifiedProviderMetadata};
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::DiscoveryError,
    http_service::HttpService,
    utils::{http_all_error_status_codes, http_error_mapper},
};

/// Fetch the provider metadata.
async fn discover_inner(
    http_service: &HttpService,
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

    let config_req = http::Request::get(config_url.as_str()).body(Bytes::new())?;

    let service = (
        JsonResponseLayer::<ProviderMetadata>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let response = service.ready_oneshot().await?.call(config_req).await?;
    tracing::debug!(?response);

    Ok(response.into_body())
}

/// Fetch the provider metadata and validate it.
///
/// # Errors
///
/// Returns an error if the request fails or if the data is invalid.
#[tracing::instrument(skip_all, fields(issuer))]
pub async fn discover(
    http_service: &HttpService,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(http_service, issuer.parse()?).await?;

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
/// * `http_service` - The service to use for making HTTP requests.
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
    http_service: &HttpService,
    issuer: &str,
) -> Result<VerifiedProviderMetadata, DiscoveryError> {
    let provider_metadata = discover_inner(http_service, issuer.parse()?).await?;

    Ok(provider_metadata.insecure_verify_metadata()?)
}
