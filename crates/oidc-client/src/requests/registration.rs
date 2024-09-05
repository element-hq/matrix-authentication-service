// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Requests for [Dynamic Registration].
//!
//! [Dynamic Registration]: https://openid.net/specs/openid-connect-registration-1_0.html

use mas_http::{CatchHttpCodesLayer, JsonRequestLayer, JsonResponseLayer};
use mas_iana::oauth::OAuthClientAuthenticationMethod;
use oauth2_types::registration::{ClientRegistrationResponse, VerifiedClientMetadata};
use serde::Serialize;
use serde_with::skip_serializing_none;
use tower::{Layer, Service, ServiceExt};
use url::Url;

use crate::{
    error::RegistrationError,
    http_service::HttpService,
    utils::{http_all_error_status_codes, http_error_mapper},
};

#[skip_serializing_none]
#[derive(Serialize)]
struct RegistrationRequest {
    #[serde(flatten)]
    client_metadata: VerifiedClientMetadata,
    software_statement: Option<String>,
}

/// Register a client with an OpenID Provider.
///
/// # Arguments
///
/// * `http_service` - The service to use for making HTTP requests.
///
/// * `registration_endpoint` - The URL of the issuer's Registration endpoint.
///
/// * `client_metadata` - The metadata to register with the issuer.
///
/// * `software_statement` - A JWT that asserts metadata values about the client
///   software that should be signed.
///
/// # Errors
///
/// Returns an error if the request fails or the response is invalid.
#[tracing::instrument(skip_all, fields(registration_endpoint))]
pub async fn register_client(
    http_service: &HttpService,
    registration_endpoint: &Url,
    client_metadata: VerifiedClientMetadata,
    software_statement: Option<String>,
) -> Result<ClientRegistrationResponse, RegistrationError> {
    tracing::debug!("Registering client...");

    let should_receive_secret = matches!(
        client_metadata.token_endpoint_auth_method(),
        OAuthClientAuthenticationMethod::ClientSecretPost
            | OAuthClientAuthenticationMethod::ClientSecretBasic
            | OAuthClientAuthenticationMethod::ClientSecretJwt
    );

    let body = RegistrationRequest {
        client_metadata,
        software_statement,
    };

    let registration_req = http::Request::post(registration_endpoint.as_str()).body(body)?;

    let service = (
        JsonRequestLayer::default(),
        JsonResponseLayer::<ClientRegistrationResponse>::default(),
        CatchHttpCodesLayer::new(http_all_error_status_codes(), http_error_mapper),
    )
        .layer(http_service.clone());

    let response = service
        .ready_oneshot()
        .await?
        .call(registration_req)
        .await?
        .into_body();

    if should_receive_secret && response.client_secret.is_none() {
        return Err(RegistrationError::MissingClientSecret);
    }

    Ok(response)
}
