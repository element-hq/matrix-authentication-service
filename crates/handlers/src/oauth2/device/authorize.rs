// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use chrono::Duration;
use headers::{CacheControl, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
};
use mas_data_model::UserAgent;
use mas_keystore::Encrypter;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, oauth2::OAuth2DeviceCodeGrantParams};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    requests::{DeviceAuthorizationRequest, DeviceAuthorizationResponse, GrantType},
    scope::ScopeToken,
};
use rand::distributions::{Alphanumeric, DistString};
use thiserror::Error;
use ulid::Ulid;

use crate::{BoundActivityTracker, impl_from_error_for_route};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("client not found")]
    ClientNotFound,

    #[error("client {0} is not allowed to use the device code grant")]
    ClientNotAllowed(Ulid),

    #[error("invalid client credentials for client {client_id}")]
    InvalidClientCredentials {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },

    #[error("could not verify client credentials for client {client_id}")]
    ClientCredentialsVerification {
        client_id: Ulid,
        #[source]
        source: CredentialsVerificationError,
    },
}

impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));

        let response = match self {
            Self::Internal(_) | Self::ClientCredentialsVerification { .. } => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ClientError::from(ClientErrorCode::ServerError)),
            ),
            Self::ClientNotFound | Self::InvalidClientCredentials { .. } => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::InvalidClient)),
            ),
            Self::ClientNotAllowed(_) => (
                StatusCode::UNAUTHORIZED,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.device.request.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut repo: BoxRepository,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    State(http_client): State<reqwest::Client>,
    State(encrypter): State<Encrypter>,
    client_authorization: ClientAuthorization<DeviceAuthorizationRequest>,
) -> Result<impl IntoResponse, RouteError> {
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // Reuse the token endpoint auth method to verify the client
    let method = client
        .token_endpoint_auth_method
        .as_ref()
        .ok_or(RouteError::ClientNotAllowed(client.id))?;

    client_authorization
        .credentials
        .verify(&http_client, &encrypter, method, &client)
        .await
        .map_err(|err| {
            if err.is_internal() {
                RouteError::ClientCredentialsVerification {
                    client_id: client.id,
                    source: err,
                }
            } else {
                RouteError::InvalidClientCredentials {
                    client_id: client.id,
                    source: err,
                }
            }
        })?;

    if !client.grant_types.contains(&GrantType::DeviceCode) {
        return Err(RouteError::ClientNotAllowed(client.id));
    }

    let scope = client_authorization
        .form
        .and_then(|f| f.scope)
        // XXX: Is this really how we do empty scopes?
        .unwrap_or(std::iter::empty::<ScopeToken>().collect());

    let expires_in = Duration::microseconds(20 * 60 * 1000 * 1000);

    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    let ip_address = activity_tracker.ip();

    let device_code = Alphanumeric.sample_string(&mut rng, 32);
    let user_code = Alphanumeric.sample_string(&mut rng, 6).to_uppercase();

    let device_code = repo
        .oauth2_device_code_grant()
        .add(
            &mut rng,
            &clock,
            OAuth2DeviceCodeGrantParams {
                client: &client,
                scope,
                device_code,
                user_code,
                expires_in,
                user_agent,
                ip_address,
            },
        )
        .await?;

    repo.save().await?;

    let response = DeviceAuthorizationResponse {
        device_code: device_code.device_code,
        user_code: device_code.user_code.clone(),
        verification_uri: url_builder.device_code_link(),
        verification_uri_complete: Some(url_builder.device_code_link_full(device_code.user_code)),
        expires_in,
        interval: Some(Duration::microseconds(5 * 1000 * 1000)),
    };

    Ok((
        StatusCode::OK,
        TypedHeader(CacheControl::new().with_no_store()),
        TypedHeader(Pragma::no_cache()),
        Json(response),
    ))
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};
    use mas_router::SimpleRoute;
    use oauth2_types::{
        registration::ClientRegistrationResponse, requests::DeviceAuthorizationResponse,
    };
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_device_code_request(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a client
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "token_endpoint_auth_method": "none",
                "grant_types": ["urn:ietf:params:oauth:grant-type:device_code"],
                "response_types": [],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let response: ClientRegistrationResponse = response.json();
        let client_id = response.client_id;

        // Test the happy path: the client is allowed to use the device code grant type
        let request = Request::post(mas_router::OAuth2DeviceAuthorizationEndpoint::PATH).form(
            serde_json::json!({
                "client_id": client_id,
                "scope": "openid",
            }),
        );
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        let response: DeviceAuthorizationResponse = response.json();
        assert_eq!(response.device_code.len(), 32);
        assert_eq!(response.user_code.len(), 6);
    }
}
