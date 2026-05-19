// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use axum_extra::typed_header::TypedHeader;
use headers::{CacheControl, Pragma};
use hyper::StatusCode;
use mas_axum_utils::{
    client_authorization::{ClientAuthorization, CredentialsVerificationError},
    record_error,
};
use mas_data_model::{AuthorizationCode, BoxClock, BoxRng, Pkce};
use mas_router::UrlBuilder;
use mas_storage::{BoxRepository, oauth2::OAuth2AuthorizationGrantRepository};
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce,
    requests::{GrantType, Prompt, PushedAuthorizationResponse, ResponseMode},
    response_type::ResponseType,
    scope::Scope,
};
use rand::{Rng, distributions::Alphanumeric};
use serde::Deserialize;
use serde_with::{StringWithSeparator, formats::SpaceSeparator, serde_as};
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use crate::{
    impl_from_error_for_route,
    oauth2::authorization::{build_request_uri, request_uri_lifetime, resolve_response_mode},
};

/// Body of a Pushed Authorization Request, modelled after
/// `AuthorizationRequest` but without `client_id` (which the
/// `ClientAuthorization` wrapper consumes) and without OIDC fields we don't
/// currently use (`display`, `ui_locales`, `max_age`, `id_token_hint`,
/// `acr_values`).
#[serde_as]
#[derive(Deserialize)]
pub(crate) struct Params {
    response_type: ResponseType,
    redirect_uri: Option<Url>,
    scope: Scope,
    state: Option<String>,
    response_mode: Option<ResponseMode>,
    nonce: Option<String>,

    #[serde_as(as = "Option<StringWithSeparator::<SpaceSeparator, Prompt>>")]
    #[serde(default)]
    prompt: Option<Vec<Prompt>>,

    login_hint: Option<String>,

    request: Option<String>,
    request_uri: Option<Url>,
    registration: Option<String>,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("client not found")]
    ClientNotFound,

    #[error("client {0} is not allowed to use the requested grant type")]
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

    #[error("missing form body")]
    MissingForm,

    #[error("nested request_uri is not allowed in a PAR")]
    NestedRequestUri,

    #[error("request parameter is not supported")]
    RequestNotSupported,

    #[error("registration parameter is not supported")]
    RegistrationNotSupported,

    #[error("unsupported response_type")]
    UnsupportedResponseType,

    #[error("invalid response_mode")]
    InvalidResponseMode,

    #[error("invalid redirect_uri")]
    InvalidRedirectUri(#[from] mas_data_model::InvalidRedirectUriError),

    #[error("invalid request")]
    InvalidRequest,

    #[error("prompt=none is not allowed via PAR")]
    LoginRequired,
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
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnauthorizedClient)),
            ),
            Self::MissingForm | Self::InvalidRequest => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::InvalidRequest)),
            ),
            Self::NestedRequestUri => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRequest).with_description(
                        "request_uri is not allowed in a Pushed Authorization Request".to_owned(),
                    ),
                ),
            ),
            Self::RequestNotSupported => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::RequestNotSupported)),
            ),
            Self::RegistrationNotSupported => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::RegistrationNotSupported)),
            ),
            Self::UnsupportedResponseType => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::UnsupportedResponseType)),
            ),
            Self::InvalidResponseMode => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRequest)
                        .with_description("invalid response_mode".to_owned()),
                ),
            ),
            Self::InvalidRedirectUri(_) => (
                StatusCode::BAD_REQUEST,
                Json(
                    ClientError::from(ClientErrorCode::InvalidRequest)
                        .with_description("invalid redirect_uri".to_owned()),
                ),
            ),
            Self::LoginRequired => (
                StatusCode::BAD_REQUEST,
                Json(ClientError::from(ClientErrorCode::LoginRequired)),
            ),
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.par.post",
    fields(client.id = client_authorization.client_id()),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client): State<reqwest::Client>,
    State(encrypter): State<mas_keystore::Encrypter>,
    State(_url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    client_authorization: ClientAuthorization<Params>,
) -> Result<impl IntoResponse, RouteError> {
    // 1. Fetch and authenticate the client
    let client = client_authorization
        .credentials
        .fetch(&mut repo)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

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

    // 2. Get the parsed request
    let params = client_authorization.form.ok_or(RouteError::MissingForm)?;

    // 3. Reject parameters that aren't valid in a PAR
    if params.request.is_some() {
        return Err(RouteError::RequestNotSupported);
    }
    if params.request_uri.is_some() {
        return Err(RouteError::NestedRequestUri);
    }
    if params.registration.is_some() {
        return Err(RouteError::RegistrationNotSupported);
    }

    // Per RFC 9126, prompt=none doesn't make sense via PAR — bail out early.
    if let Some(prompts) = &params.prompt
        && prompts.contains(&Prompt::None)
    {
        return Err(RouteError::LoginRequired);
    }

    // 4. Resolve redirect_uri & response_mode
    let redirect_uri = client.resolve_redirect_uri(&params.redirect_uri)?.clone();
    let response_type = params.response_type.clone();
    let response_mode = resolve_response_mode(&response_type, params.response_mode)
        .map_err(|_| RouteError::InvalidResponseMode)?;

    if response_type.has_token() {
        return Err(RouteError::UnsupportedResponseType);
    }
    if response_type.has_id_token() && !client.grant_types.contains(&GrantType::Implicit) {
        return Err(RouteError::ClientNotAllowed(client.id));
    }

    // 5. Generate authorization code + carry over PKCE
    let code: Option<AuthorizationCode> = if response_type.has_code() {
        if !client.grant_types.contains(&GrantType::AuthorizationCode) {
            return Err(RouteError::ClientNotAllowed(client.id));
        }

        let code: String = (&mut rng)
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        let pkce = params.pkce.map(|p| Pkce {
            challenge: p.code_challenge,
            challenge_method: p.code_challenge_method,
        });

        Some(AuthorizationCode { code, pkce })
    } else {
        if params.pkce.is_some() {
            return Err(RouteError::InvalidRequest);
        }
        None
    };

    // 6. Persist the grant in Pending state, flagged as PAR-created
    let grant = repo
        .oauth2_authorization_grant()
        .add(
            &mut rng,
            &clock,
            &client,
            redirect_uri,
            params.scope,
            code,
            params.state,
            params.nonce,
            response_mode,
            response_type.has_id_token(),
            params.login_hint,
            None,
            true,
        )
        .await?;

    repo.save().await?;

    // 7. Reply with the request_uri reference
    let response = PushedAuthorizationResponse {
        request_uri: build_request_uri(grant.id),
        expires_in: request_uri_lifetime(),
    };

    Ok((
        StatusCode::CREATED,
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
        errors::{ClientError, ClientErrorCode},
        registration::ClientRegistrationResponse,
        requests::PushedAuthorizationResponse,
    };
    use sqlx::PgPool;

    use crate::{
        oauth2::authorization::REQUEST_URI_PREFIX,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup},
    };

    async fn register_client(state: &TestState, metadata: serde_json::Value) -> String {
        let request = Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(metadata);
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: ClientRegistrationResponse = response.json();
        response.client_id
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_par_happy_path(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let client_id = register_client(
            &state,
            serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            }),
        )
        .await;

        let request = Request::post(mas_router::OAuth2PushedAuthorizationRequestEndpoint::PATH)
            .form(serde_json::json!({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://example.com/cb",
                "scope": "openid",
                "state": "abc",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);

        let parsed: PushedAuthorizationResponse = response.json();
        assert!(
            parsed.request_uri.starts_with(REQUEST_URI_PREFIX),
            "request_uri = {}",
            parsed.request_uri,
        );
        assert_eq!(parsed.expires_in.num_seconds(), 60);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_par_rejects_nested_request_uri(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let client_id = register_client(
            &state,
            serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            }),
        )
        .await;

        let request = Request::post(mas_router::OAuth2PushedAuthorizationRequestEndpoint::PATH)
            .form(serde_json::json!({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://example.com/cb",
                "scope": "openid",
                "request_uri": "urn:ietf:params:oauth:request_uri:foo",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidRequest);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_par_invalid_client(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // No matching client
        let request = Request::post(mas_router::OAuth2PushedAuthorizationRequestEndpoint::PATH)
            .form(serde_json::json!({
                "client_id": "00000000000000000000000000",
                "response_type": "code",
                "redirect_uri": "https://example.com/cb",
                "scope": "openid",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::UNAUTHORIZED);
        let error: ClientError = response.json();
        assert_eq!(error.error, ClientErrorCode::InvalidClient);
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_authorize_with_request_uri(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let client_id = register_client(
            &state,
            serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            }),
        )
        .await;

        // 1. Push the request
        let request = Request::post(mas_router::OAuth2PushedAuthorizationRequestEndpoint::PATH)
            .form(serde_json::json!({
                "client_id": client_id,
                "response_type": "code",
                "redirect_uri": "https://example.com/cb",
                "scope": "openid",
                "state": "abc",
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
                "code_challenge_method": "S256",
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let push_response: PushedAuthorizationResponse = response.json();

        // 2. Hit /authorize with the returned request_uri — expect a redirect to
        // login (we don't have a session in this test)
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair("request_uri", &push_response.request_uri)
            .finish();
        let uri = format!(
            "{}?{}",
            mas_router::OAuth2AuthorizationEndpoint::PATH,
            query
        );
        let request = Request::get(uri).empty();
        let response = state.request(request).await;
        // /authorize redirects to /login (302/303)
        assert!(
            response.status().is_redirection(),
            "expected redirect, got {}",
            response.status(),
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_authorize_rejects_bad_request_uri(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let client_id = register_client(
            &state,
            serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/cb"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code"],
                "response_types": ["code"],
            }),
        )
        .await;

        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &client_id)
            .append_pair(
                "request_uri",
                "urn:ietf:params:oauth:request_uri:doesnotexist",
            )
            .finish();
        let uri = format!(
            "{}?{}",
            mas_router::OAuth2AuthorizationEndpoint::PATH,
            query,
        );
        let request = Request::get(uri).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
