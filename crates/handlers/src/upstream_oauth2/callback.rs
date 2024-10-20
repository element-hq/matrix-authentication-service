// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Path, Query, State},
    response::IntoResponse,
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar, http_client_factory::HttpClientFactory, sentry::SentryEventID,
};
use mas_data_model::UpstreamOAuthProvider;
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::requests::{
    authorization_code::AuthorizationValidationData, jose::JwtVerificationData,
};
use mas_router::UrlBuilder;
use mas_storage::{
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
    BoxClock, BoxRepository, BoxRng, Clock,
};
use oauth2_types::errors::ClientErrorCode;
use serde::Deserialize;
use thiserror::Error;
use ulid::Ulid;

use super::{
    cache::LazyProviderInfos, client_credentials_for_provider, template::environment,
    UpstreamSessionsCookie,
};
use crate::{impl_from_error_for_route, upstream_oauth2::cache::MetadataCache};

#[derive(Deserialize)]
pub struct QueryParams {
    state: String,

    #[serde(flatten)]
    code_or_error: CodeOrError,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CodeOrError {
    Code {
        code: String,
    },
    Error {
        error: ClientErrorCode,
        error_description: Option<String>,
        #[allow(dead_code)]
        error_uri: Option<String>,
    },
}

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Session not found")]
    SessionNotFound,

    #[error("Provider not found")]
    ProviderNotFound,

    #[error("Provider mismatch")]
    ProviderMismatch,

    #[error("Session already completed")]
    AlreadyCompleted,

    #[error("State parameter mismatch")]
    StateMismatch,

    #[error("Missing ID token")]
    MissingIDToken,

    #[error("Could not extract subject from ID token")]
    ExtractSubject(#[source] minijinja::Error),

    #[error("Subject is empty")]
    EmptySubject,

    #[error("Error from the provider: {error}")]
    ClientError {
        error: ClientErrorCode,
        error_description: Option<String>,
    },

    #[error("Missing session cookie")]
    MissingCookie,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::JwksError);
impl_from_error_for_route!(mas_oidc_client::error::TokenAuthorizationCodeError);
impl_from_error_for_route!(super::ProviderCredentialsError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        let response = match self {
            Self::ProviderNotFound => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
            Self::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found").into_response(),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            e => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };

        (SentryEventID::from(event_id), response).into_response()
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.callback.get",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
    err,
)]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(http_client_factory): State<HttpClientFactory>,
    State(metadata_cache): State<MetadataCache>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    State(encrypter): State<Encrypter>,
    State(keystore): State<Keystore>,
    State(client): State<reqwest::Client>,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    Query(params): Query<QueryParams>,
) -> Result<impl IntoResponse, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);
    let (session_id, _post_auth_action) = sessions_cookie
        .find_session(provider_id, &params.state)
        .map_err(|_| RouteError::MissingCookie)?;

    let session = repo
        .upstream_oauth_session()
        .lookup(session_id)
        .await?
        .ok_or(RouteError::SessionNotFound)?;

    if provider.id != session.provider_id {
        // The provider in the session cookie should match the one from the URL
        return Err(RouteError::ProviderMismatch);
    }

    if params.state != session.state_str {
        // The state in the session cookie should match the one from the params
        return Err(RouteError::StateMismatch);
    }

    if !session.is_pending() {
        // The session was already completed
        return Err(RouteError::AlreadyCompleted);
    }

    // Let's extract the code from the params, and return if there was an error
    let code = match params.code_or_error {
        CodeOrError::Error {
            error,
            error_description,
            ..
        } => {
            return Err(RouteError::ClientError {
                error,
                error_description,
            })
        }
        CodeOrError::Code { code } => code,
    };

    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &client);

    // Fetch the JWKS
    let jwks =
        mas_oidc_client::requests::jose::fetch_jwks(&client, lazy_metadata.jwks_uri().await?)
            .await?;

    // Figure out the client credentials
    let client_credentials = client_credentials_for_provider(
        &provider,
        lazy_metadata.token_endpoint().await?,
        &keystore,
        &encrypter,
    )?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    // TODO: all that should be borrowed
    let validation_data = AuthorizationValidationData {
        state: session.state_str.clone(),
        nonce: session.nonce.clone(),
        code_challenge_verifier: session.code_challenge_verifier.clone(),
        redirect_uri,
    };

    let id_token_verification_data = JwtVerificationData {
        issuer: &provider.issuer,
        jwks: &jwks,
        // TODO: make that configurable
        signing_algorithm: &mas_iana::jose::JsonWebSignatureAlg::Rs256,
        client_id: &provider.client_id,
    };

    let (response, id_token) =
        mas_oidc_client::requests::authorization_code::access_token_with_authorization_code(
            &client,
            client_credentials,
            lazy_metadata.token_endpoint().await?,
            code,
            validation_data,
            Some(id_token_verification_data),
            clock.now(),
            &mut rng,
        )
        .await?;

    let (_header, id_token) = id_token.ok_or(RouteError::MissingIDToken)?.into_parts();

    let env = {
        let mut env = environment();
        env.add_global("user", minijinja::Value::from_serialize(&id_token));
        env
    };

    let template = provider
        .claims_imports
        .subject
        .template
        .as_deref()
        .unwrap_or("{{ user.sub }}");
    let subject = env
        .render_str(template, ())
        .map_err(RouteError::ExtractSubject)?;

    if subject.is_empty() {
        return Err(RouteError::EmptySubject);
    }

    // Look for an existing link
    let maybe_link = repo
        .upstream_oauth_link()
        .find_by_subject(&provider, &subject)
        .await?;

    let link = if let Some(link) = maybe_link {
        link
    } else {
        repo.upstream_oauth_link()
            .add(&mut rng, &clock, &provider, subject)
            .await?
    };

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(&clock, session, &link, response.id_token)
        .await?;

    let cookie_jar = sessions_cookie
        .add_link_to_session(session.id, link.id)?
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::UpstreamOAuth2Link::new(link.id)),
    ))
}
