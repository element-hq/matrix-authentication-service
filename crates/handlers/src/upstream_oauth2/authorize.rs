// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::Context;
use axum::{
    extract::{Path, Query, State},
    http,
    response::{IntoResponse, Redirect},
};
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, cookies::CookieJar};
use mas_data_model::UpstreamOAuthProvider;
use mas_http::RequestBuilderExt;
use mas_oidc_client::requests::authorization_code::AuthorizationRequestData;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxClock, BoxRepository, BoxRng,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
};
use oauth2_types::requests::PushedAuthorizationResponse;
use thiserror::Error;
use ulid::Ulid;
use url::Url;

use super::{UpstreamSessionsCookie, cache::LazyProviderInfos};
use crate::{
    impl_from_error_for_route, upstream_oauth2::cache::MetadataCache,
    views::shared::OptionalPostAuthAction,
};

#[derive(Debug, Error)]
pub(crate) enum RouteError {
    #[error("Provider not found")]
    ProviderNotFound,

    #[error(transparent)]
    Internal(Box<dyn std::error::Error>),
}

impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::AuthorizationError);
impl_from_error_for_route!(mas_storage::RepositoryError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            e @ Self::ProviderNotFound => {
                GenericError::new(StatusCode::NOT_FOUND, e).into_response()
            }
            Self::Internal(e) => InternalError::new(e).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.authorize.get",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    State(metadata_cache): State<MetadataCache>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    State(http_client): State<reqwest::Client>,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    Query(query): Query<OptionalPostAuthAction>,
) -> Result<impl IntoResponse, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    // First, discover the provider
    // This is done lazyly according to provider.discovery_mode and the various
    // endpoint overrides
    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &http_client);
    lazy_metadata.maybe_discover().await?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let mut data = AuthorizationRequestData::new(
        provider.client_id.clone(),
        provider.scope.clone(),
        redirect_uri,
    );

    if let Some(response_mode) = provider.response_mode {
        data = data.with_response_mode(response_mode.into());
    }

    // Forward the raw login hint upstream for the provider to handle however it
    // sees fit
    if provider.forward_login_hint {
        if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.post_auth_action {
            if let Some(login_hint) = repo
                .oauth2_authorization_grant()
                .lookup(*id)
                .await?
                .and_then(|grant| grant.login_hint)
            {
                data = data.with_login_hint(login_hint);
            }
        }
    }

    let data = if let Some(methods) = lazy_metadata.pkce_methods().await? {
        data.with_code_challenge_methods_supported(methods)
    } else {
        data
    };

    // Build an authorization request for it
    let (mut url, data) = if lazy_metadata
        .require_pushed_authorization_requests()
        .await?
    {
        // The upstream provider enforces Pushed Authorization Requests (PAR)
        let url = lazy_metadata
            .pushed_authorization_request_endpoint()
            .await?
            .context("provider should have a PAR endpoint")
            .map_err(|e| RouteError::Internal(e.into()))?
            .clone();

        // Construct the body for the PAR request
        let client_id = data.client_id.clone();
        let (query, validation_data) =
            mas_oidc_client::requests::authorization_code::build_par_body(data, &mut rng)?;

        // POST to the PAR endpoint
        let response = http_client
            .post(url)
            .header(
                http::header::CONTENT_TYPE,
                mime::APPLICATION_WWW_FORM_URLENCODED.as_ref(),
            )
            .body(query)
            .send_traced()
            .await
            .map_err(|e| RouteError::Internal(e.into()))?;

        // Extract the request_uri from the response
        let json = response
            .json::<PushedAuthorizationResponse>()
            .await
            .map_err(|e| RouteError::Internal(e.into()))?;
        let request_uri =
            Url::parse(&json.request_uri).map_err(|e| RouteError::Internal(e.into()))?;

        // Build the final authorization URL
        let url = mas_oidc_client::requests::authorization_code::build_par_authorization_url(
            lazy_metadata.authorization_endpoint().await?.clone(),
            client_id,
            request_uri,
        )?;

        (url, validation_data)
    } else {
        mas_oidc_client::requests::authorization_code::build_authorization_url(
            lazy_metadata.authorization_endpoint().await?.clone(),
            data,
            &mut rng,
        )?
    };

    // We do that in a block because params borrows url mutably
    {
        // Add any additional parameters to the query
        let mut params = url.query_pairs_mut();
        for (key, value) in &provider.additional_authorization_parameters {
            params.append_pair(key, value);
        }
    }

    let session = repo
        .upstream_oauth_session()
        .add(
            &mut rng,
            &clock,
            &provider,
            data.state.clone(),
            data.code_challenge_verifier,
            data.nonce,
        )
        .await?;

    let cookie_jar = UpstreamSessionsCookie::load(&cookie_jar)
        .add(session.id, provider.id, data.state, query.post_auth_action)
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((cookie_jar, Redirect::temporary(url.as_str())))
}
