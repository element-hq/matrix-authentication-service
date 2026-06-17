// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::BTreeMap;

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Redirect},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, UpstreamOAuthProvider};
use mas_oidc_client::requests::authorization_code::AuthorizationRequestData;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
};
use minijinja::context;
use thiserror::Error;
use ulid::Ulid;

use super::{UpstreamSessionsCookie, cache::LazyProviderInfos, template::environment};
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

    // Look up the downstream authorization grant once, if there is one, so
    // we can both (a) populate the MiniJinja template context for the
    // `additional_authorization_parameters` rendering and (b) keep the
    // `forward_login_hint` shortcut working for deployments that haven't
    // re-run config sync yet.
    let downstream_grant =
        if let Some(PostAuthAction::ContinueAuthorizationGrant { id }) = &query.post_auth_action {
            repo.oauth2_authorization_grant().lookup(*id).await?
        } else {
            None
        };

    let raw_parameters: BTreeMap<String, String> = downstream_grant
        .as_ref()
        .map(|grant| grant.raw_parameters.clone())
        .unwrap_or_default();

    // Back-compat: honour `forward_login_hint` as long as the operator
    // hasn't explicitly added a `login_hint` template entry to
    // `additional_authorization_parameters`. The CLI config sync will
    // also inject a template entry on the next sync, so this branch
    // mainly catches the moment between an upgrade and the next sync.
    if provider.forward_login_hint
        && !provider
            .additional_authorization_parameters
            .iter()
            .any(|(k, _)| k == "login_hint")
        && let Some(login_hint) = downstream_grant
            .as_ref()
            .and_then(|grant| grant.login_hint.clone())
    {
        data = data.with_login_hint(login_hint);
    }

    let data = if let Some(methods) = lazy_metadata.pkce_methods().await? {
        data.with_code_challenge_methods_supported(methods)
    } else {
        data
    };

    // Build an authorization request for it
    let (mut url, data) = mas_oidc_client::requests::authorization_code::build_authorization_url(
        lazy_metadata.authorization_endpoint().await?.clone(),
        data,
        &mut rng,
    )?;

    // Render the templated `additional_authorization_parameters` and
    // append the non-empty results to the URL query.
    {
        let mut pairs = url.query_pairs_mut();
        for (key, value) in render_additional_authorization_parameters(
            provider.id,
            &provider.additional_authorization_parameters,
            &raw_parameters,
        ) {
            pairs.append_pair(key, value.as_str());
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

/// Render each `additional_authorization_parameters` template against
/// the raw downstream query parameters, dropping templates that render
/// to empty strings, and logging-and-skipping any that fail to render.
fn render_additional_authorization_parameters<'a>(
    provider_id: Ulid,
    templates: &'a [(String, String)],
    raw_parameters: &BTreeMap<String, String>,
) -> impl Iterator<Item = (&'a str, String)> {
    let env = environment();
    let ctx = context! { params => raw_parameters };

    templates.iter().filter_map(move |(key, template)| {
        match env.render_str(template, &ctx).map(|v| v.trim().to_owned()) {
            Ok(value) if !value.is_empty() => Some((key.as_str(), value)),
            Ok(_) => {
                // Empty render — drop the parameter rather than forwarding
                // `?key=`.
                None
            }
            Err(error) => {
                tracing::warn!(
                    error = &error as &dyn std::error::Error,
                    upstream_oauth_provider.id = %provider_id,
                    parameter.key = %key,
                    "Failed to render upstream authorization parameter template",
                );
                None
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ulid::Ulid;

    use super::render_additional_authorization_parameters;

    fn params(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
        entries
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn renders_static_values_unchanged() {
        let templates = [("kc_idp_hint".to_owned(), "saml".to_owned())];
        let rendered =
            render_additional_authorization_parameters(Ulid::nil(), &templates, &params(&[]))
                .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }

    #[test]
    fn renders_template_from_downstream_params() {
        let templates = [
            (
                "login_hint".to_owned(),
                "{{ params.login_hint }}".to_owned(),
            ),
            (
                "acr_values".to_owned(),
                "{{ params.acr_values }}".to_owned(),
            ),
        ];
        let rendered = render_additional_authorization_parameters(
            Ulid::nil(),
            &templates,
            &params(&[("login_hint", "alice"), ("acr_values", "mfa")]),
        )
        .collect::<Vec<_>>();
        assert_eq!(
            rendered,
            vec![
                ("login_hint", "alice".to_owned()),
                ("acr_values", "mfa".to_owned()),
            ]
        );
    }

    #[test]
    fn drops_parameters_that_render_to_empty() {
        let templates = [
            (
                "login_hint".to_owned(),
                "{{ params.login_hint }}".to_owned(),
            ),
            ("kc_idp_hint".to_owned(), "saml".to_owned()),
        ];
        let rendered =
            render_additional_authorization_parameters(Ulid::nil(), &templates, &params(&[]))
                .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }

    #[test]
    fn drops_failing_template_but_keeps_others() {
        let templates = [
            ("broken".to_owned(), "{{ params. }}".to_owned()),
            ("kc_idp_hint".to_owned(), "saml".to_owned()),
        ];
        let rendered =
            render_additional_authorization_parameters(Ulid::nil(), &templates, &params(&[]))
                .collect::<Vec<_>>();
        assert_eq!(rendered, vec![("kc_idp_hint", "saml".to_owned())]);
    }
}
