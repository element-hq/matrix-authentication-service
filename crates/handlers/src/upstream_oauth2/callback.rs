// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Path, State},
    http::Method,
    response::{IntoResponse, Response},
    Form,
};
use axum_extra::response::Html;
use hyper::StatusCode;
use mas_axum_utils::{cookies::CookieJar, sentry::SentryEventID};
use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderResponseMode};
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
use mas_templates::{FormPostContext, Templates};
use oauth2_types::errors::ClientErrorCode;
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use ulid::Ulid;

use super::{
    cache::LazyProviderInfos,
    client_credentials_for_provider,
    template::{environment, AttributeMappingContext},
    UpstreamSessionsCookie,
};
use crate::{impl_from_error_for_route, upstream_oauth2::cache::MetadataCache, PreferredLanguage};

#[derive(Serialize, Deserialize)]
pub struct Params {
    state: String,

    /// An extra parameter to track whether the POST request was re-made by us
    /// to the same URL to escape Same-Site cookies restrictions
    #[serde(default)]
    did_mas_repost_to_itself: bool,

    #[serde(flatten)]
    code_or_error: CodeOrError,
}

#[derive(Serialize, Deserialize)]
#[serde(untagged)]
enum CodeOrError {
    Code {
        code: String,

        #[serde(flatten)]
        extra_callback_parameters: Option<serde_json::Value>,
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

    #[error("Missing query parameters")]
    MissingQueryParams,

    #[error("Missing form parameters")]
    MissingFormParams,

    #[error("Invalid response mode, expected '{expected}'")]
    InvalidParamsMode {
        expected: UpstreamOAuthProviderResponseMode,
    },

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::JwksError);
impl_from_error_for_route!(mas_oidc_client::error::TokenAuthorizationCodeError);
impl_from_error_for_route!(mas_oidc_client::error::UserInfoError);
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
    name = "handlers.upstream_oauth2.callback.handler",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
    err,
)]
#[allow(clippy::too_many_lines, clippy::too_many_arguments)]
pub(crate) async fn handler(
    mut rng: BoxRng,
    clock: BoxClock,
    State(metadata_cache): State<MetadataCache>,
    mut repo: BoxRepository,
    State(url_builder): State<UrlBuilder>,
    State(encrypter): State<Encrypter>,
    State(keystore): State<Keystore>,
    State(client): State<reqwest::Client>,
    State(templates): State<Templates>,
    method: Method,
    PreferredLanguage(locale): PreferredLanguage,
    cookie_jar: CookieJar,
    Path(provider_id): Path<Ulid>,
    params: Option<Form<Params>>,
) -> Result<Response, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);

    let Some(Form(params)) = params else {
        if let Method::GET = method {
            return Err(RouteError::MissingQueryParams);
        }

        return Err(RouteError::MissingFormParams);
    };

    // The `Form` extractor will use the body of the request for POST requests and
    // the query parameters for GET requests. We need to then look at the method do
    // make sure it matches the expected `response_mode`
    match (provider.response_mode, method) {
        (UpstreamOAuthProviderResponseMode::Query, Method::GET) => {}
        (UpstreamOAuthProviderResponseMode::FormPost, Method::POST) => {
            // We set the cookies with a `Same-Site` policy set to `Lax`, so because this is
            // usually a cross-site form POST, we need to render a form with the
            // same values, which posts back to the same URL. However, there are
            // other valid reasons for the cookie to be missing, so to track whether we did
            // this POST ourselves, we set a flag.
            if sessions_cookie.is_empty() && !params.did_mas_repost_to_itself {
                let params = Params {
                    did_mas_repost_to_itself: true,
                    ..params
                };
                let context = FormPostContext::new_for_current_url(params).with_language(&locale);
                let html = templates.render_form_post(&context)?;
                return Ok(Html(html).into_response());
            }
        }
        (expected, _) => return Err(RouteError::InvalidParamsMode { expected }),
    }

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
    let (code, extra_callback_parameters) = match params.code_or_error {
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
        CodeOrError::Code {
            code,
            extra_callback_parameters,
        } => (code, extra_callback_parameters),
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

    let verification_data = JwtVerificationData {
        issuer: &provider.issuer,
        jwks: &jwks,
        // TODO: make that configurable
        signing_algorithm: &mas_iana::jose::JsonWebSignatureAlg::Rs256,
        client_id: &provider.client_id,
    };

    let (response, id_token_map) =
        mas_oidc_client::requests::authorization_code::access_token_with_authorization_code(
            &client,
            client_credentials,
            lazy_metadata.token_endpoint().await?,
            code,
            validation_data,
            Some(verification_data),
            clock.now(),
            &mut rng,
        )
        .await?;

    let (_header, id_token) = id_token_map
        .clone()
        .ok_or(RouteError::MissingIDToken)?
        .into_parts();

    let mut context = AttributeMappingContext::new().with_id_token_claims(id_token);
    if let Some(extra_callback_parameters) = extra_callback_parameters.clone() {
        context = context.with_extra_callback_parameters(extra_callback_parameters);
    }

    let userinfo = if provider.fetch_userinfo {
        Some(json!(
            mas_oidc_client::requests::userinfo::fetch_userinfo(
                &client,
                lazy_metadata.userinfo_endpoint().await?,
                response.access_token.as_str(),
                Some(verification_data),
                &id_token_map.ok_or(RouteError::MissingIDToken)?,
            )
            .await?
        ))
    } else {
        None
    };

    if let Some(userinfo) = userinfo.clone() {
        context = context.with_userinfo_claims(userinfo);
    }

    let context = context.build();

    let env = environment();

    let template = provider
        .claims_imports
        .subject
        .template
        .as_deref()
        .unwrap_or("{{ user.sub }}");
    let subject = env
        .render_str(template, context)
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
        .complete_with_link(
            &clock,
            session,
            &link,
            response.id_token,
            extra_callback_parameters,
            userinfo,
        )
        .await?;

    let cookie_jar = sessions_cookie
        .add_link_to_session(session.id, link.id)?
        .save(cookie_jar, &clock);

    repo.save().await?;

    Ok((
        cookie_jar,
        url_builder.redirect(&mas_router::UpstreamOAuth2Link::new(link.id)),
    )
        .into_response())
}
