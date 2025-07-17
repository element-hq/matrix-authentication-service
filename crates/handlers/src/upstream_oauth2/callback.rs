// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use axum::{
    Form,
    extract::{Path, State},
    http::Method,
    response::{Html, IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{cookies::CookieJar, record_error};
use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderResponseMode};
use mas_jose::claims::TokenHash;
use mas_keystore::{Encrypter, Keystore};
use mas_oidc_client::requests::jose::JwtVerificationData;
use mas_router::UrlBuilder;
use mas_storage::{
    BoxClock, BoxRepository, BoxRng, Clock,
    upstream_oauth2::{
        UpstreamOAuthLinkRepository, UpstreamOAuthProviderRepository,
        UpstreamOAuthSessionRepository,
    },
};
use mas_templates::{FormPostContext, Templates};
use minijinja::Value;
use oauth2_types::{errors::ClientErrorCode, requests::AccessTokenRequest};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use ulid::Ulid;

use super::{
    UpstreamSessionsCookie,
    cache::LazyProviderInfos,
    client_credentials_for_provider,
    template::{AttributeMappingContext, environment},
};
use crate::{
    METER, PreferredLanguage, impl_from_error_for_route, upstream_oauth2::cache::MetadataCache,
};

static CALLBACK_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.upstream_oauth2.callback")
        .with_description("Number of requests to the upstream OAuth2 callback endpoint")
        .build()
});
const PROVIDER: Key = Key::from_static_str("provider");
const RESULT: Key = Key::from_static_str("result");

#[derive(Serialize, Deserialize)]
pub struct Params {
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<String>,

    /// An extra parameter to track whether the POST request was re-made by us
    /// to the same URL to escape Same-Site cookies restrictions
    #[serde(default)]
    did_mas_repost_to_itself: bool,

    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ClientErrorCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error_uri: Option<String>,

    #[serde(flatten)]
    extra_callback_parameters: Option<serde_json::Value>,
}

impl Params {
    /// Returns true if none of the fields are set
    pub fn is_empty(&self) -> bool {
        self.state.is_none()
            && self.code.is_none()
            && self.error.is_none()
            && self.error_description.is_none()
            && self.error_uri.is_none()
    }
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

    #[error("Missing state parameter")]
    MissingState,

    #[error("Missing code parameter")]
    MissingCode,

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
    InvalidResponseMode {
        expected: UpstreamOAuthProviderResponseMode,
    },

    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_oidc_client::error::DiscoveryError);
impl_from_error_for_route!(mas_oidc_client::error::JwksError);
impl_from_error_for_route!(mas_oidc_client::error::TokenRequestError);
impl_from_error_for_route!(mas_oidc_client::error::IdTokenError);
impl_from_error_for_route!(mas_oidc_client::error::UserInfoError);
impl_from_error_for_route!(super::ProviderCredentialsError);
impl_from_error_for_route!(super::cookie::UpstreamSessionNotFound);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        let response = match self {
            Self::ProviderNotFound => (StatusCode::NOT_FOUND, "Provider not found").into_response(),
            Self::SessionNotFound => (StatusCode::NOT_FOUND, "Session not found").into_response(),
            Self::Internal(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
            e => (StatusCode::BAD_REQUEST, e.to_string()).into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

#[tracing::instrument(
    name = "handlers.upstream_oauth2.callback.handler",
    fields(upstream_oauth_provider.id = %provider_id),
    skip_all,
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
    Form(params): Form<Params>,
) -> Result<Response, RouteError> {
    let provider = repo
        .upstream_oauth_provider()
        .lookup(provider_id)
        .await?
        .filter(UpstreamOAuthProvider::enabled)
        .ok_or(RouteError::ProviderNotFound)?;

    let sessions_cookie = UpstreamSessionsCookie::load(&cookie_jar);

    if params.is_empty() {
        if let Method::GET = method {
            return Err(RouteError::MissingQueryParams);
        }

        return Err(RouteError::MissingFormParams);
    }

    // The `Form` extractor will use the body of the request for POST requests and
    // the query parameters for GET requests. We need to then look at the method do
    // make sure it matches the expected `response_mode`
    match (provider.response_mode, method) {
        (Some(UpstreamOAuthProviderResponseMode::FormPost) | None, Method::POST) => {
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
        (None, _) | (Some(UpstreamOAuthProviderResponseMode::Query), Method::GET) => {}
        (Some(expected), _) => return Err(RouteError::InvalidResponseMode { expected }),
    }

    if let Some(error) = params.error {
        CALLBACK_COUNTER.add(
            1,
            &[
                KeyValue::new(PROVIDER, provider_id.to_string()),
                KeyValue::new(RESULT, "error"),
            ],
        );

        return Err(RouteError::ClientError {
            error,
            error_description: params.error_description.clone(),
        });
    }

    let Some(state) = params.state else {
        return Err(RouteError::MissingState);
    };

    let (session_id, _post_auth_action) = sessions_cookie
        .find_session(provider_id, &state)
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

    if state != session.state_str {
        // The state in the session cookie should match the one from the params
        return Err(RouteError::StateMismatch);
    }

    if !session.is_pending() {
        // The session was already completed
        return Err(RouteError::AlreadyCompleted);
    }

    // Let's extract the code from the params, and return if there was an error
    let Some(code) = params.code else {
        return Err(RouteError::MissingCode);
    };

    CALLBACK_COUNTER.add(
        1,
        &[
            KeyValue::new(PROVIDER, provider_id.to_string()),
            KeyValue::new(RESULT, "success"),
        ],
    );

    let mut lazy_metadata = LazyProviderInfos::new(&metadata_cache, &provider, &client);

    // Figure out the client credentials
    let client_credentials = client_credentials_for_provider(
        &provider,
        lazy_metadata.token_endpoint().await?,
        &keystore,
        &encrypter,
    )?;

    let redirect_uri = url_builder.upstream_oauth_callback(provider.id);

    let token_response = mas_oidc_client::requests::token::request_access_token(
        &client,
        client_credentials,
        lazy_metadata.token_endpoint().await?,
        AccessTokenRequest::AuthorizationCode(oauth2_types::requests::AuthorizationCodeGrant {
            code: code.clone(),
            redirect_uri: Some(redirect_uri),
            code_verifier: session.code_challenge_verifier.clone(),
        }),
        clock.now(),
        &mut rng,
    )
    .await?;

    let mut jwks = None;
    let mut id_token_claims = None;

    let mut context = AttributeMappingContext::new();
    if let Some(id_token) = token_response.id_token.as_ref() {
        jwks = Some(
            mas_oidc_client::requests::jose::fetch_jwks(&client, lazy_metadata.jwks_uri().await?)
                .await?,
        );

        let id_token_verification_data = JwtVerificationData {
            issuer: provider.issuer.as_deref(),
            jwks: jwks.as_ref().unwrap(),
            signing_algorithm: &provider.id_token_signed_response_alg,
            client_id: &provider.client_id,
        };

        // Decode and verify the ID token
        let id_token = mas_oidc_client::requests::jose::verify_id_token(
            id_token,
            id_token_verification_data,
            None,
            clock.now(),
        )?;

        let (_headers, mut claims) = id_token.into_parts();

        // Save a copy of the claims for later; the claims extract methods
        // remove them from the map, and we want to store the original claims.
        // We anyway need this to be a serde_json::Value
        id_token_claims = Some(
            serde_json::to_value(&claims)
                .expect("serializing a HashMap<String, Value> into a Value should never fail"),
        );

        // Access token hash must match.
        mas_jose::claims::AT_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(
                    id_token_verification_data.signing_algorithm,
                    &token_response.access_token,
                ),
            )
            .map_err(mas_oidc_client::error::IdTokenError::from)?;

        // Code hash must match.
        mas_jose::claims::C_HASH
            .extract_optional_with_options(
                &mut claims,
                TokenHash::new(id_token_verification_data.signing_algorithm, &code),
            )
            .map_err(mas_oidc_client::error::IdTokenError::from)?;

        // Nonce must match if present.
        if let Some(nonce) = session.nonce.as_deref() {
            mas_jose::claims::NONCE
                .extract_required_with_options(&mut claims, nonce)
                .map_err(mas_oidc_client::error::IdTokenError::from)?;
        }

        context = context.with_id_token_claims(claims);
    }

    if let Some(extra_callback_parameters) = params.extra_callback_parameters.clone() {
        context = context.with_extra_callback_parameters(extra_callback_parameters);
    }

    let userinfo = if provider.fetch_userinfo {
        Some(json!(match &provider.userinfo_signed_response_alg {
            Some(signing_algorithm) => {
                let jwks = match jwks {
                    Some(jwks) => jwks,
                    None => {
                        mas_oidc_client::requests::jose::fetch_jwks(
                            &client,
                            lazy_metadata.jwks_uri().await?,
                        )
                        .await?
                    }
                };

                mas_oidc_client::requests::userinfo::fetch_userinfo(
                    &client,
                    lazy_metadata.userinfo_endpoint().await?,
                    token_response.access_token.as_str(),
                    Some(JwtVerificationData {
                        issuer: provider.issuer.as_deref(),
                        jwks: &jwks,
                        signing_algorithm,
                        client_id: &provider.client_id,
                    }),
                )
                .await?
            }
            None => {
                mas_oidc_client::requests::userinfo::fetch_userinfo(
                    &client,
                    lazy_metadata.userinfo_endpoint().await?,
                    token_response.access_token.as_str(),
                    None,
                )
                .await?
            }
        }))
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
        .render_str(template, context.clone())
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
        // Try to render the human account name if we have one,
        // but just log if it fails
        let human_account_name = provider
            .claims_imports
            .account_name
            .template
            .as_deref()
            .and_then(|template| match env.render_str(template, context.clone()) {
                Ok(name) => Some(name),
                Err(e) => {
                    tracing::warn!(
                        error = &e as &dyn std::error::Error,
                        "Failed to render account name"
                    );
                    None
                }
            });

        repo.upstream_oauth_link()
            .add(&mut rng, &clock, &provider, subject, human_account_name)
            .await?
    };

    let session = repo
        .upstream_oauth_session()
        .complete_with_link(
            &clock,
            session,
            &link,
            token_response.id_token,
            id_token_claims,
            params.extra_callback_parameters,
            userinfo,
        )
        .await?;

    // Try to set can_request_admin
    if let Some(user_id) = link.user_id {
        let is_admin = determine_admin_flag(&provider, &env, context)
            .await
            .unwrap_or(false);
        let user = repo.user().lookup(user_id).await?;

        if let Some(user) = user {
            repo.user()
                .set_can_request_admin(user.clone(), is_admin)
                .await?;
        }
    }

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

async fn determine_admin_flag(
    provider: &UpstreamOAuthProvider,
    env: &minijinja::Environment<'_>,
    context: Value,
) -> Option<bool> {
    provider
        .claims_imports
        .is_admin
        .template
        .as_deref()
        .and_then(|template| match env.render_str(template, context) {
            Ok(is_admin) => match is_admin.parse() {
                Ok(is_admin) => Some(is_admin),
                Err(e) => {
                    tracing::warn!(
                        error = &e as &dyn std::error::Error,
                        "Failed to parse is_admin"
                    );
                    None
                }
            },
            Err(e) => {
                tracing::warn!(
                    error = &e as &dyn std::error::Error,
                    "Failed to render is_admin"
                );
                None
            }
        })
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderImportAction,
        UpstreamOAuthProviderImportPreference, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use minijinja::Environment;

    use super::*;

    #[tokio::test]
    async fn test_determine_admin_flag() {
        let provider = UpstreamOAuthProvider {
            id: Default::default(),
            issuer: None,
            human_name: None,
            brand_name: None,
            discovery_mode: Default::default(),
            pkce_mode: Default::default(),
            jwks_uri_override: None,
            authorization_endpoint_override: None,
            scope: "openid profile".parse().unwrap(),
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: "".to_string(),
            encrypted_client_secret: None,
            token_endpoint_signing_alg: None,
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Hs256,
            response_mode: None,
            created_at: Default::default(),
            disabled_at: None,
            claims_imports: UpstreamOAuthProviderClaimsImports {
                is_admin: UpstreamOAuthProviderImportPreference {
                    action: UpstreamOAuthProviderImportAction::Force,
                    template: Some("{{ user.is_admin }}".to_string()),
                },
                ..Default::default()
            },
            additional_authorization_parameters: vec![],
            forward_login_hint: false,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
        };

        let env = Environment::new();

        let mut id_token_claims = HashMap::new();

        // Test with is_admin set to true
        id_token_claims.insert("is_admin".to_owned(), serde_json::Value::Bool(true));

        let context = AttributeMappingContext::new()
            .with_id_token_claims(id_token_claims.clone())
            .build();

        let result = determine_admin_flag(&provider, &env, context)
            .await
            .unwrap();
        assert!(result);

        id_token_claims.clear();

        // Test with is_admin set to false
        id_token_claims.insert("is_admin".to_owned(), serde_json::Value::Bool(false));

        let context = AttributeMappingContext::new()
            .with_id_token_claims(id_token_claims.clone())
            .build();

        let result = determine_admin_flag(&provider, &env, context)
            .await
            .unwrap();
        assert!(!result);

        id_token_claims.clear();

        // Test with invalid admin field set to true
        id_token_claims.insert(
            "can_request_admin".to_owned(),
            serde_json::Value::Bool(true),
        );

        let context = AttributeMappingContext::new()
            .with_id_token_claims(id_token_claims.clone())
            .build();

        let result = determine_admin_flag(&provider, &env, context).await;
        assert!(result.is_none());

        id_token_claims.clear();

        // Test with no claims
        let context = AttributeMappingContext::new()
            .with_id_token_claims(id_token_claims.clone())
            .build();

        let result = determine_admin_flag(&provider, &env, context).await;
        assert!(result.is_none());
    }
}
