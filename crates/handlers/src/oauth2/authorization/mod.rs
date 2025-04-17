// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{SessionInfoExt, cookies::CookieJar, record_error};
use mas_data_model::{AuthorizationCode, Pkce};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxClock, BoxRepository, BoxRng,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::Templates;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce,
    requests::{AuthorizationRequest, GrantType, Prompt, ResponseMode},
    response_type::ResponseType,
};
use rand::{Rng, distributions::Alphanumeric};
use serde::Deserialize;
use thiserror::Error;

use self::callback::CallbackDestination;
use crate::{BoundActivityTracker, PreferredLanguage, impl_from_error_for_route};

mod callback;
pub(crate) mod consent;

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("could not find client")]
    ClientNotFound,

    #[error("invalid response mode")]
    InvalidResponseMode,

    #[error("invalid parameters")]
    IntoCallbackDestination(#[from] self::callback::IntoCallbackDestinationError),

    #[error("invalid redirect uri")]
    UnknownRedirectUri(#[from] mas_data_model::InvalidRedirectUriError),
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let sentry_event_id = record_error!(self, Self::Internal(_));
        // TODO: better error pages
        let response = match self {
            RouteError::Internal(e) => {
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
            RouteError::ClientNotFound => {
                (StatusCode::BAD_REQUEST, "could not find client").into_response()
            }
            RouteError::InvalidResponseMode => {
                (StatusCode::BAD_REQUEST, "invalid response mode").into_response()
            }
            RouteError::IntoCallbackDestination(e) => {
                (StatusCode::BAD_REQUEST, e.to_string()).into_response()
            }
            RouteError::UnknownRedirectUri(e) => (
                StatusCode::BAD_REQUEST,
                format!("Invalid redirect URI ({e})"),
            )
                .into_response(),
        };

        (sentry_event_id, response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(self::callback::CallbackDestinationError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);

#[derive(Deserialize)]
pub(crate) struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,
}

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
fn resolve_response_mode(
    response_type: &ResponseType,
    suggested_response_mode: Option<ResponseMode>,
) -> Result<ResponseMode, RouteError> {
    use ResponseMode as M;

    // If the response type includes either "token" or "id_token", the default
    // response mode is "fragment" and the response mode "query" must not be
    // used
    if response_type.has_token() || response_type.has_id_token() {
        match suggested_response_mode {
            None => Ok(M::Fragment),
            Some(M::Query) => Err(RouteError::InvalidResponseMode),
            Some(mode) => Ok(mode),
        }
    } else {
        // In other cases, all response modes are allowed, defaulting to "query"
        Ok(suggested_response_mode.unwrap_or(M::Query))
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.get",
    fields(client.id = %params.auth.client_id),
    skip_all,
)]
#[allow(clippy::too_many_lines)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Form(params): Form<Params>,
) -> Result<Response, RouteError> {
    // First, figure out what client it is
    let client = repo
        .oauth2_client()
        .find_by_client_id(&params.auth.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // And resolve the redirect_uri and response_mode
    let redirect_uri = client
        .resolve_redirect_uri(&params.auth.redirect_uri)?
        .clone();
    let response_type = params.auth.response_type;
    let response_mode = resolve_response_mode(&response_type, params.auth.response_mode)?;

    // Now we have a proper callback destination to go to on error
    let callback_destination = CallbackDestination::try_new(
        &response_mode,
        redirect_uri.clone(),
        params.auth.state.clone(),
    )?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();

    // One day, we will have try blocks
    let res: Result<Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        let locale = locale.clone();
        async move {
            let maybe_session = session_info.load_active_session(&mut repo).await?;
            let prompt = params.auth.prompt.as_deref().unwrap_or_default();

            // Check if the request/request_uri/registration params are used. If so, reply
            // with the right error since we don't support them.
            if params.auth.request.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestNotSupported),
                )?);
            }

            if params.auth.request_uri.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RequestUriNotSupported),
                )?);
            }

            // Check if the client asked for a `token` response type, and bail out if it's
            // the case, since we don't support them
            if response_type.has_token() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnsupportedResponseType),
                )?);
            }

            // If the client asked for a `id_token` response type, we must check if it can
            // use the `implicit` grant type
            if response_type.has_id_token() && !client.grant_types.contains(&GrantType::Implicit) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::UnauthorizedClient),
                )?);
            }

            if params.auth.registration.is_some() {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::RegistrationNotSupported),
                )?);
            }

            // Fail early if prompt=none; we never let it go through
            if prompt.contains(&Prompt::None) {
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::LoginRequired),
                )?);
            }

            let code: Option<AuthorizationCode> = if response_type.has_code() {
                // Check if it is allowed to use this grant type
                if !client.grant_types.contains(&GrantType::AuthorizationCode) {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::UnauthorizedClient),
                    )?);
                }

                // 32 random alphanumeric characters, about 190bit of entropy
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
                // If the request had PKCE params but no code asked, it should get back with an
                // error
                if params.pkce.is_some() {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::InvalidRequest),
                    )?);
                }

                None
            };

            let grant = repo
                .oauth2_authorization_grant()
                .add(
                    &mut rng,
                    &clock,
                    &client,
                    redirect_uri.clone(),
                    params.auth.scope,
                    code,
                    params.auth.state.clone(),
                    params.auth.nonce,
                    response_mode,
                    response_type.has_id_token(),
                    params.auth.login_hint,
                )
                .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let res = match maybe_session {
                None if prompt.contains(&Prompt::Create) => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    url_builder
                        .redirect(&mas_router::Register::and_then(continue_grant))
                        .into_response()
                }

                None => {
                    // Other cases where we don't have a session, ask for a login
                    repo.save().await?;

                    url_builder
                        .redirect(&mas_router::Login::and_then(continue_grant))
                        .into_response()
                }

                Some(user_session) => {
                    // TODO: better support for prompt=create when we have a session
                    repo.save().await?;

                    activity_tracker
                        .record_browser_session(&clock, &user_session)
                        .await;
                    url_builder
                        .redirect(&mas_router::Consent(grant.id))
                        .into_response()
                }
            };

            Ok(res)
        }
    })
    .await;

    let response = match res {
        Ok(r) => r,
        Err(err) => {
            tracing::error!(message = &err as &dyn std::error::Error);
            callback_destination.go(
                &templates,
                &locale,
                ClientError::from(ClientErrorCode::ServerError),
            )?
        }
    };

    Ok((cookie_jar, response).into_response())
}
