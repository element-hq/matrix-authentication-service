// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::{IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, SessionInfoExt, cookies::CookieJar};
use mas_data_model::{AuthorizationCode, BoxClock, BoxRng, Pkce};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::Templates;
use oauth2_types::{
    errors::{ClientError, ClientErrorCode},
    pkce,
    requests::{GrantType, Prompt, ResponseMode},
    response_type::ResponseType,
    scope::Scope,
};
use rand::{Rng, distributions::Alphanumeric};
use serde::Deserialize;
use serde_with::{StringWithSeparator, formats::SpaceSeparator, serde_as};
use thiserror::Error;
use url::Url;

use self::callback::CallbackDestination;
use crate::{BoundActivityTracker, PreferredLanguage, impl_from_error_for_route};

mod callback;
pub(crate) mod consent;

/// The URN prefix for `request_uri` values issued by the PAR endpoint
/// (RFC 9126 / MSC4305).
pub(crate) const REQUEST_URI_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";

/// Build a `request_uri` referring to the given pushed authorization grant.
#[must_use]
pub(crate) fn build_request_uri(grant_id: ulid::Ulid) -> String {
    format!("{REQUEST_URI_PREFIX}{grant_id}")
}

/// Parse a `request_uri` value back into the grant ULID it refers to.
///
/// Returns `None` if the URI does not match the expected URN format or if the
/// embedded identifier is not a valid ULID.
#[must_use]
pub(crate) fn parse_request_uri(request_uri: &url::Url) -> Option<ulid::Ulid> {
    request_uri
        .as_str()
        .strip_prefix(REQUEST_URI_PREFIX)
        .and_then(|s| s.parse().ok())
}

/// Lifetime of a `request_uri` issued by the PAR endpoint
/// (RFC 9126 §2 recommends a short lifetime; we use 60 seconds).
pub(crate) const REQUEST_URI_LIFETIME_SECONDS: i64 = 60;

/// Lifetime of a `request_uri` issued by the PAR endpoint.
#[must_use]
pub(crate) fn request_uri_lifetime() -> chrono::Duration {
    chrono::Duration::seconds(REQUEST_URI_LIFETIME_SECONDS)
}

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

    #[error("invalid or expired request_uri")]
    InvalidRequestUri,

    #[error("missing response_type parameter")]
    MissingResponseType,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ (Self::ClientNotFound
            | Self::InvalidResponseMode
            | Self::IntoCallbackDestination(_)
            | Self::UnknownRedirectUri(_)
            | Self::InvalidRequestUri
            | Self::MissingResponseType) => {
                GenericError::new(StatusCode::BAD_REQUEST, e).into_response()
            }
        }
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(self::callback::CallbackDestinationError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);

/// Query parameters accepted at the `/authorize` endpoint.
///
/// Mirrors [`oauth2_types::requests::AuthorizationRequest`] but with
/// `response_type` and `scope` made optional, because RFC 9126 §4 allows them
/// to be absent when `request_uri` is used. The handler validates that both
/// are present on the non-PAR path.
#[serde_as]
#[derive(Deserialize)]
pub(crate) struct Params {
    client_id: String,
    response_type: Option<ResponseType>,
    redirect_uri: Option<Url>,
    scope: Option<Scope>,
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

/// Given a list of response types and an optional user-defined response mode,
/// figure out what response mode must be used, and emit an error if the
/// suggested response mode isn't allowed for the given response types.
pub(crate) fn resolve_response_mode(
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
    fields(client.id = %params.client_id),
    skip_all,
)]
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
        .find_by_client_id(&params.client_id)
        .await?
        .ok_or(RouteError::ClientNotFound)?;

    // If the client supplied a `request_uri`, resolve it to a previously-pushed
    // authorization grant (RFC 9126). Other request parameters are ignored in
    // that case, per spec.
    let pushed_grant: Option<mas_data_model::AuthorizationGrant> =
        if let Some(request_uri) = params.request_uri.as_ref() {
            let grant_id = parse_request_uri(request_uri).ok_or(RouteError::InvalidRequestUri)?;
            let grant = repo
                .oauth2_authorization_grant()
                .lookup(grant_id)
                .await?
                .ok_or(RouteError::InvalidRequestUri)?;

            if grant.client_id != client.id
                || !grant.created_via_par
                || !grant.stage.is_pending()
                || clock.now() - grant.created_at > request_uri_lifetime()
            {
                return Err(RouteError::InvalidRequestUri);
            }

            Some(grant)
        } else {
            if client.require_pushed_authorization_requests {
                // The client requires PAR but didn't use it.
                // Validate the rest of the request just enough to build a
                // callback destination, so we can return a proper error.
                let response_type = params
                    .response_type
                    .as_ref()
                    .ok_or(RouteError::MissingResponseType)?;
                let redirect_uri = client.resolve_redirect_uri(&params.redirect_uri)?;
                let response_mode = resolve_response_mode(response_type, params.response_mode)?;
                let callback_destination = CallbackDestination::try_new(
                    &response_mode,
                    redirect_uri.clone(),
                    params.state.clone(),
                )?;
                return Ok(callback_destination.go(
                    &templates,
                    &locale,
                    ClientError::from(ClientErrorCode::InvalidRequest).with_description(
                        "this client must use Pushed Authorization Requests".to_owned(),
                    ),
                )?);
            }
            None
        };

    // Resolve redirect_uri / response_mode / state — from the pushed grant if
    // PAR is in use, otherwise from the inbound request parameters.
    let (redirect_uri, response_mode, callback_state) = if let Some(grant) = &pushed_grant {
        (
            grant.redirect_uri.clone(),
            grant.response_mode.clone(),
            grant.state.clone(),
        )
    } else {
        let response_type = params
            .response_type
            .as_ref()
            .ok_or(RouteError::MissingResponseType)?;
        let redirect_uri = client.resolve_redirect_uri(&params.redirect_uri)?.clone();
        let response_mode = resolve_response_mode(response_type, params.response_mode)?;
        (redirect_uri, response_mode, params.state.clone())
    };

    // Now we have a proper callback destination to go to on error
    let callback_destination =
        CallbackDestination::try_new(&response_mode, redirect_uri.clone(), callback_state)?;

    // Get the session info from the cookie
    let (session_info, cookie_jar) = cookie_jar.session_info();

    // One day, we will have try blocks
    let res: Result<Response, RouteError> = ({
        let templates = templates.clone();
        let callback_destination = callback_destination.clone();
        let locale = locale.clone();
        async move {
            let maybe_session = session_info.load_active_session(&mut repo).await?;

            let grant = if let Some(grant) = pushed_grant {
                // The grant has already been validated at the PAR endpoint.
                grant
            } else {
                let prompt = params.prompt.as_deref().unwrap_or_default();
                // Safe: pushed_grant.is_none() means we already validated
                // response_type is present above.
                let response_type = params.response_type.expect("response_type present");
                let Some(scope) = params.scope else {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::InvalidRequest)
                            .with_description("missing scope parameter".to_owned()),
                    )?);
                };

                // Check if the request/registration params are used. If so, reply
                // with the right error since we don't support them.
                if params.request.is_some() {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::RequestNotSupported),
                    )?);
                }

                // Check if the client asked for a `token` response type, and bail
                // out if it's the case, since we don't support them
                if response_type.has_token() {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::UnsupportedResponseType),
                    )?);
                }

                // If the client asked for a `id_token` response type, we must check
                // if it can use the `implicit` grant type
                if response_type.has_id_token()
                    && !client.grant_types.contains(&GrantType::Implicit)
                {
                    return Ok(callback_destination.go(
                        &templates,
                        &locale,
                        ClientError::from(ClientErrorCode::UnauthorizedClient),
                    )?);
                }

                if params.registration.is_some() {
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
                    // If the request had PKCE params but no code asked, it should
                    // get back with an error
                    if params.pkce.is_some() {
                        return Ok(callback_destination.go(
                            &templates,
                            &locale,
                            ClientError::from(ClientErrorCode::InvalidRequest),
                        )?);
                    }

                    None
                };

                repo.oauth2_authorization_grant()
                    .add(
                        &mut rng,
                        &clock,
                        &client,
                        redirect_uri.clone(),
                        scope,
                        code,
                        params.state.clone(),
                        params.nonce,
                        response_mode,
                        response_type.has_id_token(),
                        params.login_hint,
                        Some(locale.to_string()),
                        false,
                    )
                    .await?
            };

            let prompt_create = params
                .prompt
                .as_deref()
                .is_some_and(|p| p.contains(&Prompt::Create));

            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let res = match maybe_session {
                None if prompt_create => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    url_builder
                        .redirect(&mas_router::Register::and_then(continue_grant))
                        .into_response()
                }

                None => {
                    // Other cases where we don't have a session, ask for a login
                    repo.save().await?;

                    let mut url = mas_router::Login::and_then(continue_grant);

                    url = if let Some(login_hint) = grant.login_hint {
                        url.with_login_hint(login_hint)
                    } else {
                        url
                    };

                    url_builder.redirect(&url).into_response()
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
