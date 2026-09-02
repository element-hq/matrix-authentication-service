// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::collections::BTreeMap;

use axum::{
    extract::State,
    response::{IntoResponse, Response},
};
use axum_extra::extract::Query;
use hyper::StatusCode;
use mas_axum_utils::{GenericError, InternalError, SessionInfoExt, cookies::CookieJar};
use mas_data_model::{AuthorizationCode, BoxClock, BoxRng, Pkce};
use mas_router::{LoginMethodHint, PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
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
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ (Self::ClientNotFound
            | Self::InvalidResponseMode
            | Self::IntoCallbackDestination(_)
            | Self::UnknownRedirectUri(_)) => {
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

#[derive(Deserialize)]
pub(crate) struct Params {
    #[serde(flatten)]
    auth: AuthorizationRequest,

    #[serde(flatten)]
    pkce: Option<pkce::AuthorizationRequest>,

    /// Which login method the client would like us to use. MAS-specific, so
    /// not part of the [`AuthorizationRequest`] wire type.
    #[serde(rename = "io.element.login_method")]
    login_method: Option<LoginMethodHint>,
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
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    // Extract the query parameters twice: once to get the raw query string,
    // and once to parse it into a structured `Params` object.
    Query(raw_parameters): Query<BTreeMap<String, String>>,
    Query(params): Query<Params>,
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

            // The hint is advisory: a value we can't make sense of is dropped, so
            // that a misconfigured client still gets a working login page.
            let login_method = match params.login_method {
                Some(LoginMethodHint::Unknown(value)) => {
                    tracing::warn!(
                        login_method = value,
                        "Unknown io.element.login_method value, ignoring it"
                    );
                    None
                }
                hint @ (Some(LoginMethodHint::Password | LoginMethodHint::UpstreamOAuth2(_))
                | None) => hint,
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
                    Some(locale.to_string()),
                    raw_parameters,
                )
                .await?;
            let continue_grant = PostAuthAction::continue_grant(grant.id);

            let res = match maybe_session {
                None if prompt.contains(&Prompt::Create) => {
                    // Client asked for a registration, show the registration prompt
                    repo.save().await?;

                    let mut url = mas_router::Register::and_then(continue_grant);

                    if let Some(login_method) = login_method {
                        url = url.with_login_method(login_method);
                    }

                    url_builder.redirect(&url).into_response()
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

                    if let Some(login_method) = login_method {
                        url = url.with_login_method(login_method);
                    }

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

#[cfg(test)]
mod test {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::SessionInfoExt as _;
    use mas_data_model::AuthorizationGrant;
    use mas_router::{LoginMethodHint, Route, SimpleRoute};
    use mas_storage::{RepositoryAccess, oauth2::OAuth2AuthorizationGrantRepository};
    use oauth2_types::registration::ClientRegistrationResponse;
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    const PROVIDER_ID: &str = "01HFRQFT5QFMJFGF01P7JAV2ME";

    /// Register a client which can do the authorization code flow, and return
    /// its client id.
    async fn client(state: &TestState) -> String {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));

        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let registration: ClientRegistrationResponse = response.json();
        registration.client_id
    }

    fn authorize_url(client_id: &str, extra: &str) -> String {
        format!(
            "/authorize?response_type=code&client_id={client_id}\
             &redirect_uri=https%3A%2F%2Fexample.com%2Fcallback&scope=openid&state=state{extra}"
        )
    }

    fn location(response: &hyper::Response<String>) -> &str {
        response
            .headers()
            .get(LOCATION)
            .expect("missing Location header")
            .to_str()
            .unwrap()
    }

    /// Load the grant the `/login` or `/register` redirect continues.
    async fn grant_from_redirect(state: &TestState, location: &str) -> AuthorizationGrant {
        let id: Ulid = location
            .split("id=")
            .nth(1)
            .expect("no grant id in the redirect")
            .split('&')
            .next()
            .unwrap()
            .parse()
            .unwrap();

        let mut repo = state.repository().await.unwrap();
        repo.oauth2_authorization_grant()
            .lookup(id)
            .await
            .unwrap()
            .unwrap()
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_forwarded_to_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(
            &client_id,
            &format!("&io.element.login_method=upstream-oauth2:{PROVIDER_ID}"),
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = location(&response).to_owned();
        assert!(location.starts_with("/login?"), "location: {location}");
        let grant = grant_from_redirect(&state, &location).await;
        assert_eq!(
            location,
            mas_router::Login::and_continue_grant(grant.id)
                .with_login_method(LoginMethodHint::UpstreamOAuth2(
                    Ulid::from_string(PROVIDER_ID).unwrap()
                ))
                .path_and_query()
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_forwarded_to_register(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(
            &client_id,
            "&prompt=create&io.element.login_method=password",
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = location(&response).to_owned();
        assert!(location.starts_with("/register?"), "location: {location}");
        let grant = grant_from_redirect(&state, &location).await;
        assert_eq!(
            location,
            mas_router::Register::and_continue_grant(grant.id)
                .with_login_method(LoginMethodHint::Password)
                .path_and_query()
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_forwarded_to_register_with_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(
            &client_id,
            &format!("&prompt=create&io.element.login_method=upstream-oauth2:{PROVIDER_ID}"),
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = location(&response).to_owned();
        assert!(location.starts_with("/register?"), "location: {location}");
        let grant = grant_from_redirect(&state, &location).await;
        assert_eq!(
            location,
            mas_router::Register::and_continue_grant(grant.id)
                .with_login_method(LoginMethodHint::UpstreamOAuth2(
                    Ulid::from_string(PROVIDER_ID).unwrap()
                ))
                .path_and_query()
        );
    }

    /// An unusable value is dropped from the redirect, but it still lands in
    /// the grant's raw parameters like every other query parameter.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_unknown_login_method_hint_is_dropped(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(
            &client_id,
            "&io.element.login_method=not-a-login-method",
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);

        let location = location(&response).to_owned();
        assert!(
            !location.contains("io.element.login_method"),
            "location: {location}"
        );

        let grant = grant_from_redirect(&state, &location).await;
        assert_eq!(
            grant.raw_parameters.get("io.element.login_method").unwrap(),
            "not-a-login-method"
        );
    }

    /// An empty value is treated as absent.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_empty_login_method_hint_is_dropped(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(&client_id, "&io.element.login_method=")).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            !location(&response).contains("io.element.login_method"),
            "location: {}",
            location(&response)
        );
    }

    /// With an existing session the hint is irrelevant: we go to the consent
    /// page as usual.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_ignored_with_a_session(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;
        let cookies = CookieHelper::new();

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        cookies.import(state.cookie_jar().set_session(&browser_session));

        let request = Request::get(authorize_url(
            &client_id,
            "&io.element.login_method=password",
        ))
        .empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            location(&response).starts_with("/consent/"),
            "location: {}",
            location(&response)
        );
    }

    /// A duplicated parameter is ambiguous, and the query extractor rejects it
    /// rather than picking one of the values.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_duplicated_login_method_hint_is_rejected(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let client_id = client(&state).await;

        let request = Request::get(authorize_url(
            &client_id,
            "&io.element.login_method=password&io.element.login_method=upstream-oauth2:01HFRQFT5QFMJFGF01P7JAV2ME",
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::BAD_REQUEST);
    }
}
