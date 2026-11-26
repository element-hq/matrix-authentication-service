// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{sync::Arc, time::Duration};

use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use hyper::StatusCode;
use mas_axum_utils::{
    GenericError, InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{
    AuthorizationGrant, AuthorizationGrantStage, BoxClock, BoxRng, BrowserSession, Client,
    MatrixUser,
};
use mas_i18n::DataLocale;
use mas_keystore::Keystore;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use oauth2_types::requests::AuthorizationResponse;
use thiserror::Error;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::{
    BoundActivityTracker, PreferredLanguage, impl_from_error_for_route,
    oauth2::generate_id_token,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] mas_axum_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant {0} already used")]
    GrantNotPending(Ulid),

    #[error("Failed to load client {0}")]
    NoSuchClient(Ulid),
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(crate::session::SessionLoadError);
impl_from_error_for_route!(crate::oauth2::IdTokenSignatureError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Internal(e) => InternalError::new(e).into_response(),
            e @ Self::NoSuchClient(_) => InternalError::new(Box::new(e)).into_response(),
            e @ Self::GrantNotFound => GenericError::new(StatusCode::NOT_FOUND, e).into_response(),
            e @ Self::GrantNotPending(_) => {
                GenericError::new(StatusCode::CONFLICT, e).into_response()
            }
            e @ Self::Csrf(_) => GenericError::new(StatusCode::BAD_REQUEST, e).into_response(),
        }
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.consent.get",
    fields(grant.id = %grant_id),
    skip_all,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(key_store): State<Keystore>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::continue_grant(grant_id)),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    let user_agent = user_agent.map(|ua| ua.to_string());

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let session_counts = count_user_sessions_for_limiting(&mut repo, &session.user).await?;

    let input = mas_policy::AuthorizationGrantInput {
        user: Some(&session.user),
        client: &client,
        session_counts: Some(session_counts),
        scope: &grant.scope,
        grant_type: mas_policy::GrantType::AuthorizationCode,
        requester: mas_policy::Requester {
            ip_address: activity_tracker.ip(),
            user_agent,
        },
        now: clock.now(),
    };

    let res = policy.evaluate_authorization_grant(input.clone()).await?;
    if !res.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    if policy.evaluate_skip_consent(input).await? {
        tracing::info!(
            user.id = %session.user.id,
            client.id = %client.id,
            "Approving the authorization grant without consent, as allowed by the policy"
        );

        let callback_destination = CallbackDestination::try_from(&grant)?;

        return approve_grant(
            &mut rng,
            &clock,
            &locale,
            &templates,
            &url_builder,
            &key_store,
            repo,
            cookie_jar,
            &session,
            &client,
            grant,
            callback_destination,
        )
        .await;
    }

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    // Fetch informations about the user. This is purely cosmetic, so we let it
    // fail and put a 1s timeout to it in case we fail to query it
    // XXX: we're likely to need this in other places
    let localpart = &session.user.username;
    let display_name = match tokio::time::timeout(
        Duration::from_secs(1),
        homeserver.query_user(localpart),
    )
    .await
    {
        Ok(Ok(user)) => user.displayname,
        Ok(Err(err)) => {
            tracing::warn!(
                error = &*err as &dyn std::error::Error,
                localpart,
                "Failed to query user"
            );
            None
        }
        Err(_) => {
            tracing::warn!(localpart, "Timed out while querying user");
            None
        }
    };

    let matrix_user = MatrixUser {
        mxid: homeserver.mxid(localpart),
        display_name,
    };

    let ctx = ConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_consent(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[tracing::instrument(
    name = "handlers.oauth2.authorization.consent.post",
    fields(grant.id = %grant_id),
    skip_all,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(key_store): State<Keystore>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    Path(grant_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, RouteError> {
    cookie_jar.verify_form(&clock, form)?;

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::continue_grant(grant_id)),
        &mut repo,
    )
    .await?
    {
        SessionOrFallback::MaybeSession {
            cookie_jar,
            maybe_session,
            ..
        } => (cookie_jar, maybe_session),
        SessionOrFallback::Fallback { response } => return Ok(response),
    };

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    let user_agent = user_agent.map(|ua| ua.to_string());

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;
    let callback_destination = CallbackDestination::try_from(&grant)?;

    let Some(browser_session) = maybe_session else {
        let next = PostAuthAction::continue_grant(grant_id);
        let login = mas_router::Login::and_then(next);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &browser_session)
        .await;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient(grant.client_id))?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending(grant.id));
    }

    let session_counts = count_user_sessions_for_limiting(&mut repo, &browser_session.user).await?;

    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
            now: clock.now(),
        })
        .await?;

    if !res.valid() {
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(browser_session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    // All good, let's fulfill the grant with the browser session.
    approve_grant(
        &mut rng,
        &clock,
        &locale,
        &templates,
        &url_builder,
        &key_store,
        repo,
        cookie_jar,
        &browser_session,
        &client,
        grant,
        callback_destination,
    )
    .await
}

/// Fulfills the grant with the browser session, and sends the response to the
/// client
async fn approve_grant(
    rng: &mut BoxRng,
    clock: &BoxClock,
    locale: &DataLocale,
    templates: &Templates,
    url_builder: &UrlBuilder,
    key_store: &Keystore,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    browser_session: &BrowserSession,
    client: &Client,
    grant: AuthorizationGrant,
    callback_destination: CallbackDestination,
) -> Result<Response, RouteError> {
    // The OAuth2 session will be created later at token exchange time.
    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(clock, browser_session, grant)
        .await?;

    let mut params = AuthorizationResponse::default();

    // Did they request an ID token?
    if grant.response_type_id_token {
        // Fetch the last authentication
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            rng,
            clock,
            url_builder,
            key_store,
            client,
            Some(&grant),
            browser_session,
            None,
            last_authentication.as_ref(),
        )?);
    }

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    Ok((
        cookie_jar,
        callback_destination.go(templates, locale, params)?,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::SessionInfoExt;
    use mas_matrix::{HomeserverConnection, ProvisionRequest};
    use mas_router::SimpleRoute;
    use oauth2_types::registration::ClientRegistrationResponse;
    use sqlx::PgPool;

    use crate::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, policy_factory, setup,
    };

    /// Starts an authorization for the client, and requests its consent page
    async fn request_consent(
        state: &TestState,
        cookies: &CookieHelper,
        client_id: &str,
    ) -> hyper::Response<String> {
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", client_id)
            .append_pair("redirect_uri", "https://example.com/callback")
            .append_pair(
                "scope",
                "openid urn:matrix:client:api:* urn:matrix:client:device:ABCDEFGHIJ",
            )
            .append_pair("state", "state")
            .append_pair("response_mode", "query")
            .finish();
        let request = Request::get(format!(
            "{}?{query}",
            mas_router::OAuth2AuthorizationEndpoint::PATH
        ))
        .empty();
        let response = state.request(cookies.with_cookies(request)).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let consent = response.headers()[LOCATION].to_str().unwrap();

        state
            .request(cookies.with_cookies(Request::get(consent).empty()))
            .await
    }

    /// Creates a user with a browser session, and stores its cookie
    async fn sign_in(state: &TestState, cookies: &CookieHelper, username: &str) {
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, username.to_owned())
            .await
            .unwrap();
        state
            .homeserver_connection
            .provision_user(&ProvisionRequest::new(&user.username, &user.sub, false))
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        cookies.import(state.cookie_jar().set_session(&browser_session));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_skip_consent(pool: PgPool) {
        setup();
        let mut state = TestState::from_pool(pool).await.unwrap();

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
        let ClientRegistrationResponse { client_id, .. } = response.json();

        let alice = CookieHelper::new();
        sign_in(&state, &alice, "alice").await;
        let bob = CookieHelper::new();
        sign_in(&state, &bob, "bob").await;

        // Without policy data, consent is asked
        let response = request_consent(&state, &alice, &client_id).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Use another account"));

        state.policy_factory = policy_factory(
            mas_policy::BaseData {
                server_name: "example.com".to_owned(),
                session_limit: None,
            },
            serde_json::json!({
                "skip_consent": {
                    "client_ids": [client_id],
                    "max_account_age_seconds": 600,
                },
            }),
        )
        .await
        .unwrap();

        // The new account is sent straight back to the client with a code
        let response = request_consent(&state, &alice, &client_id).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let location: url::Url = response.headers()[LOCATION]
            .to_str()
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(location.path(), "/callback");
        let (_, code) = location
            .query_pairs()
            .find(|(key, _)| key == "code")
            .unwrap();

        let request =
            Request::post(mas_router::OAuth2TokenEndpoint::PATH).form(serde_json::json!({
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://example.com/callback",
                "client_id": client_id,
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        // Once the account has a session, consent is asked again
        let response = request_consent(&state, &alice, &client_id).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Use another account"));

        // Once an account without sessions is older than the window, consent
        // is asked again
        state.clock.advance(chrono::Duration::seconds(601));
        let response = request_consent(&state, &bob, &client_id).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Use another account"));
    }
}
