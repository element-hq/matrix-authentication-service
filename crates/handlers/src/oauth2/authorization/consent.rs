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
use http::HeaderValue;
use hyper::{StatusCode, header::CONTENT_SECURITY_POLICY};
use mas_axum_utils::{
    GenericError, InternalError,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{AuthorizationGrant, AuthorizationGrantStage, BoxClock, BoxRng, MatrixUser};
use mas_keystore::Keystore;
use mas_matrix::HomeserverConnection;
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxRepository,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
};
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use oauth2_types::requests::{AuthorizationResponse, ResponseMode};
use thiserror::Error;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::{
    BoundActivityTracker, Csp, PreferredLanguage, impl_from_error_for_route,
    oauth2::generate_id_token,
    session::{SessionOrFallback, count_user_sessions_for_limiting, load_session_or_fallback},
};

/// The policy for the consent and policy violation pages.
///
/// Both render a "Cancel" button which, in the `form_post` response mode,
/// posts a form straight to the client's redirect URI instead of back to us.
fn page_csp(csp: &Csp, grant: &AuthorizationGrant) -> HeaderValue {
    match grant.response_mode {
        ResponseMode::FormPost => csp.human_posting_to(&grant.redirect_uri),
        _ => csp.human(),
    }
}

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
    State(csp): State<Csp>,
    State(url_builder): State<UrlBuilder>,
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

    // We can close the repository early, we don't need it at this point
    repo.save().await?;

    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            session_counts: Some(session_counts),
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;
    if !res.valid() {
        let policy = page_csp(&csp, &grant);
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((
            cookie_jar,
            [(CONTENT_SECURITY_POLICY, policy)],
            Html(content),
        )
            .into_response());
    }

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

    let policy = page_csp(&csp, &grant);
    let ctx = ConsentContext::new(grant, client, matrix_user)
        .with_session(session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_consent(&ctx)?;

    Ok((
        cookie_jar,
        [(CONTENT_SECURITY_POLICY, policy)],
        Html(content),
    )
        .into_response())
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
    State(csp): State<Csp>,
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
        })
        .await?;

    if !res.valid() {
        let policy = page_csp(&csp, &grant);
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client, res.violations)
            .with_session(browser_session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((
            cookie_jar,
            [(CONTENT_SECURITY_POLICY, policy)],
            Html(content),
        )
            .into_response());
    }

    // All good, let's fulfill the grant with the browser session.
    // The OAuth2 session will be created later at token exchange time.
    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&clock, &browser_session, grant)
        .await?;

    let mut params = AuthorizationResponse::default();

    // Did they request an ID token?
    if grant.response_type_id_token {
        // Fetch the last authentication
        let last_authentication = repo
            .browser_session()
            .get_last_authentication(&browser_session)
            .await?;

        params.id_token = Some(generate_id_token(
            &mut rng,
            &clock,
            &url_builder,
            &key_store,
            &client,
            Some(&grant),
            &browser_session,
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
        callback_destination.go(&templates, &csp, &locale, params)?,
    )
        .into_response())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use hyper::{Request, StatusCode, header::CONTENT_SECURITY_POLICY};
    use mas_axum_utils::SessionInfoExt;
    use mas_data_model::AuthorizationCode;
    use mas_router::{Route, SimpleRoute};
    use oauth2_types::{
        registration::ClientRegistrationResponse,
        requests::ResponseMode,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;

    use crate::test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup};

    /// Render the consent page for a grant with the given response mode, and
    /// return its `Content-Security-Policy`.
    async fn consent_page_csp(state: &TestState, response_mode: ResponseMode) -> String {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://client.example.com/",
                "redirect_uris": ["https://client.example.com/callback"],
                "token_endpoint_auth_method": "none",
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let registration: ClientRegistrationResponse = response.json();

        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        let client = repo
            .oauth2_client()
            .find_by_client_id(&registration.client_id)
            .await
            .unwrap()
            .unwrap();
        let grant = repo
            .oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                &client,
                "https://client.example.com/callback".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "thisisaverysecurecode".to_owned(),
                    pkce: None,
                }),
                Some("test-state-value".to_owned()),
                None,
                response_mode,
                false,
                None,
                None,
                BTreeMap::new(),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&browser_session));

        let request = cookies
            .with_cookies(Request::get(mas_router::Consent(grant.id).path().as_ref()).empty());
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);

        response
            .headers()
            .get(CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned()
    }

    /// The consent page's "Cancel" button posts a form straight to the client
    /// in `form_post` response mode, so the policy has to name it
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_content_security_policy(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let csp = consent_page_csp(&state, ResponseMode::FormPost).await;
        assert!(
            csp.contains("form-action 'self' https://client.example.com;"),
            "expected the client origin in the policy, got {csp:?}"
        );
    }

    /// In the other response modes that button is a plain link, so the page
    /// keeps the unmodified policy
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_content_security_policy_query_mode(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let csp = consent_page_csp(&state, ResponseMode::Query).await;
        assert_eq!(csp, state.csp.human());
    }
}
