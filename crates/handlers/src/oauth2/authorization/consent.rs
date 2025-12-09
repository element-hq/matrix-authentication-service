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
use mas_data_model::{AuthorizationGrantStage, BoxClock, BoxRng, MatrixUser};
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
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
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

     // :tchap:
    let email = repo
        .user_email()
        .all(&session.user)
        .await?
        .first()
        .map(|user_email| user_email.email.clone());
    // :tchap: end

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
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
            .with_session(session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
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

   

    let ctx = ConsentContext::new(grant, client, matrix_user)
        // :tchap:
        .with_email(email)
        // :tchap: end
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
        cookie_jar, &clock, &mut rng, &templates, &locale, &mut repo,
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
        let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
            .with_session(browser_session)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);

        let content = templates.render_policy_violation(&ctx)?;

        return Ok((cookie_jar, Html(content)).into_response());
    }

    // All good, let's start the session
    let session = repo
        .oauth2_session()
        .add_from_browser_session(
            &mut rng,
            &clock,
            &client,
            &browser_session,
            grant.scope.clone(),
        )
        .await?;

    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(&clock, &session, grant)
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

    activity_tracker
        .record_oauth2_session(&clock, &session)
        .await;

    Ok((
        cookie_jar,
        callback_destination.go(&templates, &locale, params)?,
    )
        .into_response())
}
