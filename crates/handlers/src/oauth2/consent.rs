// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, Path, State},
    response::{Html, IntoResponse, Response},
};
use hyper::StatusCode;
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    sentry::SentryEventID,
    SessionInfoExt,
};
use mas_data_model::{AuthorizationGrantStage, Device};
use mas_policy::Policy;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
    BoxClock, BoxRepository, BoxRng,
};
use mas_templates::{ConsentContext, PolicyViolationContext, TemplateContext, Templates};
use thiserror::Error;
use ulid::Ulid;

use crate::{impl_from_error_for_route, BoundActivityTracker, PreferredLanguage};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync>),

    #[error(transparent)]
    Csrf(#[from] mas_axum_utils::csrf::CsrfError),

    #[error("Authorization grant not found")]
    GrantNotFound,

    #[error("Authorization grant already used")]
    GrantNotPending,

    #[error("Policy violation")]
    PolicyViolation,

    #[error("Failed to load client")]
    NoSuchClient,
}

impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event_id = sentry::capture_error(&self);
        (
            SentryEventID::from(event_id),
            StatusCode::INTERNAL_SERVER_ERROR,
        )
            .into_response()
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.consent.get",
    fields(grant.id = %grant_id),
    skip_all,
    err,
)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient)?;

    if !matches!(grant.stage, AuthorizationGrantStage::Pending) {
        return Err(RouteError::GrantNotPending);
    }

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

        let res = policy
            .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
                user: Some(&session.user),
                client: &client,
                scope: &grant.scope,
                grant_type: mas_policy::GrantType::AuthorizationCode,
                requester: mas_policy::Requester {
                    ip_address: activity_tracker.ip(),
                },
            })
            .await?;

        if res.valid() {
            let ctx = ConsentContext::new(grant, client)
                .with_session(session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            let content = templates.render_consent(&ctx)?;

            Ok((cookie_jar, Html(content)).into_response())
        } else {
            let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
                .with_session(session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            let content = templates.render_policy_violation(&ctx)?;

            Ok((cookie_jar, Html(content)).into_response())
        }
    } else {
        let login = mas_router::Login::and_continue_grant(grant_id);
        Ok((cookie_jar, url_builder.redirect(&login)).into_response())
    }
}

#[tracing::instrument(
    name = "handlers.oauth2.consent.post",
    fields(grant.id = %grant_id),
    skip_all,
    err,
)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    mut policy: Policy,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    Path(grant_id): Path<Ulid>,
    Form(form): Form<ProtectedForm<()>>,
) -> Result<Response, RouteError> {
    cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::GrantNotFound)?;
    let next = PostAuthAction::continue_grant(grant_id);

    let Some(session) = maybe_session else {
        let login = mas_router::Login::and_then(next);
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient)?;

    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&session.user),
            client: &client,
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
            },
        })
        .await?;

    if !res.valid() {
        return Err(RouteError::PolicyViolation);
    }

    // Do not consent for the "urn:matrix:org.matrix.msc2967.client:device:*" scope
    let scope_without_device = grant
        .scope
        .iter()
        .filter(|s| Device::from_scope_token(s).is_none())
        .cloned()
        .collect();

    repo.oauth2_client()
        .give_consent_for_user(
            &mut rng,
            &clock,
            &client,
            &session.user,
            &scope_without_device,
        )
        .await?;

    repo.oauth2_authorization_grant()
        .give_consent(grant)
        .await?;

    repo.save().await?;

    Ok((cookie_jar, next.go_next(&url_builder)).into_response())
}
