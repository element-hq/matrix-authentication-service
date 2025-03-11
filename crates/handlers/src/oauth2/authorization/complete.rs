// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use hyper::StatusCode;
use mas_axum_utils::{SessionInfoExt, cookies::CookieJar, csrf::CsrfExt, sentry::SentryEventID};
use mas_data_model::{AuthorizationGrant, BrowserSession, Client, Device};
use mas_keystore::Keystore;
use mas_policy::{EvaluationResult, Policy};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{
    BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess,
    oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository, OAuth2SessionRepository},
    user::BrowserSessionRepository,
};
use mas_templates::{PolicyViolationContext, TemplateContext, Templates};
use oauth2_types::requests::AuthorizationResponse;
use thiserror::Error;
use tracing::warn;
use ulid::Ulid;

use super::callback::CallbackDestination;
use crate::{
    BoundActivityTracker, PreferredLanguage, impl_from_error_for_route, oauth2::generate_id_token,
};

#[derive(Debug, Error)]
pub enum RouteError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("authorization grant was not found")]
    NotFound,

    #[error("authorization grant is not in a pending state")]
    NotPending,

    #[error("failed to load client")]
    NoSuchClient,
}

impl IntoResponse for RouteError {
    fn into_response(self) -> axum::response::Response {
        let event = sentry::capture_error(&self);
        // TODO: better error pages
        let response = match self {
            RouteError::NotFound => {
                (StatusCode::NOT_FOUND, "authorization grant was not found").into_response()
            }
            RouteError::NotPending => (
                StatusCode::BAD_REQUEST,
                "authorization grant not in a pending state",
            )
                .into_response(),
            RouteError::Internal(_) | Self::NoSuchClient => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string()).into_response()
            }
        };

        (SentryEventID::from(event), response).into_response()
    }
}

impl_from_error_for_route!(mas_storage::RepositoryError);
impl_from_error_for_route!(mas_templates::TemplateError);
impl_from_error_for_route!(mas_policy::LoadError);
impl_from_error_for_route!(mas_policy::EvaluationError);
impl_from_error_for_route!(super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(super::callback::CallbackDestinationError);

#[tracing::instrument(
    name = "handlers.oauth2.authorization_complete.get",
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
    State(key_store): State<Keystore>,
    policy: Policy,
    activity_tracker: BoundActivityTracker,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    Path(grant_id): Path<Ulid>,
) -> Result<Response, RouteError> {
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    let user_agent = user_agent.map(|TypedHeader(ua)| ua.to_string());

    let grant = repo
        .oauth2_authorization_grant()
        .lookup(grant_id)
        .await?
        .ok_or(RouteError::NotFound)?;

    let callback_destination = CallbackDestination::try_from(&grant)?;
    let continue_grant = PostAuthAction::continue_grant(grant.id);

    let Some(session) = maybe_session else {
        // If there is no session, redirect to the login screen, redirecting here after
        // logout
        return Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::Login::and_then(continue_grant)),
        )
            .into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let client = repo
        .oauth2_client()
        .lookup(grant.client_id)
        .await?
        .ok_or(RouteError::NoSuchClient)?;

    match complete(
        &mut rng,
        &clock,
        &activity_tracker,
        user_agent,
        repo,
        key_store,
        policy,
        &url_builder,
        grant,
        &client,
        &session,
    )
    .await
    {
        Ok(params) => {
            let res = callback_destination.go(&templates, &locale, params).await?;
            Ok((cookie_jar, res).into_response())
        }
        Err(GrantCompletionError::RequiresReauth) => Ok((
            cookie_jar,
            url_builder.redirect(&mas_router::Reauth::and_then(continue_grant)),
        )
            .into_response()),
        Err(GrantCompletionError::RequiresConsent) => {
            let next = mas_router::Consent(grant_id);
            Ok((cookie_jar, url_builder.redirect(&next)).into_response())
        }
        Err(GrantCompletionError::PolicyViolation(grant, res)) => {
            warn!(violation = ?res, "Authorization grant for client {} denied by policy", client.id);

            let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
            let ctx = PolicyViolationContext::for_authorization_grant(grant, client)
                .with_session(session)
                .with_csrf(csrf_token.form_value())
                .with_language(locale);

            let content = templates.render_policy_violation(&ctx)?;

            Ok((cookie_jar, Html(content)).into_response())
        }
        Err(GrantCompletionError::NotPending) => Err(RouteError::NotPending),
        Err(GrantCompletionError::Internal(e)) => Err(RouteError::Internal(e)),
    }
}

#[derive(Debug, Error)]
pub enum GrantCompletionError {
    #[error(transparent)]
    Internal(Box<dyn std::error::Error + Send + Sync + 'static>),

    #[error("authorization grant is not in a pending state")]
    NotPending,

    #[error("user needs to reauthenticate")]
    RequiresReauth,

    #[error("client lacks consent")]
    RequiresConsent,

    #[error("denied by the policy")]
    PolicyViolation(AuthorizationGrant, EvaluationResult),
}

impl_from_error_for_route!(GrantCompletionError: mas_storage::RepositoryError);
impl_from_error_for_route!(GrantCompletionError: super::callback::IntoCallbackDestinationError);
impl_from_error_for_route!(GrantCompletionError: mas_policy::LoadError);
impl_from_error_for_route!(GrantCompletionError: mas_policy::EvaluationError);
impl_from_error_for_route!(GrantCompletionError: super::super::IdTokenSignatureError);

pub(crate) async fn complete(
    rng: &mut (impl rand::RngCore + rand::CryptoRng + Send),
    clock: &impl Clock,
    activity_tracker: &BoundActivityTracker,
    user_agent: Option<String>,
    mut repo: BoxRepository,
    key_store: Keystore,
    mut policy: Policy,
    url_builder: &UrlBuilder,
    grant: AuthorizationGrant,
    client: &Client,
    browser_session: &BrowserSession,
) -> Result<AuthorizationResponse, GrantCompletionError> {
    // Verify that the grant is in a pending stage
    if !grant.stage.is_pending() {
        return Err(GrantCompletionError::NotPending);
    }

    // Check if the authentication is fresh enough
    let authentication = repo
        .browser_session()
        .get_last_authentication(browser_session)
        .await?;
    let authentication = authentication.filter(|auth| auth.created_at > grant.max_auth_time());

    let Some(valid_authentication) = authentication else {
        repo.save().await?;
        return Err(GrantCompletionError::RequiresReauth);
    };

    // Run through the policy
    let res = policy
        .evaluate_authorization_grant(mas_policy::AuthorizationGrantInput {
            user: Some(&browser_session.user),
            client,
            scope: &grant.scope,
            grant_type: mas_policy::GrantType::AuthorizationCode,
            requester: mas_policy::Requester {
                ip_address: activity_tracker.ip(),
                user_agent,
            },
        })
        .await?;

    if !res.valid() {
        return Err(GrantCompletionError::PolicyViolation(grant, res));
    }

    let current_consent = repo
        .oauth2_client()
        .get_consent_for_user(client, &browser_session.user)
        .await?;

    let lacks_consent = grant
        .scope
        .difference(&current_consent)
        .filter(|scope| Device::from_scope_token(scope).is_none())
        .any(|_| true);

    // Check if the client lacks consent *or* if consent was explicitly asked
    if lacks_consent || grant.requires_consent {
        repo.save().await?;
        return Err(GrantCompletionError::RequiresConsent);
    }

    // All good, let's start the session
    let session = repo
        .oauth2_session()
        .add_from_browser_session(rng, clock, client, browser_session, grant.scope.clone())
        .await?;

    let grant = repo
        .oauth2_authorization_grant()
        .fulfill(clock, &session, grant)
        .await?;

    // Yep! Let's complete the auth now
    let mut params = AuthorizationResponse::default();

    // Did they request an ID token?
    if grant.response_type_id_token {
        params.id_token = Some(generate_id_token(
            rng,
            clock,
            url_builder,
            &key_store,
            client,
            Some(&grant),
            browser_session,
            None,
            Some(&valid_authentication),
        )?);
    }

    // Did they request an auth code?
    if let Some(code) = grant.code {
        params.code = Some(code.code);
    }

    repo.save().await?;

    activity_tracker
        .record_oauth2_session(clock, &session)
        .await;

    Ok(params)
}
