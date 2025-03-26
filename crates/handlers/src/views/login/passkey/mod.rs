// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod cookie;

use axum::{
    Form,
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::TypedHeader;
use cookie::UserPasskeyChallenges;
use hyper::StatusCode;
use mas_axum_utils::{
    FancyError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{SiteConfig, UserAgent};
use mas_i18n::DataLocale;
use mas_router::UrlBuilder;
use mas_storage::{BoxClock, BoxRepository, BoxRng, Clock, RepositoryAccess};
use mas_templates::{
    AccountInactiveContext, FieldError, FormError, FormState, PasskeyLoginContext,
    PasskeyLoginFormField, TemplateContext, Templates, ToFormState,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use ulid::Ulid;

use crate::{
    BoundActivityTracker, Limiter, PreferredLanguage, RequesterFingerprint,
    session::{SessionOrFallback, load_session_or_fallback},
    views::shared::OptionalPostAuthAction,
    webauthn::{Webauthn, WebauthnError},
};

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct PasskeyLoginForm {
    id: String,
    response: String,
}

impl ToFormState for PasskeyLoginForm {
    type Field = PasskeyLoginFormField;
}

#[tracing::instrument(name = "handlers.views.login.passkey.get", skip_all, err)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(webauthn): State<Webauthn>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
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

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    };

    if !site_config.passkeys_enabled {
        // If passkeys are disabled, redirect to the login page here
        return Ok(url_builder
            .redirect(&mas_router::Login::from(query.post_auth_action))
            .into_response());
    }

    render(
        locale,
        cookie_jar,
        FormState::default(),
        webauthn,
        query,
        repo,
        &clock,
        &mut rng,
        &templates,
    )
    .await
}

#[tracing::instrument(name = "handlers.views.login.passkey.post", skip_all, err)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(limiter): State<Limiter>,
    State(webauthn): State<Webauthn>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    requester: RequesterFingerprint,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Form(form): Form<ProtectedForm<PasskeyLoginForm>>,
) -> Result<Response, FancyError> {
    let user_agent = user_agent.map(|ua| UserAgent::parse(ua.as_str().to_owned()));
    if !site_config.passkeys_enabled {
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    let mut form_state = form.to_form_state();

    // Setting Ulid directly on the form field shows an ugly text only form parsing
    // error about invalid length if the ID is somehow missing
    let ulid = Ulid::from_string(&form.id).unwrap_or_default();
    if ulid.is_nil() {
        form_state.add_error_on_field(PasskeyLoginFormField::Id, FieldError::Required);
    }

    if form.response.is_empty() {
        form_state.add_error_on_field(PasskeyLoginFormField::Response, FieldError::Required);
    }

    if !form_state.is_valid() {
        return render(
            locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
        )
        .await;
    }

    // Find the challenge
    let challenge = match webauthn
        .lookup_challenge(&mut repo, &clock, ulid, None)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(c) => c,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return render(
                locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
            )
            .await;
        }
    };

    // Validate cookie
    let challenges = UserPasskeyChallenges::load(&cookie_jar);
    if !challenges.contains(&challenge) {
        let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
        return render(
            locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
        )
        .await;
    }

    // Consume and complete the challenge already as we'll give them a new one if
    // there's an error
    let cookie_jar = challenges
        .consume_challenge(&challenge)?
        .save(cookie_jar, &clock);

    let challenge = repo
        .user_passkey()
        .complete_challenge(&clock, challenge)
        .await?;

    // Get the user and passkey from the authenticator response
    let (response, user, passkey) = match webauthn
        .discover_credential(&mut repo, form.response)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(v) => v,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return render(
                locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
            )
            .await;
        }
    };

    // XXX: Reusing the password rate limiter. Maybe it should be renamed to login
    // ratelimiter or have a passkey specific one
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(error = &e as &dyn std::error::Error);
        let form_state = form_state.with_error_on_form(FormError::RateLimitExceeded);
        return render(
            locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
        )
        .await;
    }

    // Validate the passkey
    let passkey = match webauthn
        .finish_passkey_authentication(&mut repo, &clock, challenge, response, passkey)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(p) => p,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return render(
                locale, cookie_jar, form_state, webauthn, query, repo, &clock, &mut rng, &templates,
            )
            .await;
        }
    };

    // Now that we have checked the passkey, we now want to show an error if
    // the user is locked or deactivated
    if user.deactivated_at.is_some() {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = AccountInactiveContext::new(user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let content = templates.render_account_deactivated(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    if user.locked_at.is_some() {
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = AccountInactiveContext::new(user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let content = templates.render_account_locked(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    // At this point, we should have a 'valid' user. In case we missed something, we
    // want it to crash in tests/debug builds
    debug_assert!(user.is_valid());

    // Start a new session
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    // And mark it as authenticated by the passkey
    repo.browser_session()
        .authenticate_with_passkey(&mut rng, &clock, &user_session, &passkey)
        .await?;

    repo.save().await?;

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let cookie_jar = cookie_jar.set_session(&user_session);
    let reply = query.go_next(&url_builder);
    Ok((cookie_jar, reply).into_response())
}

async fn render(
    locale: DataLocale,
    cookie_jar: CookieJar,
    mut form_state: FormState<PasskeyLoginFormField>,
    webauthn: Webauthn,
    action: OptionalPostAuthAction,
    mut repo: BoxRepository,
    clock: &impl Clock,
    rng: &mut (dyn RngCore + Send),
    templates: &Templates,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, &mut *rng);

    let (options, challenge) = webauthn
        .start_passkey_authentication(&mut repo, rng, clock)
        .await?;

    form_state.set_value(PasskeyLoginFormField::Id, Some(challenge.id.to_string()));

    let cookie_jar = UserPasskeyChallenges::load(&cookie_jar)
        .add(&challenge)
        .save(cookie_jar, clock);

    let ctx = PasskeyLoginContext::default()
        .with_form_state(form_state)
        .with_options(options);

    let next = action.load_context(&mut repo).await?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    repo.save().await?;

    let content = templates.render_passkey_login(&ctx)?;
    Ok((cookie_jar, Html(content)).into_response())
}
