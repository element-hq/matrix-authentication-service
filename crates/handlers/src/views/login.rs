// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::{Arc, LazyLock};

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use hyper::StatusCode;
use mas_axum_utils::{
    InternalError, RecordAsRequester, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{AuthenticationMethod, BoxClock, BoxRng, Clock};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_router::{PostAuthAction, UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    BoxRepository, RepositoryAccess,
    oauth2::OAuth2AuthorizationGrantRepository,
    upstream_oauth2::{UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository},
    user::{
        BrowserSessionRepository, LoginSessionRepository, UserPasswordRepository, UserRepository,
    },
};
use mas_templates::{
    FieldError, FormError, FormState, LoginContext, LoginFormField, TemplateContext, Templates,
    ToFormState, WelcomeBackContext,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use rand::Rng;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use super::shared::{LoginHint, OptionalPostAuthAction, QueryLoginHint};
use crate::{
    BoundActivityTracker, Limiter, METER, PreferredLanguage, RequesterFingerprint, SiteConfig,
    passwords::{PasswordManager, PasswordVerificationResult},
    session::{SessionOrFallback, load_session_or_fallback, render_account_inactive},
};

static PASSWORD_LOGIN_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("mas.user.password_login_attempt")
        .with_description("Number of password login attempts")
        .with_unit("{attempt}")
        .build()
});
const RESULT: Key = Key::from_static_str("result");

#[derive(Debug, Deserialize, Serialize)]
pub(crate) struct LoginForm {
    username: String,
    password: String,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[tracing::instrument(name = "handlers.views.login.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    Query(query_login_hint): Query<QueryLoginHint>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        query.post_auth_action.clone(),
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

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    // If we're continuing an authorization grant that carries a trusted target
    // (the resolved outcome of a verified `id_token_hint`), streamline the
    // re-authentication: either auto-redirect to the upstream provider the
    // target last used, or render a "welcome back" page pre-filled with the
    // target's username. `maybe_welcome_back` hands the cookie jar back
    // untouched when it doesn't handle the request.
    let (cookie_jar, welcome_back_form_state) = match maybe_welcome_back(
        &mut rng,
        &clock,
        locale.clone(),
        &url_builder,
        &templates,
        &mut repo,
        &site_config,
        &homeserver,
        cookie_jar,
        &query,
    )
    .await?
    {
        Ok(response) => return Ok(response),
        Err((cookie_jar, form_state)) => (cookie_jar, form_state),
    };

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
    if !site_config.password_login_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    render(
        locale,
        cookie_jar,
        welcome_back_form_state,
        query,
        &mut repo,
        &clock,
        &mut rng,
        &templates,
        &homeserver,
        &site_config,
        query_login_hint,
    )
    .await
}

#[tracing::instrument(name = "handlers.views.login.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(password_manager): State<PasswordManager>,
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(limiter): State<Limiter>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    requester: RequesterFingerprint,
    (Query(query), Query(query_login_hint)): (Query<OptionalPostAuthAction>, Query<QueryLoginHint>),
    cookie_jar: CookieJar,
    user_agent: Option<TypedHeader<headers::UserAgent>>,
    Form(form): Form<ProtectedForm<LoginForm>>,
) -> Result<Response, InternalError> {
    let user_agent = user_agent.map(|ua| ua.as_str().to_owned());
    if !site_config.password_login_enabled {
        // XXX: is it necessary to have better errors here?
        return Ok(StatusCode::METHOD_NOT_ALLOWED.into_response());
    }

    let form = cookie_jar.verify_form(&clock, form)?;

    // Validate the form
    let mut form_state = form.to_form_state();

    if form.username.is_empty() {
        form_state.add_error_on_field(LoginFormField::Username, FieldError::Required);
    }

    if form.password.is_empty() {
        form_state.add_error_on_field(LoginFormField::Password, FieldError::Required);
    }

    if !form_state.is_valid() {
        tracing::warn!("Invalid login form: {form_state:?}");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render_credential_failure(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            query_login_hint,
        )
        .await;
    }

    // Extract the localpart of the MXID, fallback to the bare username
    let username = homeserver
        .localpart(&form.username)
        .unwrap_or(&form.username);

    // First, lookup the user
    let Some(user) = get_user_by_email_or_by_username(&site_config, &mut repo, username).await?
    else {
        tracing::warn!(username, "User not found");
        let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render_credential_failure(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            query_login_hint,
        )
        .await;
    };

    // Check the rate limit
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(error = &e as &dyn std::error::Error, "ratelimit exceeded");
        let form_state = form_state.with_error_on_form(FormError::RateLimitExceeded);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render_credential_failure(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            query_login_hint,
        )
        .await;
    }

    // And its password
    let Some(user_password) = repo.user_password().active(&user).await? else {
        // There is no password for this user, but we don't want to disclose that. Show
        // a generic 'invalid credentials' error instead
        tracing::warn!(username, "No password for user");
        let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render_credential_failure(
            locale,
            cookie_jar,
            form_state,
            query,
            &mut repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            query_login_hint,
        )
        .await;
    };

    let password = Zeroizing::new(form.password);

    // Verify the password, and upgrade it on-the-fly if needed
    let user_password = match password_manager
        .verify_and_upgrade(
            &mut rng,
            user_password.version,
            password,
            user_password.hashed_password.clone(),
        )
        .await
    {
        Ok(PasswordVerificationResult::Success(Some((version, new_password_hash)))) => {
            // Save the upgraded password
            repo.user_password()
                .add(
                    &mut rng,
                    &clock,
                    &user,
                    version,
                    new_password_hash,
                    Some(&user_password),
                )
                .await?
        }
        Ok(PasswordVerificationResult::Success(None)) => user_password,
        Ok(PasswordVerificationResult::Failure) => {
            tracing::warn!(username, "Failed to verify/upgrade password for user");
            let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "mismatch")]);
            return render_credential_failure(
                locale,
                cookie_jar,
                form_state,
                query,
                &mut repo,
                &clock,
                &mut rng,
                &templates,
                &homeserver,
                &site_config,
                query_login_hint,
            )
            .await;
        }
        Err(err) => return Err(InternalError::from_anyhow(err)),
    };

    // Now that we have checked the user password, we now want to show an error if
    // the user is locked or deactivated, while preserving the post-auth action so
    // the sign-in button on the interstitial resumes the flow the user started.
    if user.deactivated_at.is_some() {
        tracing::warn!(username, "User is deactivated");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let (cookie_jar, response) = render_account_inactive(
            &templates,
            &locale,
            &clock,
            &mut rng,
            cookie_jar,
            user,
            query.post_auth_action.clone(),
        )?;
        return Ok((cookie_jar, response).into_response());
    }

    if user.locked_at.is_some() {
        tracing::warn!(username, "User is locked");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let (cookie_jar, response) = render_account_inactive(
            &templates,
            &locale,
            &clock,
            &mut rng,
            cookie_jar,
            user,
            query.post_auth_action.clone(),
        )?;
        return Ok((cookie_jar, response).into_response());
    }

    // At this point, we should have a 'valid' user. In case we missed something, we
    // want it to crash in tests/debug builds
    debug_assert!(user.is_valid());

    // Start a new session
    let user_session = repo
        .browser_session()
        .add(&mut rng, &clock, &user, user_agent)
        .await?;

    // And mark it as authenticated by the password
    repo.browser_session()
        .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
        .await?;

    repo.save().await?;

    // Attribute the rest of this request (and its log line) to the user that
    // just logged in.
    user.maybe_record_as_requester();

    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let cookie_jar = cookie_jar.set_session(&user_session);
    let reply = query.go_next(&url_builder);
    Ok((cookie_jar, reply).into_response())
}

async fn get_user_by_email_or_by_username<R: RepositoryAccess>(
    site_config: &SiteConfig,
    repo: &mut R,
    username_or_email: &str,
) -> Result<Option<mas_data_model::User>, R::Error> {
    if site_config.login_with_email_allowed && username_or_email.contains('@') {
        let maybe_user_email = repo.user_email().find_by_email(username_or_email).await?;

        if let Some(user_email) = maybe_user_email {
            let user = repo.user().lookup(user_email.user_id).await?;

            if user.is_some() {
                return Ok(user);
            }
        }
    }

    let user = repo.user().find_by_username(username_or_email).await?;

    Ok(user)
}

/// How a trusted welcome-back target last authenticated, recovered from the
/// grant's `target_user_session_id` (the `BrowserSession` the `id_token_hint`'s
/// `sid` claim pointed at).
enum WelcomeBackMethod {
    /// The most-recent authentication on that session was a password login.
    Password,
    /// The most-recent authentication on that session was through this
    /// upstream provider, which is still enabled.
    Upstream { provider_id: ulid::Ulid },
    /// The method can't be confirmed: a stale/absent session, no
    /// authentication recorded, or a since-disabled provider (whose
    /// auto-redirect would dead-end at `ProviderNotFound`).
    Unknown,
}

/// A trusted welcome-back target: the user resolved from a verified
/// `id_token_hint`, how they last authenticated, and the action being
/// continued.
struct WelcomeBackTarget {
    user: mas_data_model::User,
    method: WelcomeBackMethod,
    action: PostAuthAction,
}

/// Resolve the trusted welcome-back target of the flow this `/login` request
/// continues, if any.
///
/// A resolved target can come off an authorization grant (`id_token_hint` on
/// `/authorize`) or a login session (`id_token_hint` on the
/// account-management deeplink). Returns `None` when there is nothing to
/// streamline: the request doesn't continue either flow, the flow carries no
/// *trusted* `target_user_id` (an untrusted `login_hint` never resolves one),
/// the login session is no longer valid, or the target user vanished since
/// the flow started.
///
/// This is the single resolution shared by the GET ([`maybe_welcome_back`])
/// and POST ([`render_credential_failure`]) paths so they stay in lockstep.
async fn welcome_back_target(
    repo: &mut BoxRepository,
    clock: &impl Clock,
    query: &OptionalPostAuthAction,
) -> Result<Option<WelcomeBackTarget>, InternalError> {
    // Only authorization grants and login sessions carry a resolved target.
    let target_user_ids = match query.post_auth_action {
        Some(PostAuthAction::ContinueAuthorizationGrant { id }) => {
            let Some(grant) = repo.oauth2_authorization_grant().lookup(id).await? else {
                return Ok(None);
            };
            (grant.target_user_id, grant.target_user_session_id)
        }
        Some(PostAuthAction::ContinueLoginSession { id }) => {
            let Some(login_session) = repo.login_session().lookup(id).await? else {
                return Ok(None);
            };
            if !login_session.is_valid(clock.now()) {
                return Ok(None);
            }
            (
                login_session.target_user_id,
                login_session.target_user_session_id,
            )
        }
        _ => return Ok(None),
    };

    // Only act on a *trusted* target (`id_token_hint`); an untrusted `login_hint`
    // has no resolved `target_user_id`.
    let (Some(target_user_id), target_user_session_id) = target_user_ids else {
        return Ok(None);
    };

    let Some(user) = repo.user().lookup(target_user_id).await? else {
        // The target user vanished since the flow started.
        return Ok(None);
    };

    let method = welcome_back_method(repo, target_user_session_id).await?;

    Ok(Some(WelcomeBackTarget {
        user,
        method,
        action: query
            .post_auth_action
            .clone()
            .expect("checked to be a continue action above"),
    }))
}

/// Recover how the trusted target last authenticated, following the flow's
/// `target_user_session_id` to its most-recent [`Authentication`].
///
/// [`Authentication`]: mas_data_model::Authentication
async fn welcome_back_method(
    repo: &mut BoxRepository,
    target_user_session_id: Option<ulid::Ulid>,
) -> Result<WelcomeBackMethod, InternalError> {
    let Some(session_id) = target_user_session_id else {
        return Ok(WelcomeBackMethod::Unknown);
    };
    let Some(session) = repo.browser_session().lookup(session_id).await? else {
        return Ok(WelcomeBackMethod::Unknown);
    };
    let Some(authentication) = repo
        .browser_session()
        .get_last_authentication(&session)
        .await?
    else {
        return Ok(WelcomeBackMethod::Unknown);
    };

    let upstream_oauth2_session_id = match authentication.authentication_method {
        AuthenticationMethod::Password { .. } => return Ok(WelcomeBackMethod::Password),
        AuthenticationMethod::UpstreamOAuth2 {
            upstream_oauth2_session_id,
        } => upstream_oauth2_session_id,
        AuthenticationMethod::Unknown => return Ok(WelcomeBackMethod::Unknown),
    };

    let Some(upstream_session) = repo
        .upstream_oauth_session()
        .lookup(upstream_oauth2_session_id)
        .await?
    else {
        return Ok(WelcomeBackMethod::Unknown);
    };
    // Only auto-redirect to a provider that is currently enabled; a
    // since-disabled provider would make the redirect hit `ProviderNotFound`.
    let Some(provider) = repo
        .upstream_oauth_provider()
        .lookup(upstream_session.provider_id)
        .await?
    else {
        return Ok(WelcomeBackMethod::Unknown);
    };
    if !provider.enabled() {
        return Ok(WelcomeBackMethod::Unknown);
    }

    Ok(WelcomeBackMethod::Upstream {
        provider_id: provider.id,
    })
}

/// Decide whether `/login` should render the dedicated welcome-back *password*
/// page, and for whom: a trusted target whose most-recent authentication is
/// *confirmed* to be a password login, on an instance with password login
/// enabled (the page posts to the `/login` password handler, which 405s when
/// it is disabled).
async fn welcome_back_password_target(
    repo: &mut BoxRepository,
    clock: &impl Clock,
    site_config: &SiteConfig,
    query: &OptionalPostAuthAction,
) -> Result<Option<mas_data_model::User>, InternalError> {
    if !site_config.password_login_enabled {
        return Ok(None);
    }

    Ok(welcome_back_target(repo, clock, query)
        .await?
        .filter(|target| matches!(target.method, WelcomeBackMethod::Password))
        .map(|target| target.user))
}

/// Build the [`WelcomeBackContext`] (including the consent-style user card) for
/// the given target `user` and `form_state`, and render the welcome-back
/// password page.
#[expect(clippy::too_many_arguments)]
async fn render_welcome_back(
    rng: impl Rng,
    clock: &impl Clock,
    locale: DataLocale,
    templates: &Templates,
    repo: &mut BoxRepository,
    homeserver: &dyn HomeserverConnection,
    cookie_jar: CookieJar,
    query: &OptionalPostAuthAction,
    user: &mas_data_model::User,
    form_state: FormState<LoginFormField>,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);

    // Build the consent-style user card for the target, mirroring `consent.rs`.
    let matrix_user = crate::best_effort_matrix_user(homeserver, &user.username).await;

    let ctx =
        WelcomeBackContext::new(user.username.clone(), matrix_user).with_form_state(form_state);
    let next = query
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_welcome_back(&ctx)?;
    Ok((cookie_jar, Html(content)).into_response())
}

/// Handle the "welcome back" mode of `/login`.
///
/// When `/login` continues a `ContinueAuthorizationGrant` whose grant carries a
/// trusted `target_user_id` (the resolved outcome of a verified
/// `id_token_hint`), streamline re-authentication for that user:
///
/// * if the target's most-recent authentication was via an upstream provider
///   (read off the `BrowserSession` the `sid` claim pointed at) that is still
///   enabled, auto-redirect to that provider's authorize endpoint — mirroring
///   the password-disabled-single-provider shortcut in [`get`]; otherwise
/// * if the target's most-recent authentication was *confirmed* to be a
///   password login and the instance has password login enabled, render the
///   dedicated "welcome back" template (via [`render_welcome_back`]), posting
///   to the existing `/login` POST.
///
/// Anything else — no grant, no `target_user_id`, a vanished target, a
/// stale/unknown `sid` (so the most-recent method can't be confirmed), a
/// since-disabled upstream provider, or a password target on a
/// password-login-disabled instance — falls through to the caller's normal
/// `/login` handling. In that case the cookie jar and a form state (pre-filled
/// with the target's username when we know it, so the generic page renders both
/// password and upstream buttons for the right account) are handed back as
/// `Err((cookie_jar, form_state))`.
// Mirrors the argument list of the surrounding `/login` handler; threading a
// struct here would be more ceremony than it's worth.
#[expect(clippy::too_many_arguments)]
async fn maybe_welcome_back(
    rng: &mut (impl Rng + Send),
    clock: &impl Clock,
    locale: DataLocale,
    url_builder: &UrlBuilder,
    templates: &Templates,
    repo: &mut BoxRepository,
    site_config: &SiteConfig,
    homeserver: &dyn HomeserverConnection,
    cookie_jar: CookieJar,
    query: &OptionalPostAuthAction,
) -> Result<Result<Response, (CookieJar, FormState<LoginFormField>)>, InternalError> {
    let Some(WelcomeBackTarget {
        user,
        method,
        action,
    }) = welcome_back_target(repo, clock, query).await?
    else {
        return Ok(Err((cookie_jar, FormState::default())));
    };

    // From here on we know the target user, so any fall-through should pre-fill
    // the generic login page with their username.
    let fallback_form_state = || {
        let mut form_state = FormState::<LoginFormField>::default();
        form_state.set_value(LoginFormField::Username, Some(user.username.clone()));
        form_state
    };

    match method {
        // The `sid` claim resolved to a still-existing session whose
        // most-recent authentication was via an upstream provider that is
        // still enabled: auto-redirect to that provider — mirroring the
        // password-disabled single-provider shortcut in `get`.
        WelcomeBackMethod::Upstream { provider_id } => {
            let destination = UpstreamOAuth2Authorize::new(provider_id).and_then(action);
            Ok(Ok(
                (cookie_jar, url_builder.redirect(&destination)).into_response()
            ))
        }

        // Confirmed password last-authentication on a password-login-enabled
        // instance: render the dedicated welcome-back password page.
        WelcomeBackMethod::Password if site_config.password_login_enabled => {
            let response = render_welcome_back(
                rng,
                clock,
                locale,
                templates,
                repo,
                homeserver,
                cookie_jar,
                query,
                &user,
                FormState::default(),
            )
            .await?;
            Ok(Ok(response))
        }

        // A stale/absent session, an unknown method, or a
        // password-login-disabled instance: fall through to the generic login
        // page (which renders both password and upstream buttons per the
        // account config) rather than an unusable password-only form.
        WelcomeBackMethod::Password | WelcomeBackMethod::Unknown => {
            Ok(Err((cookie_jar, fallback_form_state())))
        }
    }
}

fn handle_login_hint(
    mut ctx: LoginContext,
    query_login_hint: &QueryLoginHint,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
) -> LoginContext {
    let form_state = ctx.form_state_mut();

    // Do not override username if coming from a failed login attempt
    if form_state.has_value(LoginFormField::Username) {
        return ctx;
    }

    let value = match query_login_hint.parse_login_hint(homeserver.homeserver()) {
        LoginHint::Mxid(mxid) => Some(mxid.localpart().to_owned()),
        LoginHint::Email(email) if site_config.login_with_email_allowed => Some(email.to_string()),
        _ => None,
    };
    form_state.set_value(LoginFormField::Username, value);

    ctx
}

async fn render(
    locale: DataLocale,
    cookie_jar: CookieJar,
    form_state: FormState<LoginFormField>,
    action: OptionalPostAuthAction,
    repo: &mut impl RepositoryAccess,
    clock: &impl Clock,
    rng: impl Rng,
    templates: &Templates,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
    query_login_hint: QueryLoginHint,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, rng);
    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    let ctx = LoginContext::default()
        .with_form_state(form_state)
        .with_upstream_providers(providers);

    let ctx = handle_login_hint(ctx, &query_login_hint, homeserver, site_config);

    let next = action
        .load_context(repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_login(&ctx)?;
    Ok((cookie_jar, Html(content)).into_response())
}

/// Re-render the appropriate page after a credential failure in the POST
/// handler.
///
/// When the request is a welcome-back *password* page (per the shared
/// [`welcome_back_password_target`] predicate), re-render that page with the
/// error so the End-User stays on the welcome-back flow. Otherwise fall back to
/// the generic login page via [`render`], preserving the previous behavior for
/// non-welcome-back requests.
#[expect(clippy::too_many_arguments)]
async fn render_credential_failure(
    locale: DataLocale,
    cookie_jar: CookieJar,
    form_state: FormState<LoginFormField>,
    query: OptionalPostAuthAction,
    repo: &mut BoxRepository,
    clock: &impl Clock,
    rng: &mut (impl Rng + Send),
    templates: &Templates,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
    query_login_hint: QueryLoginHint,
) -> Result<Response, InternalError> {
    let maybe_user = welcome_back_password_target(repo, clock, site_config, &query).await?;
    if let Some(user) = maybe_user {
        return render_welcome_back(
            rng, clock, locale, templates, repo, homeserver, cookie_jar, &query, &user, form_state,
        )
        .await;
    }

    render(
        locale,
        cookie_jar,
        form_state,
        query,
        repo,
        clock,
        rng,
        templates,
        homeserver,
        site_config,
        query_login_hint,
    )
    .await
}

#[cfg(test)]
mod test {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION, X_FRAME_OPTIONS},
    };
    use mas_data_model::{
        AuthorizationCode, UpstreamOAuthProviderClaimsImports,
        UpstreamOAuthProviderOnBackchannelLogout, UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::{PostAuthAction, Route, SimpleRoute, UpstreamOAuth2Authorize};
    use mas_storage::{
        RepositoryAccess,
        oauth2::{OAuth2AuthorizationGrantRepository, OAuth2ClientRepository},
        upstream_oauth2::{
            UpstreamOAuthLinkRepository, UpstreamOAuthProviderParams,
            UpstreamOAuthProviderRepository, UpstreamOAuthSessionRepository,
        },
        user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
    };
    use mas_templates::escape_html;
    use oauth2_types::{
        requests::ResponseMode,
        scope::{OPENID, Scope},
    };
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

    /// A fixed authorization-grant ULID used to check that the post-auth action
    /// round-trips through the account-inactive interstitials.
    const GRANT_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    /// Extract the logout form's HTML from a rendered interstitial: the
    /// substring from the `<form` tag whose `action` ends in `/logout` through
    /// the following `</form>`. This scopes hidden-input assertions to the
    /// logout form, so they don't accidentally match markup elsewhere on the
    /// page. Panics with a clear message if no logout form is found.
    ///
    /// The rendered attribute is HTML-escaped (`action="&#x2f;logout"`), so we
    /// key off the `logout"` that terminates the action value rather than the
    /// literal `/logout`.
    fn extract_logout_form(body: &str) -> &str {
        let action_end = body
            .find(r#"logout""#)
            .expect("expected a logout form (action ending in /logout) in the body");
        let form_start = body[..action_end]
            .rfind("<form")
            .expect("expected an enclosing <form tag before the /logout action");
        let form_end = body[form_start..]
            .find("</form>")
            .expect("expected a closing </form> after the logout form")
            + "</form>".len();
        &body[form_start..form_start + form_end]
    }

    /// Assert that the rendered interstitial carries the hidden inputs which
    /// make the sign-out/sign-in button continue an authorization grant.
    ///
    /// Scoped to the logout form so a match anywhere else on the page can't
    /// mask a missing hidden input.
    fn assert_interstitial_carries_grant_action(body: &str, grant_id: &str) {
        let form = extract_logout_form(body);
        assert!(
            form.contains(r#"name="kind""#)
                && form.contains(r#"value="continue_authorization_grant""#),
            "expected a continue_authorization_grant hidden input, form: {form}"
        );
        assert!(
            form.contains(r#"name="id""#) && form.contains(&format!(r#"value="{grant_id}""#)),
            "expected the grant id hidden input, form: {form}"
        );
    }

    /// Extract the (single) CSRF token from a rendered interstitial's logout
    /// form.
    fn extract_csrf(body: &str) -> &str {
        body.split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap()
    }

    /// Provision a live browser-session cookie for `user` into `cookies`, and
    /// return the created session.
    async fn login_with_session(
        state: &TestState,
        cookies: &CookieHelper,
        user: &mas_data_model::User,
    ) -> mas_data_model::BrowserSession {
        use mas_axum_utils::SessionInfoExt as _;

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookie_jar = state.cookie_jar().set_session(&browser_session);
        cookies.import(cookie_jar);

        browser_session
    }

    /// Register an `OAuth2` client and return its id, so we can attach an
    /// authorization grant to it.
    async fn provision_client(state: &TestState) -> mas_data_model::Client {
        let request =
            Request::post(mas_router::OAuth2RegistrationEndpoint::PATH).json(serde_json::json!({
                "client_uri": "https://example.com/",
                "redirect_uris": ["https://example.com/redirect"],
                "response_types": ["code"],
                "grant_types": ["authorization_code"],
                "token_endpoint_auth_method": "none",
            }));
        let response = state.request(request).await;
        response.assert_status(StatusCode::CREATED);
        let response: oauth2_types::registration::ClientRegistrationResponse = response.json();

        let mut repo = state.repository().await.unwrap();
        let client = repo
            .oauth2_client()
            .find_by_client_id(&response.client_id)
            .await
            .unwrap()
            .unwrap();
        repo.save().await.unwrap();
        client
    }

    /// Add an authorization grant with optional trusted target.
    async fn add_grant(
        state: &TestState,
        repo: &mut mas_storage::BoxRepository,
        client: &mas_data_model::Client,
        login_hint: Option<String>,
        target_user: Option<&mas_data_model::User>,
        target_user_session: Option<&mas_data_model::BrowserSession>,
    ) -> mas_data_model::AuthorizationGrant {
        repo.oauth2_authorization_grant()
            .add(
                &mut state.rng(),
                &state.clock,
                client,
                "https://example.com/redirect".parse().unwrap(),
                Scope::from_iter([OPENID]),
                Some(AuthorizationCode {
                    code: "thisisaverysecurecode".to_owned(),
                    pkce: None,
                }),
                Some("state".to_owned()),
                Some("nonce".to_owned()),
                ResponseMode::Query,
                false,
                login_hint,
                None,
                std::collections::BTreeMap::new(),
                target_user,
                target_user_session,
            )
            .await
            .unwrap()
    }

    fn provider_params(issuer: &str) -> UpstreamOAuthProviderParams {
        UpstreamOAuthProviderParams {
            issuer: Some(issuer.to_owned()),
            human_name: Some("Example Ltd.".to_owned()),
            brand_name: None,
            scope: Scope::from_iter([OPENID]),
            token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
            token_endpoint_signing_alg: None,
            id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
            fetch_userinfo: false,
            userinfo_signed_response_alg: None,
            client_id: "client".to_owned(),
            encrypted_client_secret: None,
            claims_imports: UpstreamOAuthProviderClaimsImports::default(),
            authorization_endpoint_override: None,
            token_endpoint_override: None,
            userinfo_endpoint_override: None,
            jwks_uri_override: None,
            discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
            pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
            response_mode: None,
            additional_authorization_parameters: Vec::new(),
            forward_login_hint: false,
            ui_order: 0,
            on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
            registration_token_required: false,
        }
    }

    /// A trusted target whose last authentication was a password login should
    /// render the dedicated "welcome back" page, naming the target and
    /// pre-filling their username.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_password_target(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a user "alice" with a password, and a browser session
        // authenticated by that password.
        let user = user_with_password(&state, "alice", "hunter2").await;
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_password(
                &mut state.rng(),
                &state.clock,
                &browser_session,
                &user_password,
            )
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        // GET /login continuing the grant, with no active session cookie.
        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        let body = response.body();
        // The welcome-back page shows the confirmation headline...
        assert!(
            body.contains("Confirm it's you"),
            "Expected welcome-back headline, body: {body}"
        );
        // ...and the consent-style user card showing the target's mxid.
        assert!(
            body.contains("@alice:example.com"),
            "Expected the user card to show the mxid, body: {body}"
        );
        // ...and pre-fills the username in a hidden field, distinct from the
        // generic login form which has a visible, empty username input.
        assert!(
            body.contains(r#"<input type="hidden" name="username" value="alice""#),
            "Expected hidden username field, body: {body}"
        );
        // Make sure this isn't the generic login form.
        assert!(
            !body.contains("No login methods available"),
            "Should not be the generic login page"
        );
    }

    /// A wrong password submitted from the welcome-back password page must
    /// re-render the welcome-back page (with the error), NOT drop the user onto
    /// the generic login page.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_wrong_password_stays(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user "alice" with a password, and a browser session
        // authenticated by that password.
        let user = user_with_password(&state, "alice", "hunter2").await;
        let mut repo = state.repository().await.unwrap();
        let user_password = repo.user_password().active(&user).await.unwrap().unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_password(
                &mut state.rng(),
                &state.clock,
                &browser_session,
                &user_password,
            )
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        // GET /login continuing the grant: this is the welcome-back password
        // page; grab its CSRF token.
        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let request = cookies.with_cookies(Request::get(&*url).empty());
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(
            body.contains("Confirm it's you"),
            "Expected the welcome-back page, body: {body}"
        );
        let csrf_token = body
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // POST /login continuing the grant with the right username but the WRONG
        // password.
        let request = Request::post(&*url).form(serde_json::json!({
            "csrf": csrf_token,
            "username": "alice",
            "password": "wrongpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);

        let body = response.body();
        // It must stay on the welcome-back page, showing the error...
        assert!(
            body.contains("Confirm it's you"),
            "Expected to stay on the welcome-back page, body: {body}"
        );
        assert!(
            body.contains("Invalid credentials"),
            "Expected the invalid-credentials error, body: {body}"
        );
        // ...and definitely NOT fall back to the generic login page.
        assert!(
            !body.contains("No login methods available"),
            "Should not fall back to the generic login page, body: {body}"
        );
    }

    /// A trusted target whose last authentication was via an upstream provider
    /// should auto-redirect to that provider's authorize endpoint.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_upstream_target(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();

        // Provision a user and an upstream provider + completed session.
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                provider_params("https://upstream.example/"),
            )
            .await
            .unwrap();

        let upstream_session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();
        let upstream_session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                upstream_session,
                &link,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        // A browser session whose most-recent authentication is upstream.
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_upstream(&mut rng, &state.clock, &browser_session, &upstream_session)
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        // GET /login continuing the grant, with no active session cookie.
        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);

        // It should redirect to the upstream authorize endpoint for the provider
        // the target last used, carrying the continue-grant post-auth action.
        let expected = UpstreamOAuth2Authorize::new(provider.id)
            .and_then(PostAuthAction::ContinueAuthorizationGrant { id: grant.id });
        response.assert_header_value(LOCATION, &expected.path_and_query());
    }

    /// An untrusted hint (a `login_hint`, no resolved `target_user_id`) keeps
    /// the generic login page, with the username pre-filled — NOT the
    /// welcome-back template.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_untrusted_login_hint_generic_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let user = user_with_password(&state, "alice", "hunter2").await;
        let mut repo = state.repository().await.unwrap();
        let client = provision_client(&state).await;
        // No target_user_id => untrusted.
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            Some("mxid:@alice:example.com".to_owned()),
            None,
            None,
        )
        .await;
        repo.save().await.unwrap();
        drop(user);

        // GET /login continuing the grant, passing the login_hint on the URL.
        let url = mas_router::Login::and_continue_grant(grant.id)
            .with_login_hint("mxid:@alice:example.com".to_owned())
            .path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        let body = response.body();
        // Generic login form with the username pre-filled...
        assert!(
            body.contains(r#"value="alice""#),
            "Expected username pre-filled, body: {body}"
        );
        // ...and definitely NOT the welcome-back page.
        assert!(
            !body.contains("Confirm it's you"),
            "Should not render the welcome-back page for an untrusted hint"
        );
    }

    /// On a password-login-disabled instance, a trusted *password* target must
    /// NOT render the welcome-back password page (whose POST would 405); it
    /// should fall through to the generic login page instead.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_password_target_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_login_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        // Provision a user "alice" and a browser session whose most-recent
        // authentication is a password login. The password manager is disabled
        // in this site config, so insert the password row with a dummy hash
        // directly rather than going through `PasswordManager::hash`.
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut state.rng(), &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let user_password = repo
            .user_password()
            .add(
                &mut state.rng(),
                &state.clock,
                &user,
                1,
                "$argon2id$dummy".to_owned(),
                None,
            )
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_password(
                &mut state.rng(),
                &state.clock,
                &browser_session,
                &user_password,
            )
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        let body = response.body();
        // It must NOT be the welcome-back password page.
        assert!(
            !body.contains("Confirm it's you"),
            "Should not render the welcome-back password page when password login is disabled, body: {body}"
        );
        // With no upstream providers configured, the generic login page shows
        // the "no login methods" message.
        assert!(
            body.contains("No login methods available"),
            "Expected the generic login page, body: {body}"
        );
    }

    /// A trusted target whose `target_user_session_id` no longer resolves to a
    /// session (stale/reaped `sid`) can't have its most-recent method
    /// confirmed, so we must fall through to the generic login page pre-filled
    /// with the target's username — NOT the (upstream-button-less) welcome-back
    /// password page.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_stale_session_generic_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // Provision a target user and a real browser session, attach the grant
        // to it, then delete the session row. The grant's
        // `target_user_session_id` foreign key is `ON DELETE SET NULL`, so the
        // stored grant ends up pointing at no session — exactly the reaped/stale
        // `sid` case, where the most-recent method can't be confirmed.
        let user = user_with_password(&state, "alice", "hunter2").await;
        let mut repo = state.repository().await.unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut state.rng(), &state.clock, &user, None)
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        // Reap the session: the FK nulls the grant's `target_user_session_id`.
        sqlx::query("DELETE FROM user_sessions WHERE user_session_id = $1")
            .bind(sqlx::types::Uuid::from(browser_session.id))
            .execute(&state.repository_factory.pool())
            .await
            .unwrap();

        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        let body = response.body();
        // Generic login page, pre-filled with the target's username...
        assert!(
            body.contains(r#"value="alice""#),
            "Expected username pre-filled on the generic login page, body: {body}"
        );
        // ...NOT the welcome-back password page.
        assert!(
            !body.contains("Confirm it's you"),
            "Should not render the welcome-back page for a stale/unknown sid, body: {body}"
        );
    }

    /// A trusted *upstream* target whose provider has since been disabled must
    /// NOT auto-redirect to it (that would dead-end at `ProviderNotFound`); it
    /// should fall through to the generic login page instead.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_welcome_back_upstream_target_provider_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();

        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();

        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                provider_params("https://upstream.example/"),
            )
            .await
            .unwrap();

        let upstream_session = repo
            .upstream_oauth_session()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "state".to_owned(),
                None,
                None,
            )
            .await
            .unwrap();
        let link = repo
            .upstream_oauth_link()
            .add(
                &mut rng,
                &state.clock,
                &provider,
                "subject".to_owned(),
                None,
            )
            .await
            .unwrap();
        let upstream_session = repo
            .upstream_oauth_session()
            .complete_with_link(
                &state.clock,
                upstream_session,
                &link,
                None,
                None,
                None,
                None,
            )
            .await
            .unwrap();

        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.browser_session()
            .authenticate_with_upstream(&mut rng, &state.clock, &browser_session, &upstream_session)
            .await
            .unwrap();

        // Disable the provider after the fact.
        repo.upstream_oauth_provider()
            .disable(&state.clock, provider)
            .await
            .unwrap();

        let client = provision_client(&state).await;
        let grant = add_grant(
            &state,
            &mut repo,
            &client,
            None,
            Some(&user),
            Some(&browser_session),
        )
        .await;
        repo.save().await.unwrap();

        let url = mas_router::Login::and_continue_grant(grant.id).path_and_query();
        let response = state.request(Request::get(&*url).empty()).await;
        // It must NOT redirect to the disabled provider.
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");

        let body = response.body();
        // Falls through to the generic login page pre-filled with the username.
        assert!(
            body.contains(r#"value="alice""#),
            "Expected username pre-filled on the generic login page, body: {body}"
        );
        assert!(
            !body.contains("Confirm it's you"),
            "Should not render the welcome-back page, body: {body}"
        );
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_login_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let mut rng = state.rng();

        // Without password login and no upstream providers, we should get an error
        // message
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(
            response.body().contains("No login methods available"),
            "Response body: {}",
            response.body()
        );

        // Adding an upstream provider should redirect to it
        let mut repo = state.repository().await.unwrap();
        let first_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://first.com/".to_owned()),
                    human_name: Some("First Ltd.".to_owned()),
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 0,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let first_provider_login = mas_router::UpstreamOAuth2Authorize::new(first_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &first_provider_login.path_and_query());

        // Adding a second provider should show a login page with both providers
        let mut repo = state.repository().await.unwrap();
        let second_provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    issuer: Some("https://second.com/".to_owned()),
                    human_name: None,
                    brand_name: None,
                    scope: [OPENID].into_iter().collect(),
                    token_endpoint_auth_method: UpstreamOAuthProviderTokenAuthMethod::None,
                    token_endpoint_signing_alg: None,
                    id_token_signed_response_alg: JsonWebSignatureAlg::Rs256,
                    fetch_userinfo: false,
                    userinfo_signed_response_alg: None,
                    client_id: "client".to_owned(),
                    encrypted_client_secret: None,
                    claims_imports: UpstreamOAuthProviderClaimsImports::default(),
                    authorization_endpoint_override: None,
                    token_endpoint_override: None,
                    userinfo_endpoint_override: None,
                    jwks_uri_override: None,
                    discovery_mode: mas_data_model::UpstreamOAuthProviderDiscoveryMode::Oidc,
                    pkce_mode: mas_data_model::UpstreamOAuthProviderPkceMode::Auto,
                    response_mode: None,
                    additional_authorization_parameters: Vec::new(),
                    forward_login_hint: false,
                    ui_order: 1,
                    on_backchannel_logout: UpstreamOAuthProviderOnBackchannelLogout::DoNothing,
                    registration_token_required: false,
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let second_provider_login = mas_router::UpstreamOAuth2Authorize::new(second_provider.id);

        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains(&escape_html("First Ltd.")));
        assert!(
            response
                .body()
                .contains(&escape_html(&first_provider_login.path_and_query()))
        );
        assert!(response.body().contains(&escape_html("second.com")));
        assert!(
            response
                .body()
                .contains(&escape_html(&second_provider_login.path_and_query()))
        );
    }

    async fn user_with_password(
        state: &TestState,
        username: &str,
        password: &str,
    ) -> mas_data_model::User {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, username.to_owned())
            .await
            .unwrap();
        let (version, hash) = state
            .password_manager
            .hash(&mut rng, Zeroizing::new(password.to_owned()))
            .await
            .unwrap();
        repo.user_password()
            .add(&mut rng, &state.clock, &user, version, hash, None)
            .await
            .unwrap();
        repo.save().await.unwrap();
        user
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_with_mxid(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:example.com",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::SEE_OTHER);

        // Now if we get to the home page, we should see the user's username
        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("john"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_with_mxid_wrong_server(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        user_with_password(&state, "john", "hunter2").await;

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "@john:something.corp",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;

        // This shouldn't have worked, we're back on the login page
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Invalid credentials"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_rate_limit(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();
        let cookies = CookieHelper::new();

        // Provision a user without a password.
        // We don't give that user a password, so that we skip hashing it in this test.
        // It will still be rate-limited
        let mut repo = state.repository().await.unwrap();
        repo.user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);

        // First three attempts should just tell about the invalid credentials
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(body.contains("Invalid credentials"));
        assert!(!body.contains("too many requests"));

        // The fourth attempt should be rate-limited
        let response = state.request(request.clone()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        assert!(!body.contains("Invalid credentials"));
        assert!(body.contains("too many requests"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_locked_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Lock the user
        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form, carrying a post-auth action which should be
        // preserved on the account-locked interstitial so the sign-in button
        // resumes the flow.
        let request = Request::post(format!(
            "/login?kind=continue_authorization_grant&id={GRANT_ID}"
        ))
        .form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account locked"));
        assert_interstitial_carries_grant_action(response.body(), GRANT_ID);

        // A bad password should not disclose that the account is locked
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account locked"));
        assert!(response.body().contains("Invalid credentials"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_password_login_deactivated_account(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        // Provision a user with a password
        let user = user_with_password(&state, "john", "hunter2").await;

        // Deactivate the user
        let mut repo = state.repository().await.unwrap();
        repo.user().deactivate(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Render the login page to get a CSRF token
        let request = Request::get("/login").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        // Extract the CSRF token from the response body
        let csrf_token = response
            .body()
            .split("name=\"csrf\" value=\"")
            .nth(1)
            .unwrap()
            .split('\"')
            .next()
            .unwrap();

        // Submit the login form, carrying a post-auth action which should be
        // preserved on the account-deactivated interstitial.
        let request = Request::post(format!(
            "/login?kind=continue_authorization_grant&id={GRANT_ID}"
        ))
        .form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "hunter2",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(response.body().contains("Account deleted"));
        assert_interstitial_carries_grant_action(response.body(), GRANT_ID);

        // A bad password should not disclose that the account is deleted
        let request = Request::post("/login").form(serde_json::json!({
            "csrf": csrf_token,
            "username": "john",
            "password": "badpassword",
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        response.assert_header_value(CONTENT_TYPE, "text/html; charset=utf-8");
        assert!(!response.body().contains("Account deleted"));
        assert!(response.body().contains("Invalid credentials"));
    }

    /// A locked user hitting `GET /login` with an in-flight authorization grant
    /// (via the `load_session_or_fallback` cookie path) should get the
    /// account-locked interstitial carrying the continuation.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_get_locked_account_preserves_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        login_with_session(&state, &cookies, &user).await;

        // Lock the user after the session was established
        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!(
            "/login?kind=continue_authorization_grant&id={GRANT_ID}"
        ))
        .empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));
        assert_interstitial_carries_grant_action(response.body(), GRANT_ID);
    }

    /// A locked user with a live session requesting `/consent/{grant_id}`
    /// should get the account-locked interstitial carrying the grant, and
    /// signing out from it should continue back into the grant.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_consent_locked_account_preserves_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        login_with_session(&state, &cookies, &user).await;

        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // The consent handler falls back to the interstitial before even looking
        // up the grant, so any grant id exercises the path.
        let request = Request::get(format!("/consent/{GRANT_ID}")).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));
        assert_interstitial_carries_grant_action(response.body(), GRANT_ID);

        // Signing out from the interstitial should continue into the grant.
        let csrf_token = extract_csrf(response.body()).to_owned();
        let request = Request::post("/logout").form(serde_json::json!({
            "csrf": csrf_token,
            "kind": "continue_authorization_grant",
            "id": GRANT_ID,
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &format!("/consent/{GRANT_ID}"));
    }

    /// A session finished out-of-band (remote logout) should render the
    /// 'logged out' interstitial carrying the continuation, and signing out
    /// should continue into it.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_logged_out_session_preserves_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        let session = login_with_session(&state, &cookies, &user).await;

        // Finish the session out-of-band, as an admin or remote logout would.
        let mut repo = state.repository().await.unwrap();
        repo.browser_session()
            .finish(&state.clock, session)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!("/consent/{GRANT_ID}")).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        // It's the 'logged out' page, not locked/deactivated.
        assert!(!response.body().contains("Account locked"));
        assert!(!response.body().contains("Account deleted"));
        assert_interstitial_carries_grant_action(response.body(), GRANT_ID);

        let csrf_token = extract_csrf(response.body()).to_owned();
        let request = Request::post("/logout").form(serde_json::json!({
            "csrf": csrf_token,
            "kind": "continue_authorization_grant",
            "id": GRANT_ID,
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, &format!("/consent/{GRANT_ID}"));
    }

    /// Without a continuation the post-logout redirect must be action-driven:
    /// signing out from the interstitial with only the CSRF field (no
    /// `kind`/`id`) lands on a bare `/login`, not on any grant continuation.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_logout_without_action_redirects_to_login(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        login_with_session(&state, &cookies, &user).await;

        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let request = Request::get(format!("/consent/{GRANT_ID}")).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        cookies.save_cookies(&response);
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));

        // Sign out with only the CSRF field, i.e. no post-logout action.
        let csrf_token = extract_csrf(response.body()).to_owned();
        let request = Request::post("/logout").form(serde_json::json!({
            "csrf": csrf_token,
        }));
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, "/login");
    }

    /// The device-consent and compat-SSO interstitials should carry their
    /// respective continuations for a locked user.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_device_and_compat_locked_account_preserve_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        login_with_session(&state, &cookies, &user).await;

        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        // Device consent
        let request = Request::get(format!("/device/{GRANT_ID}")).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));
        assert!(
            response
                .body()
                .contains(r#"value="continue_device_code_grant""#),
            "expected continue_device_code_grant input, body: {}",
            response.body()
        );
        assert!(response.body().contains(&format!(r#"value="{GRANT_ID}""#)));

        // Compat SSO completion
        let request = Request::get(format!("/complete-compat-sso/{GRANT_ID}")).empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));
        assert!(
            response
                .body()
                .contains(r#"value="continue_compat_sso_login""#),
            "expected continue_compat_sso_login input, body: {}",
            response.body()
        );
        assert!(response.body().contains(&format!(r#"value="{GRANT_ID}""#)));
    }

    /// The homepage passes no action, so a locked user's interstitial there
    /// must not emit any continuation hidden inputs (guards the
    /// `skip_serializing_if`).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_index_locked_account_has_no_action(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let user = user_with_password(&state, "john", "hunter2").await;
        login_with_session(&state, &cookies, &user).await;

        let mut repo = state.repository().await.unwrap();
        repo.user().lock(&state.clock, user).await.unwrap();
        repo.save().await.unwrap();

        let request = Request::get("/").empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(response.body().contains("Account locked"));
        // Scope to the logout form if there is one, otherwise fall back to the
        // whole body.
        let scope = if response.body().contains(r#"logout""#) {
            extract_logout_form(response.body())
        } else {
            response.body()
        };
        assert!(
            !scope.contains(r#"name="kind""#),
            "homepage interstitial should carry no continuation, form/body: {scope}"
        );
        assert!(!scope.contains("continue_authorization_grant"));
    }

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_x_frame_options(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        // GET /login should include X-Frame-Options: DENY so the page cannot be
        // embedded in an iframe on another origin.
        let response = state.request(Request::get("/login").empty()).await;
        response.assert_status(StatusCode::OK);
        response.assert_header_value(X_FRAME_OPTIONS, "DENY");
    }
}
