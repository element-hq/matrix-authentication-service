// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod cookie;

use std::sync::{Arc, LazyLock};

use axum::{
    extract::{Form, State},
    response::{Html, IntoResponse, Response},
};
use axum_extra::{extract::Query, typed_header::TypedHeader};
use cookie::UserPasskeyChallenges;
use hyper::StatusCode;
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::{BoxClock, BoxRng, Clock, Password, User, UserPasskey, oauth2::LoginHint};
use mas_i18n::DataLocale;
use mas_matrix::HomeserverConnection;
use mas_router::{UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{
    BoxRepository, RepositoryAccess,
    upstream_oauth2::UpstreamOAuthProviderRepository,
    user::{BrowserSessionRepository, UserPasswordRepository, UserRepository},
};
use mas_templates::{
    AccountInactiveContext, FieldError, FormError, FormState, LoginContext, LoginFormField,
    PostAuthContext, PostAuthContextInner, TemplateContext, Templates, ToFormState,
};
use opentelemetry::{Key, KeyValue, metrics::Counter};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use ulid::Ulid;
use zeroize::Zeroizing;

use super::shared::OptionalPostAuthAction;
use crate::{
    BoundActivityTracker, Limiter, METER, PreferredLanguage, RequesterFingerprint, SiteConfig,
    passwords::{PasswordManager, PasswordVerificationResult},
    session::{SessionOrFallback, load_session_or_fallback},
    webauthn::{Webauthn, WebauthnError},
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
    passkey_challenge_id: Option<String>,
    passkey_response: Option<String>,
}

impl ToFormState for LoginForm {
    type Field = LoginFormField;
}

#[derive(Debug)]
enum AuthenticatedWith {
    Password(Password),
    Passkey(UserPasskey),
}

#[tracing::instrument(name = "handlers.views.login.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    State(webauthn): State<Webauthn>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
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
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login and passkeys are disabled, and there is only one
    // upstream provider, we can directly start an authorization flow
    if !site_config.password_login_enabled && !site_config.passkeys_enabled && providers.len() == 1
    {
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
        FormState::default(),
        query,
        repo,
        &clock,
        &mut rng,
        &templates,
        &homeserver,
        &site_config,
        webauthn,
    )
    .await
}

#[tracing::instrument(name = "handlers.views.login.post", skip_all)]
pub(crate) async fn post(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    (State(password_manager), State(webauthn)): (State<PasswordManager>, State<Webauthn>),
    State(site_config): State<SiteConfig>,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(limiter): State<Limiter>,
    State(homeserver): State<Arc<dyn HomeserverConnection>>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    requester: RequesterFingerprint,
    Query(query): Query<OptionalPostAuthAction>,
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

    if form.username.is_empty() && form.passkey_response.as_ref().is_none_or(String::is_empty) {
        form_state.add_error_on_field(LoginFormField::Username, FieldError::Required);
    }

    if form.password.is_empty() && form.passkey_response.as_ref().is_none_or(String::is_empty) {
        form_state.add_error_on_field(LoginFormField::Password, FieldError::Required);
    }

    if !form_state.is_valid() {
        tracing::warn!("Invalid login form: {form_state:?}");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            webauthn,
        )
        .await;
    }

    let cookie_jar = if let Some(form_challenge_id) = &form.passkey_challenge_id {
        // Validate passkey challenge cookie
        let challenge_id = Ulid::from_string(form_challenge_id).unwrap_or_default();
        let challenges = UserPasskeyChallenges::load(&cookie_jar);
        if !challenges.contains(&challenge_id) {
            let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
            return render(
                locale,
                cookie_jar,
                form_state,
                query,
                repo,
                &clock,
                &mut rng,
                &templates,
                &homeserver,
                &site_config,
                webauthn,
            )
            .await;
        }

        // Consume the cookie already as we'll give them a new one anyway
        challenges
            .consume_challenge(&challenge_id)
            .save(cookie_jar, &clock)
    } else {
        cookie_jar
    };

    let validation = match (
        form.password.is_empty(),
        form.passkey_response.as_ref().is_none_or(String::is_empty),
    ) {
        // Password login
        (false, true) => {
            password_login(
                &mut rng,
                &clock,
                password_manager,
                &site_config,
                limiter,
                &homeserver,
                &mut repo,
                requester,
                form,
                form_state,
            )
            .await?
        }
        // Passkey login. User's password manager may have prefilled the password despite using a
        // passkey
        (_, false) => {
            if !site_config.passkeys_enabled {
                let form_state = form_state.with_error_on_form(FormError::InvalidCredentials);
                return render(
                    locale,
                    cookie_jar,
                    form_state,
                    query,
                    repo,
                    &clock,
                    &mut rng,
                    &templates,
                    &homeserver,
                    &site_config,
                    webauthn,
                )
                .await;
            }
            passkey_login(
                &clock, &webauthn, limiter, &mut repo, requester, form, form_state,
            )
            .await?
        }
        _ => Err(form_state.with_error_on_form(FormError::Internal)),
    };

    let Ok((user, auth_with)) = validation else {
        let form_state = validation.unwrap_err();
        return render(
            locale,
            cookie_jar,
            form_state,
            query,
            repo,
            &clock,
            &mut rng,
            &templates,
            &homeserver,
            &site_config,
            webauthn,
        )
        .await;
    };

    // Now that we have checked the user password, we now want to show an error if
    // the user is locked or deactivated
    if user.deactivated_at.is_some() {
        tracing::warn!(user.username, "User is deactivated");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
        let ctx = AccountInactiveContext::new(user)
            .with_csrf(csrf_token.form_value())
            .with_language(locale);
        let content = templates.render_account_deactivated(&ctx)?;
        return Ok((cookie_jar, Html(content)).into_response());
    }

    if user.locked_at.is_some() {
        tracing::warn!(user.username, "User is locked");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
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

    match auth_with {
        AuthenticatedWith::Password(user_password) => {
            // And mark it as authenticated by the password
            repo.browser_session()
                .authenticate_with_password(&mut rng, &clock, &user_session, &user_password)
                .await?;
        }
        AuthenticatedWith::Passkey(passkey) => {
            // And mark it as authenticated by the passkey
            repo.browser_session()
                .authenticate_with_passkey(&mut rng, &clock, &user_session, &passkey)
                .await?;
        }
    }

    repo.save().await?;

    PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "success")]);

    activity_tracker
        .record_browser_session(&clock, &user_session)
        .await;

    let cookie_jar = cookie_jar.set_session(&user_session);
    let reply = query.go_next(&url_builder);
    Ok((cookie_jar, reply).into_response())
}

async fn password_login(
    mut rng: &mut BoxRng,
    clock: &BoxClock,
    password_manager: PasswordManager,
    site_config: &SiteConfig,
    limiter: Limiter,
    homeserver: &dyn HomeserverConnection,
    repo: &mut impl RepositoryAccess,
    requester: RequesterFingerprint,
    form: LoginForm,
    form_state: FormState<LoginFormField>,
) -> Result<Result<(User, AuthenticatedWith), FormState<LoginFormField>>, InternalError> {
    // Extract the localpart of the MXID, fallback to the bare username
    let username = homeserver
        .localpart(&form.username)
        .unwrap_or(&form.username);

    // First, lookup the user
    let Some(user) = get_user_by_email_or_by_username(site_config, repo, username).await? else {
        tracing::warn!(username, "User not found");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return Ok(Err(
            form_state.with_error_on_form(FormError::InvalidCredentials)
        ));
    };

    // Check the rate limit
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(error = &e as &dyn std::error::Error, "ratelimit exceeded");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return Ok(Err(
            form_state.with_error_on_form(FormError::RateLimitExceeded)
        ));
    }

    // And its password
    let Some(user_password) = repo.user_password().active(&user).await? else {
        // There is no password for this user, but we don't want to disclose that. Show
        // a generic 'invalid credentials' error instead
        tracing::warn!(username, "No password for user");
        PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "error")]);
        return Ok(Err(
            form_state.with_error_on_form(FormError::InvalidCredentials)
        ));
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
                    clock,
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
            PASSWORD_LOGIN_COUNTER.add(1, &[KeyValue::new(RESULT, "mismatch")]);
            return Ok(Err(
                form_state.with_error_on_form(FormError::InvalidCredentials)
            ));
        }
        Err(err) => return Err(InternalError::from_anyhow(err)),
    };

    Ok(Ok((user, AuthenticatedWith::Password(user_password))))
}

async fn passkey_login(
    clock: &BoxClock,
    webauthn: &Webauthn,
    limiter: Limiter,
    repo: &mut impl RepositoryAccess,
    requester: RequesterFingerprint,
    form: LoginForm,
    form_state: FormState<LoginFormField>,
) -> Result<Result<(User, AuthenticatedWith), FormState<LoginFormField>>, InternalError> {
    let Some(passkey_challenge_id) = form.passkey_challenge_id else {
        return Ok(Err(
            form_state.with_error_on_form(FormError::InvalidCredentials)
        ));
    };

    let Some(passkey_response) = form.passkey_response else {
        return Ok(Err(
            form_state.with_error_on_form(FormError::InvalidCredentials)
        ));
    };

    let challenge_id = Ulid::from_string(&passkey_challenge_id).unwrap_or_default();

    // Find the challenge
    let challenge = match webauthn
        .lookup_challenge(repo, clock, challenge_id, None)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(c) => c,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return Ok(Err(form_state));
        }
    };

    // Mark challenge as completed
    let challenge = repo
        .user_passkey()
        .complete_challenge(clock, challenge)
        .await?;

    // Get the user and passkey from the authenticator response
    let (response, user, passkey) = match webauthn
        .discover_credential(repo, passkey_response)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(v) => v,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return Ok(Err(form_state));
        }
    };

    // XXX: Reusing the password rate limiter. Maybe it should be renamed to login
    // ratelimiter or have a passkey specific one
    if let Err(e) = limiter.check_password(requester, &user) {
        tracing::warn!(error = &e as &dyn std::error::Error, "ratelimit exceeded");
        return Ok(Err(
            form_state.with_error_on_form(FormError::RateLimitExceeded)
        ));
    }

    // Validate the passkey
    let passkey = match webauthn
        .finish_passkey_authentication(repo, clock, challenge, response, passkey)
        .await
        .map_err(anyhow::Error::downcast::<WebauthnError>)
    {
        Ok(p) => p,
        Err(err) => {
            let form_state = form_state.with_error_on_form(match err {
                Ok(_) => FormError::InvalidCredentials,
                Err(_) => FormError::Internal,
            });
            return Ok(Err(form_state));
        }
    };

    Ok(Ok((user, AuthenticatedWith::Passkey(passkey))))
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

fn handle_login_hint(
    mut ctx: LoginContext,
    next: &PostAuthContext,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
) -> LoginContext {
    let form_state = ctx.form_state_mut();

    // Do not override username if coming from a failed login attempt
    if form_state.has_value(LoginFormField::Username) {
        return ctx;
    }

    if let PostAuthContextInner::ContinueAuthorizationGrant { ref grant } = next.ctx {
        let value = match grant.parse_login_hint(homeserver.homeserver()) {
            LoginHint::MXID(mxid) => Some(mxid.localpart().to_owned()),
            LoginHint::Email(email) if site_config.login_with_email_allowed => {
                Some(email.to_string())
            }
            _ => None,
        };
        form_state.set_value(LoginFormField::Username, value);
    }

    ctx
}

async fn render(
    locale: DataLocale,
    cookie_jar: CookieJar,
    mut form_state: FormState<LoginFormField>,
    action: OptionalPostAuthAction,
    mut repo: BoxRepository,
    clock: &impl Clock,
    rng: &mut (dyn RngCore + Send),
    templates: &Templates,
    homeserver: &dyn HomeserverConnection,
    site_config: &SiteConfig,
    webauthn: Webauthn,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(clock, &mut *rng);
    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    let ctx = LoginContext::default();

    let (ctx, cookie_jar) = if site_config.passkeys_enabled {
        let (options, challenge) = webauthn
            .start_passkey_authentication(&mut repo, &mut *rng, clock)
            .await
            .map_err(InternalError::from_anyhow)?;

        form_state.set_value(
            LoginFormField::PasskeyChallengeId,
            Some(challenge.id.to_string()),
        );

        let cookie_jar = UserPasskeyChallenges::load(&cookie_jar)
            .add(&challenge)
            .save(cookie_jar, clock);

        (ctx.with_webauthn_options(options), cookie_jar)
    } else {
        (ctx, cookie_jar)
    };

    let ctx = ctx
        .with_form_state(form_state)
        .with_upstream_providers(providers);

    let next = action
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    let ctx = if let Some(next) = next {
        let ctx = handle_login_hint(ctx, &next, homeserver, site_config);
        ctx.with_post_action(next)
    } else {
        ctx
    };
    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    repo.save().await?;

    let content = templates.render_login(&ctx)?;
    Ok((cookie_jar, Html(content)).into_response())
}

#[cfg(test)]
mod test {
    use hyper::{
        Request, StatusCode,
        header::{CONTENT_TYPE, LOCATION},
    };
    use mas_data_model::{
        UpstreamOAuthProviderClaimsImports, UpstreamOAuthProviderOnBackchannelLogout,
        UpstreamOAuthProviderTokenAuthMethod,
    };
    use mas_iana::jose::JsonWebSignatureAlg;
    use mas_router::Route;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use mas_templates::escape_html;
    use oauth2_types::scope::OPENID;
    use sqlx::PgPool;
    use zeroize::Zeroizing;

    use crate::{
        SiteConfig,
        test_utils::{
            CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
        },
    };

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

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
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

        // Submit the login form
        let request = Request::post("/login").form(serde_json::json!({
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
}
