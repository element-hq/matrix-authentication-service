// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use axum_extra::extract::Query;
use mas_axum_utils::{InternalError, SessionInfoExt, cookies::CookieJar, csrf::CsrfExt as _};
use mas_data_model::{BoxClock, BoxRng, SiteConfig};
use mas_router::{PasswordRegister, UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{RegisterContext, TemplateContext, Templates};

use super::shared::{OptionalPostAuthAction, QueryLoginMethod, Resolved, resolve_login_method};
use crate::{BoundActivityTracker, PreferredLanguage};

mod cookie;
pub(crate) mod password;
pub(crate) mod steps;

pub use self::cookie::UserRegistrationSessions as UserRegistrationSessionsCookie;

#[tracing::instrument(name = "handlers.views.register.get", skip_all)]
pub(crate) async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    activity_tracker: BoundActivityTracker,
    Query(query): Query<OptionalPostAuthAction>,
    Query(query_login_method): Query<QueryLoginMethod>,
    cookie_jar: CookieJar,
) -> Result<Response, InternalError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    }

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    match resolve_login_method(
        query_login_method.login_method(query.post_auth_action.as_ref()),
        &providers,
        site_config.password_registration_enabled,
    ) {
        Resolved::UpstreamOAuth2(provider) => {
            let mut destination = UpstreamOAuth2Authorize::new(provider.id);

            if let Some(action) = query.post_auth_action.clone() {
                destination = destination.and_then(action);
            }

            return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
        }

        Resolved::Password => {
            let mut destination = PasswordRegister::default();

            if let Some(action) = query.post_auth_action.clone() {
                destination = destination.and_then(action);
            }

            return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
        }

        Resolved::None => {}
    }

    // If password-based registration is disabled, and there is only one upstream
    // provider, we can directly start an authorization flow
    if !site_config.password_registration_enabled && providers.len() == 1 {
        let provider = providers.into_iter().next().unwrap();

        let mut destination = UpstreamOAuth2Authorize::new(provider.id);

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    // If password-based registration is enabled and there are no upstream
    // providers, we redirect to the password registration page
    if site_config.password_registration_enabled && providers.is_empty() {
        let mut destination = PasswordRegister::default();

        if let Some(action) = query.post_auth_action {
            destination = destination.and_then(action);
        }

        return Ok((cookie_jar, url_builder.redirect(&destination)).into_response());
    }

    let mut ctx = RegisterContext::new(providers);
    let post_action = query
        .load_context(&mut repo)
        .await
        .map_err(InternalError::from_anyhow)?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_register(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

#[cfg(test)]
mod test {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_router::Route;
    use mas_storage::{
        RepositoryAccess,
        upstream_oauth2::{UpstreamOAuthProviderParams, UpstreamOAuthProviderRepository},
    };
    use mas_templates::escape_html;
    use sqlx::PgPool;

    use crate::{
        SiteConfig,
        test_utils::{
            RequestBuilderExt, ResponseExt, TestState, setup, test_site_config,
            upstream_oauth_provider_params,
        },
    };

    /// A fixed ULID for the post-auth actions carried alongside the hint.
    const ACTION_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";

    /// Add an enabled upstream provider.
    async fn add_provider(
        state: &TestState,
        issuer: &str,
        human_name: &str,
        ui_order: i32,
    ) -> mas_data_model::UpstreamOAuthProvider {
        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let provider = repo
            .upstream_oauth_provider()
            .add(
                &mut rng,
                &state.clock,
                UpstreamOAuthProviderParams {
                    ui_order,
                    ..upstream_oauth_provider_params(issuer, human_name)
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        provider
    }

    /// A provider hint skips the chooser and starts that provider's
    /// authorization flow, carrying the post-auth action over.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_provider(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        add_provider(&state, "first.com", "First Ltd.", 0).await;
        let second = add_provider(&state, "second.com", "Second Ltd.", 1).await;

        let request = Request::get(format!(
            "/register?kind=continue_authorization_grant&id={ACTION_ID}\
             &io.element.login_method=upstream-oauth2:{}",
            second.id
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::UpstreamOAuth2Authorize::new(second.id)
                .and_then(mas_router::PostAuthAction::continue_grant(
                    ACTION_ID.parse().unwrap(),
                ))
                .path_and_query(),
        );
    }

    /// The `password` hint skips the chooser and goes to the password
    /// registration page, which renders instead of redirecting back to
    /// `/login`.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_password(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        add_provider(&state, "first.com", "First Ltd.", 0).await;
        add_provider(&state, "second.com", "Second Ltd.", 1).await;

        let request = Request::get("/register?io.element.login_method=password").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        let destination = mas_router::PasswordRegister::default().path_and_query();
        response.assert_header_value(LOCATION, &destination);

        let response = state
            .request(Request::get(destination.as_ref()).empty())
            .await;
        response.assert_status(StatusCode::OK);
    }

    /// With password registration disabled, the `password` hint is ignored,
    /// and the single-provider shortcut fires instead.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_password_disabled(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                password_registration_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let provider = add_provider(&state, "first.com", "First Ltd.", 0).await;

        let request = Request::get("/register?io.element.login_method=password").empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::UpstreamOAuth2Authorize::new(provider.id).path_and_query(),
        );
    }

    /// A provider hint with no providers at all falls through to the
    /// password-registration shortcut.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_provider_without_providers(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let request = Request::get(
            "/register?io.element.login_method=upstream-oauth2:01ARZ3NDEKTSV4RRFFQ69G5FAV",
        )
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::PasswordRegister::default().path_and_query(),
        );
    }

    /// A hint must not hijack an upstream-account linking flow into a
    /// different provider.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_login_method_hint_ignored_when_linking(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let first = add_provider(&state, "first.com", "First Ltd.", 0).await;
        let second = add_provider(&state, "second.com", "Second Ltd.", 1).await;

        let request = Request::get(format!(
            "/register?kind=link_upstream&id={ACTION_ID}\
             &io.element.login_method=upstream-oauth2:{}",
            second.id
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        for provider_id in [first.id, second.id] {
            let link = mas_router::UpstreamOAuth2Authorize::new(provider_id).path_and_query();
            assert!(body.contains(&escape_html(&link)), "body: {body}");
        }
    }

    /// Without a hint, the chooser is rendered as before.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_no_login_method_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let first = add_provider(&state, "first.com", "First Ltd.", 0).await;
        let second = add_provider(&state, "second.com", "Second Ltd.", 1).await;

        let response = state.request(Request::get("/register").empty()).await;
        response.assert_status(StatusCode::OK);
        let body = response.body();
        for provider_id in [first.id, second.id] {
            let link = mas_router::UpstreamOAuth2Authorize::new(provider_id).path_and_query();
            assert!(body.contains(&escape_html(&link)), "body: {body}");
        }
    }
}
