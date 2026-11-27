// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::State,
    response::{Html, IntoResponse},
};
use axum_extra::extract::Query;
use mas_axum_utils::{InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng};
use mas_router::{LoginMethodHint, PostAuthAction, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{AppContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{
    BoundActivityTracker, PreferredLanguage,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<mas_router::AccountAction>,

    #[serde(rename = "org.matrix.msc4198.login_hint")]
    unstable_login_hint: Option<String>,

    #[serde(rename = "io.element.login_method")]
    login_method: Option<LoginMethodHint>,
}

#[tracing::instrument(name = "handlers.views.app.get", skip_all)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    Query(Params {
        action,
        unstable_login_hint,
        login_method,
    }): Query<Params>,
    mut repo: BoxRepository,
    clock: BoxClock,
    mut rng: BoxRng,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, InternalError> {
    // TODO: keep the full path, not just the action
    let mut login = mas_router::Login::and_then(PostAuthAction::manage_account(action));

    if let Some(login_hint) = unstable_login_hint {
        login = login.with_login_hint(login_hint);
    }

    if let Some(login_method) = login_method {
        login = login.with_login_method(login_method);
    }

    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        login.clone(),
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

    let Some(session) = maybe_session else {
        return Ok((cookie_jar, url_builder.redirect(&login)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
) -> Result<impl IntoResponse, InternalError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;

    Ok(Html(content).into_response())
}

#[cfg(test)]
mod test {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_axum_utils::SessionInfoExt as _;
    use mas_router::{AccountAction, LoginMethodHint, Route};
    use mas_storage::{
        RepositoryAccess,
        user::{BrowserSessionRepository, UserRepository},
    };
    use sqlx::PgPool;

    use crate::test_utils::{
        CookieHelper, RequestBuilderExt, ResponseExt, TestState, add_upstream_oauth_provider, setup,
    };

    /// The deeplink hands the login-method hint over to the login page, next
    /// to the account-management action.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_threads_the_login_method_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let provider_id =
            add_upstream_oauth_provider(&state, "upstream.example.com", "Upstream Ltd.", 0)
                .await
                .id;

        let request = Request::get(format!(
            "/account/?action=org.matrix.profile\
             &io.element.login_method=upstream-oauth2:{provider_id}"
        ))
        .empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(
            LOCATION,
            &mas_router::Login::and_then(mas_router::PostAuthAction::manage_account(Some(
                AccountAction::OrgMatrixProfile,
            )))
            .with_login_method(LoginMethodHint::UpstreamOAuth2(provider_id))
            .path_and_query(),
        );
    }

    /// With a session finished out-of-band, the 'logged out' interstitial
    /// carries the login-method hint in its sign-out form.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_deeplink_logged_out_session_keeps_the_login_method_hint(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let cookies = CookieHelper::new();

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "john".to_owned())
            .await
            .unwrap();
        let session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        cookies.import(state.cookie_jar().set_session(&session));
        repo.browser_session()
            .finish(&state.clock, session)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request =
            Request::get("/account/?action=org.matrix.profile&io.element.login_method=password")
                .empty();
        let request = cookies.with_cookies(request);
        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert!(
            response
                .body()
                .contains(r#"name="io.element.login_method" value="password""#),
            "body: {}",
            response.body()
        );
    }
}
