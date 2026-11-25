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
use hyper::header::CONTENT_SECURITY_POLICY;
use mas_axum_utils::{InternalError, cookies::CookieJar};
use mas_data_model::{BoxClock, BoxRng, SiteConfig};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::BoxRepository;
use mas_templates::{AppContext, TemplateContext, Templates};
use serde::Deserialize;

use crate::{
    BoundActivityTracker, PreferredLanguage, csp,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[derive(Deserialize)]
pub struct Params {
    #[serde(default, flatten)]
    action: Option<mas_router::AccountAction>,

    #[serde(rename = "org.matrix.msc4198.login_hint")]
    unstable_login_hint: Option<String>,
}

#[tracing::instrument(name = "handlers.views.app.get", skip_all)]
pub async fn get(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    activity_tracker: BoundActivityTracker,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    Query(Params {
        action,
        unstable_login_hint,
    }): Query<Params>,
    mut repo: BoxRepository,
    clock: BoxClock,
    mut rng: BoxRng,
    cookie_jar: CookieJar,
) -> Result<impl IntoResponse, InternalError> {
    let (cookie_jar, maybe_session) = match load_session_or_fallback(
        cookie_jar,
        &clock,
        &mut rng,
        &templates,
        &locale,
        Some(PostAuthAction::manage_account(action.clone())),
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

    // TODO: keep the full path, not just the action
    let Some(session) = maybe_session else {
        let mut url = mas_router::Login::and_then(PostAuthAction::manage_account(action));

        if let Some(login_hint) = unstable_login_hint {
            url = url.with_login_hint(login_hint);
        }

        return Ok((cookie_jar, url_builder.redirect(&url)).into_response());
    };

    activity_tracker
        .record_browser_session(&clock, &session)
        .await;

    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;
    let policy = csp::app(
        site_config.plan_management_iframe_uri.as_deref(),
        &url_builder,
    );

    Ok((
        cookie_jar,
        [(CONTENT_SECURITY_POLICY, policy)],
        Html(content),
    )
        .into_response())
}

/// Like `get`, but allow anonymous access.
/// Used for a subset of the account management paths.
/// Needed for e.g. account recovery.
#[tracing::instrument(name = "handlers.views.app.get_anonymous", skip_all)]
pub async fn get_anonymous(
    PreferredLanguage(locale): PreferredLanguage,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
) -> Result<impl IntoResponse, InternalError> {
    let ctx = AppContext::from_url_builder(&url_builder).with_language(locale);
    let content = templates.render_app(&ctx)?;
    let policy = csp::app(
        site_config.plan_management_iframe_uri.as_deref(),
        &url_builder,
    );

    Ok(([(CONTENT_SECURITY_POLICY, policy)], Html(content)).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::CONTENT_SECURITY_POLICY};
    use mas_axum_utils::SessionInfoExt as _;
    use sqlx::PgPool;

    use crate::{
        csp,
        test_utils::{CookieHelper, RequestBuilderExt, ResponseExt, TestState, setup},
    };

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_content_security_policy(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let mut rng = state.rng();
        let mut repo = state.repository().await.unwrap();
        let user = repo
            .user()
            .add(&mut rng, &state.clock, "alice".to_owned())
            .await
            .unwrap();
        let browser_session = repo
            .browser_session()
            .add(&mut rng, &state.clock, &user, None)
            .await
            .unwrap();
        repo.save().await.unwrap();

        let cookies = CookieHelper::new();
        cookies.import(state.cookie_jar().set_session(&browser_session));

        let response = state
            .request(cookies.with_cookies(Request::get("/account/").empty()))
            .await;
        response.assert_status(StatusCode::OK);

        let expected = csp::app(
            state.site_config.plan_management_iframe_uri.as_deref(),
            &state.url_builder,
        );
        response.assert_header_value(CONTENT_SECURITY_POLICY, expected.to_str().unwrap());
        assert!(expected.to_str().unwrap().contains("'unsafe-inline'"));
    }
}
