// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Query, State},
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{FancyError, SessionInfoExt, cookies::CookieJar, csrf::CsrfExt as _};
use mas_data_model::SiteConfig;
use mas_router::{PasswordRegister, UpstreamOAuth2Authorize, UrlBuilder};
use mas_storage::{BoxClock, BoxRepository, BoxRng};
use mas_templates::{RegisterContext, TemplateContext, Templates};

use super::shared::OptionalPostAuthAction;
use crate::{BoundActivityTracker, PreferredLanguage};

mod cookie;
pub(crate) mod password;
pub(crate) mod steps;

#[tracing::instrument(name = "handlers.views.register.get", skip_all, err)]
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
    cookie_jar: CookieJar,
) -> Result<Response, FancyError> {
    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_active_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        let reply = query.go_next(&url_builder);
        return Ok((cookie_jar, reply).into_response());
    };

    let providers = repo.upstream_oauth_provider().all_enabled().await?;

    // If password-based login is disabled, and there is only one upstream provider,
    // we can directly start an authorization flow
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
    let post_action = query.load_context(&mut repo).await?;
    if let Some(action) = post_action {
        ctx = ctx.with_post_action(action);
    }

    let ctx = ctx.with_csrf(csrf_token.form_value()).with_language(locale);

    let content = templates.render_register(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}
