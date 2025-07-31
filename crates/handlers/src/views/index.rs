// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::State,
    response::{Html, IntoResponse, Response},
};
use mas_axum_utils::{InternalError, cookies::CookieJar, csrf::CsrfExt};
use mas_data_model::{BoxClock, BoxRng};
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use mas_templates::{IndexContext, TemplateContext, Templates};

use crate::{
    BoundActivityTracker,
    preferred_language::PreferredLanguage,
    session::{SessionOrFallback, load_session_or_fallback},
};

#[tracing::instrument(name = "handlers.views.index.get", skip_all)]
pub async fn get(
    mut rng: BoxRng,
    clock: BoxClock,
    activity_tracker: BoundActivityTracker,
    State(templates): State<Templates>,
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    PreferredLanguage(locale): PreferredLanguage,
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

    let (csrf_token, cookie_jar) = cookie_jar.csrf_token(&clock, &mut rng);

    if let Some(session) = maybe_session.as_ref() {
        activity_tracker
            .record_browser_session(&clock, session)
            .await;
    }

    let ctx = IndexContext::new(url_builder.oidc_discovery())
        .maybe_with_session(maybe_session)
        .with_csrf(csrf_token.form_value())
        .with_language(locale);

    let content = templates.render_index(&ctx)?;

    Ok((cookie_jar, Html(content)).into_response())
}
