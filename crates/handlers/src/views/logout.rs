// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::IntoResponse,
};
use mas_axum_utils::{
    InternalError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_data_model::BoxClock;
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxRepository, user::BrowserSessionRepository};

use crate::BoundActivityTracker;

#[tracing::instrument(name = "handlers.views.logout.post", skip_all)]
pub(crate) async fn post(
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    Form(form): Form<ProtectedForm<Option<PostAuthAction>>>,
) -> Result<impl IntoResponse, InternalError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, cookie_jar) = cookie_jar.session_info();

    if let Some(session_id) = session_info.current_session_id() {
        let maybe_session = repo.browser_session().lookup(session_id).await?;
        if let Some(session) = maybe_session {
            if session.finished_at.is_none() {
                activity_tracker
                    .record_browser_session(&clock, &session)
                    .await;

                repo.browser_session().finish(&clock, session).await?;
            }
        }
    }

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    let destination = if let Some(action) = form {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&mas_router::Login::default())
    };

    Ok((cookie_jar, destination))
}
