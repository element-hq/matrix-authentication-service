// Copyright (C) 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::IntoResponse,
};
use mas_axum_utils::{
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
    FancyError, SessionInfoExt,
};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{user::BrowserSessionRepository, BoxClock, BoxRepository};

use crate::BoundActivityTracker;

#[tracing::instrument(name = "handlers.views.logout.post", skip_all, err)]
pub(crate) async fn post(
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    Form(form): Form<ProtectedForm<Option<PostAuthAction>>>,
) -> Result<impl IntoResponse, FancyError> {
    let form = cookie_jar.verify_form(&clock, form)?;

    let (session_info, mut cookie_jar) = cookie_jar.session_info();

    let maybe_session = session_info.load_session(&mut repo).await?;

    if let Some(session) = maybe_session {
        activity_tracker
            .record_browser_session(&clock, &session)
            .await;

        repo.browser_session().finish(&clock, session).await?;
        cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());
    }

    repo.save().await?;

    let destination = if let Some(action) = form {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&mas_router::Login::default())
    };

    Ok((cookie_jar, destination))
}
