// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use axum::{
    extract::{Form, State},
    response::{IntoResponse, Redirect},
};
use mas_axum_utils::{
    FancyError, SessionInfoExt,
    cookies::CookieJar,
    csrf::{CsrfExt, ProtectedForm},
};
use mas_router::{PostAuthAction, UrlBuilder};
use mas_storage::{BoxClock, BoxRepository, user::BrowserSessionRepository};
use tracing::warn;

use crate::{BoundActivityTracker, upstream_oauth2::logout::get_rp_initiated_logout_endpoints};

#[tracing::instrument(name = "handlers.views.logout.post", skip_all, err)]
pub(crate) async fn post(
    clock: BoxClock,
    mut repo: BoxRepository,
    cookie_jar: CookieJar,
    State(url_builder): State<UrlBuilder>,
    activity_tracker: BoundActivityTracker,
    Form(form): Form<ProtectedForm<Option<PostAuthAction>>>,
) -> Result<impl IntoResponse, FancyError> {
    let form: Option<PostAuthAction> = cookie_jar.verify_form(&clock, form)?;
    let (session_info, cookie_jar) = cookie_jar.session_info();

    let mut upstream_logout_url = None;

    if let Some(session_id) = session_info.current_session_id() {
        let maybe_session = repo.browser_session().lookup(session_id).await?;
        if let Some(session) = maybe_session {
            if session.finished_at.is_none() {
                activity_tracker
                    .record_browser_session(&clock, &session)
                    .await;

                // First, get RP-initiated logout endpoints before actually finishing the
                // session
                match get_rp_initiated_logout_endpoints(&url_builder, &mut repo, &cookie_jar).await
                {
                    Ok(logout_info) => {
                        // If we have any RP-initiated logout endpoints, use the first one
                        if !logout_info.logout_endpoints.is_empty() {
                            upstream_logout_url = Some(logout_info.logout_endpoints.clone());
                        }
                    }
                    Err(e) => {
                        warn!("Failed to get RP-initiated logout endpoints: {}", e);
                        // Continue with logout even if endpoint retrieval fails
                    }
                }
                // Now finish the session
                repo.browser_session().finish(&clock, session).await?;
            }
        }
    }

    repo.save().await?;

    // We always want to clear out the session cookie, even if the session was
    // invalid
    let cookie_jar = cookie_jar.update_session_info(&session_info.mark_session_ended());

    // If we have an upstream provider to logout from, redirect to it
    if let Some(logout_url) = upstream_logout_url {
        return Ok((cookie_jar, Redirect::to(&logout_url)).into_response());
    }

    // Default behavior - redirect to login or specified action
    let destination = if let Some(action) = form {
        action.go_next(&url_builder)
    } else {
        url_builder.redirect(&mas_router::Login::default())
    };

    Ok((cookie_jar, destination).into_response())
}
