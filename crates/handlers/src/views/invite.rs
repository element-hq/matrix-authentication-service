// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::{IntoResponse, Response},
};
use mas_axum_utils::InternalError;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;

/// `GET /invite/{token}`
///
/// Deep-link to register with a specific registration token.
/// Redirects to the password registration page with the token pre-filled.
#[tracing::instrument(name = "handlers.views.invite.get", skip_all, fields(token))]
pub async fn get(
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    Path(token): Path<String>,
) -> Result<Response, InternalError> {
    // Look up the token to make sure it exists
    let registration_token = repo.user_registration_token().find_by_token(&token).await?;
    repo.cancel().await?;

    if registration_token.is_none() {
        // TODO: show a proper error page
        return Ok(axum::http::StatusCode::NOT_FOUND.into_response());
    }

    // Redirect to the registration page with the token as a query param
    let url = url_builder.absolute_url_for(&mas_router::PasswordRegister::default());
    let url = format!("{url}?token={token}");
    Ok(axum::response::Redirect::to(&url).into_response())
}
