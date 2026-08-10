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
/// Redirects to the registration page with the token pre-filled.
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
    let url = url_builder.absolute_url_for(&mas_router::Register::default());
    let url = format!("{url}?token={token}");
    Ok(axum::response::Redirect::to(&url).into_response())
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_router::Route;
    use sqlx::PgPool;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    /// An invite link hands the token over to the registration page
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_invite(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let mut rng = state.rng();

        let mut repo = state.repository().await.unwrap();
        repo.user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                "invite_code".to_owned(),
                None,
                None,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        repo.save().await.unwrap();

        let request =
            Request::get(&*mas_router::Invite::new("invite_code".to_owned()).path()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        assert!(
            response
                .headers()
                .get(LOCATION)
                .unwrap()
                .to_str()
                .unwrap()
                .ends_with("/register?token=invite_code")
        );

        // An unknown token doesn't lead anywhere
        let request = Request::get(&*mas_router::Invite::new("nope".to_owned()).path()).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::NOT_FOUND);
    }
}
