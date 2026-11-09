// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::Redirect,
};
use mas_axum_utils::InternalError;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use ulid::Ulid;

use crate::views::shared::OptionalPostAuthAction;

/// Send the browser to the continue URL of a registration token. The token's
/// validity doesn't matter, so that its link still leads there after
/// registering. No session is needed either: the URL is no secret from
/// whoever holds the link, and getting there grants nothing. Without a token
/// or a continue URL, it goes where a missing post-auth action goes.
#[tracing::instrument(
    name = "handlers.views.register.continue_url.get",
    fields(user_registration_token.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    State(url_builder): State<UrlBuilder>,
    mut repo: BoxRepository,
    Path(id): Path<Ulid>,
) -> Result<Redirect, InternalError> {
    let continue_url = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .and_then(|token| token.continue_url);

    Ok(match continue_url {
        Some(continue_url) => Redirect::to(&continue_url),
        None => OptionalPostAuthAction::default().go_next(&url_builder),
    })
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::{Clock as _, UserRegistrationToken};
    use mas_storage::user::UserRegistrationTokenParams;
    use rand::distr::{Alphanumeric, SampleString as _};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    const CONTINUE_URL: &str =
        "https://app.example.com/#/room/%21abc%3Aexample.com?via=example.com";

    async fn add_token(state: &TestState, continue_url: Option<&str>) -> UserRegistrationToken {
        let mut rng = state.rng();
        let token = Alphanumeric.sample_string(&mut rng, 12);
        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                UserRegistrationTokenParams {
                    token,
                    usage_limit: Some(1),
                    expires_at: Some(state.clock.now() + Duration::hours(1)),
                    continue_url: continue_url.map(ToOwned::to_owned),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        token
    }

    async fn assert_continues(state: &TestState, id: Ulid, location: &str) {
        let request = Request::get(format!("/register/continue/{id}")).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, location);
    }

    /// The continue URL is redirected to as it was given
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_continue(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let token = add_token(&state, Some(CONTINUE_URL)).await;
        assert_continues(&state, token.id, CONTINUE_URL).await;
    }

    /// A token that can no longer register still leads to its continue URL
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_continue_invalid_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let used = add_token(&state, Some(CONTINUE_URL)).await;
        let expired = add_token(&state, Some(CONTINUE_URL)).await;
        let revoked = add_token(&state, Some(CONTINUE_URL)).await;

        let mut repo = state.repository().await.unwrap();
        let used = repo
            .user_registration_token()
            .use_token(&state.clock, used)
            .await
            .unwrap();
        let revoked = repo
            .user_registration_token()
            .revoke(&state.clock, revoked)
            .await
            .unwrap();
        repo.save().await.unwrap();

        for token in [used, revoked] {
            assert!(!token.is_valid(state.clock.now()));
            assert_continues(&state, token.id, CONTINUE_URL).await;
        }

        state.clock.advance(Duration::hours(2));
        assert!(!expired.is_valid(state.clock.now()));
        assert_continues(&state, expired.id, CONTINUE_URL).await;
    }

    /// An unknown token, or a token without a continue URL, goes where a
    /// missing post-auth action goes
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_continue_without_url(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let token = add_token(&state, None).await;
        assert_continues(&state, token.id, "/").await;
        assert_continues(&state, Ulid::nil(), "/").await;
    }
}
