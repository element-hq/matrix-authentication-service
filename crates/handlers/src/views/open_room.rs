// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{
    extract::{Path, State},
    response::Redirect,
};
use mas_axum_utils::InternalError;
use mas_data_model::SiteConfig;
use mas_router::UrlBuilder;
use mas_storage::BoxRepository;
use ulid::Ulid;

use super::shared::OptionalPostAuthAction;

/// Send the browser to the room of a registration token in the configured
/// client. The token's validity doesn't matter, so that its link still opens
/// the room after registering, and no session is needed, since a room's ID
/// lets nobody join it. Without a token, a room or a client, it goes where a
/// missing post-auth action goes.
#[tracing::instrument(
    name = "handlers.views.open_room.get",
    fields(user_registration_token.id = %id),
    skip_all,
)]
pub(crate) async fn get(
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    mut repo: BoxRepository,
    Path(id): Path<Ulid>,
) -> Result<Redirect, InternalError> {
    let room_id = repo
        .user_registration_token()
        .lookup(id)
        .await?
        .and_then(|token| token.room_id);

    Ok(match (site_config.room_invites_client_room_url, room_id) {
        (Some(client_room_url), Some(room_id)) => {
            Redirect::to(&client_room_url.replace("{room_id}", &urlencoding::encode(&room_id)))
        }
        _ => OptionalPostAuthAction::default().go_next(&url_builder),
    })
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use hyper::{Request, StatusCode, header::LOCATION};
    use mas_data_model::{Clock as _, UserRegistrationToken};
    use rand::distr::{Alphanumeric, SampleString as _};
    use sqlx::PgPool;
    use ulid::Ulid;

    use crate::{
        SiteConfig,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup, test_site_config},
    };

    async fn add_token(state: &TestState, room_id: Option<&str>) -> UserRegistrationToken {
        let mut rng = state.rng();
        let token = Alphanumeric.sample_string(&mut rng, 12);
        let mut repo = state.repository().await.unwrap();
        let token = repo
            .user_registration_token()
            .add(
                &mut rng,
                &state.clock,
                token,
                Some(1),
                Some(state.clock.now() + Duration::hours(1)),
                None,
                None,
                false,
                room_id.map(ToOwned::to_owned),
            )
            .await
            .unwrap();
        repo.save().await.unwrap();
        token
    }

    async fn assert_open_room(state: &TestState, id: Ulid, location: &str) {
        let request = Request::get(format!("/open-room/{id}")).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, location);
    }

    /// The room ID is percent-encoded into the client URL, with a space
    /// encoded as `%20` and not `+`, which the client wouldn't decode. The
    /// client URL is used whether or not guest invites are enabled.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                guest_invites_enabled: false,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        for (room_id, location) in [
            (
                "!abc:example.com",
                "https://app.example.com/#/room/%21abc%3Aexample.com",
            ),
            (
                "!31hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM",
                "https://app.example.com/#/room/%2131hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM",
            ),
            (
                "!a+b c/#",
                "https://app.example.com/#/room/%21a%2Bb%20c%2F%23",
            ),
        ] {
            let token = add_token(&state, Some(room_id)).await;
            assert_open_room(&state, token.id, location).await;
        }
    }

    /// A token that can no longer register still opens its room
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room_invalid_token(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let location = "https://app.example.com/#/room/%21abc%3Aexample.com";

        let used = add_token(&state, Some("!abc:example.com")).await;
        let expired = add_token(&state, Some("!abc:example.com")).await;
        let revoked = add_token(&state, Some("!abc:example.com")).await;

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
            assert_open_room(&state, token.id, location).await;
        }

        state.clock.advance(Duration::hours(2));
        assert!(!expired.is_valid(state.clock.now()));
        assert_open_room(&state, expired.id, location).await;
    }

    /// An unknown token, or a token without a room, goes where a missing
    /// post-auth action goes
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room_without_room(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        let token = add_token(&state, None).await;
        assert_open_room(&state, token.id, "/").await;
        assert_open_room(&state, Ulid::nil(), "/").await;
    }

    /// Without a client to send them to, invitees go where a missing post-auth
    /// action goes
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room_without_client_room_url(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                room_invites_client_room_url: None,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        let token = add_token(&state, Some("!abc:example.com")).await;
        assert_open_room(&state, token.id, "/").await;
    }
}
