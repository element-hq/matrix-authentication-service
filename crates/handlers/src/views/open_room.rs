// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{extract::State, response::Redirect};
use axum_extra::extract::{Query, QueryRejection};
use mas_data_model::SiteConfig;
use mas_router::{OpenRoom, UrlBuilder};

use super::shared::OptionalPostAuthAction;
use crate::room_id::is_valid_room_id;

/// Send the browser to the room in the configured client. Without a client,
/// or without a valid room ID, it goes where a missing post-auth action goes.
#[tracing::instrument(
    name = "handlers.views.open_room.get",
    fields(room.id = tracing::field::Empty),
    skip_all,
)]
pub(crate) async fn get(
    State(url_builder): State<UrlBuilder>,
    State(site_config): State<SiteConfig>,
    query: Result<Query<OpenRoom>, QueryRejection>,
) -> Redirect {
    let room_id = query
        .ok()
        .map(|Query(query)| query.room_id)
        .filter(|room_id| is_valid_room_id(room_id));

    match (site_config.guest_invites_client_room_url, room_id) {
        (Some(client_room_url), Some(room_id)) => {
            tracing::Span::current().record("room.id", room_id.as_str());
            Redirect::to(&client_room_url.replace("{room_id}", &urlencoding::encode(&room_id)))
        }
        _ => OptionalPostAuthAction::default().go_next(&url_builder),
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode, header::LOCATION};
    use sqlx::PgPool;

    use crate::{
        SiteConfig,
        test_utils::{RequestBuilderExt, ResponseExt, TestState, setup, test_site_config},
    };

    async fn assert_open_room(state: &TestState, query: &str, location: &str) {
        let request = Request::get(format!("/open-room?{query}")).empty();
        let response = state.request(request).await;
        response.assert_status(StatusCode::SEE_OTHER);
        response.assert_header_value(LOCATION, location);
    }

    /// The room ID is percent-encoded into the client URL, with a space
    /// encoded as `%20` and not `+`, which the client wouldn't decode.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        assert_open_room(
            &state,
            "room_id=%21abc%3Aexample.com",
            "https://app.example.com/#/room/%21abc%3Aexample.com",
        )
        .await;
        // A version 12 room ID has no server name
        assert_open_room(
            &state,
            "room_id=%2131hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM",
            "https://app.example.com/#/room/%2131hneApxJ_1o-63DmFrpeqnkFfWppnzWso1JvH3ogLM",
        )
        .await;
        assert_open_room(
            &state,
            "room_id=%21a%2Bb%20c%2F%23",
            "https://app.example.com/#/room/%21a%2Bb%20c%2F%23",
        )
        .await;
    }

    /// A missing or invalid room ID, including one with control or bidi
    /// characters, goes where a missing post-auth action goes
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room_not_a_room_id(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();

        for query in [
            "room_id=%23alias%3Aexample.com".to_owned(),
            "room_id=https%3A%2F%2Fevil.example.com".to_owned(),
            "room_id=".to_owned(),
            String::new(),
            format!("room_id=%21{}", "a".repeat(255)),
            "room_id=%21a%0Ab%3Aexample.com".to_owned(),
            "room_id=%21a%C2%85b%3Aexample.com".to_owned(),
            "room_id=%21a%E2%80%AEb%3Aexample.com".to_owned(),
        ] {
            assert_open_room(&state, &query, "/").await;
        }
    }

    /// Without a client to send them to, invitees go where a missing post-auth
    /// action goes
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_open_room_without_client_room_url(pool: PgPool) {
        setup();
        let state = TestState::from_pool_with_site_config(
            pool,
            SiteConfig {
                guest_invites_client_room_url: None,
                ..test_site_config()
            },
        )
        .await
        .unwrap();

        assert_open_room(&state, "room_id=%21abc%3Aexample.com", "/").await;
    }
}
