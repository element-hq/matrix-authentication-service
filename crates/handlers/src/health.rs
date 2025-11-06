// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{extract::State, response::IntoResponse};
use mas_axum_utils::InternalError;
use sqlx::PgPool;
use tracing::{Instrument, info_span};

pub async fn get(State(pool): State<PgPool>) -> Result<impl IntoResponse, InternalError> {
    let mut conn = pool.acquire().await?;

    sqlx::query("SELECT $1")
        .bind(1_i64)
        .execute(&mut *conn)
        .instrument(info_span!("DB health"))
        .await?;

    Ok("ok")
}

#[cfg(test)]
mod tests {
    use hyper::{Request, StatusCode};

    use super::*;
    use crate::test_utils::{RequestBuilderExt, ResponseExt, TestState, setup};

    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_get_health(pool: PgPool) {
        setup();
        let state = TestState::from_pool(pool).await.unwrap();
        let request = Request::get("/health").empty();

        let response = state.request(request).await;
        response.assert_status(StatusCode::OK);
        assert_eq!(response.body(), "ok");
    }
}
