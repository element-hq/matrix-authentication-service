// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use axum::{Json, extract::State, response::IntoResponse};
use mas_keystore::Keystore;

#[tracing::instrument(name = "handlers.oauth2.keys.get", skip_all)]
pub(crate) async fn get(State(key_store): State<Keystore>) -> impl IntoResponse {
    let jwks = key_store.public_jwks();
    Json(jwks)
}
