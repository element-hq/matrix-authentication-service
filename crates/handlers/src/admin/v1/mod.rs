// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use aide::axum::{
    routing::{get_with, post_with},
    ApiRouter,
};
use axum::extract::{FromRef, FromRequestParts};
use mas_matrix::BoxHomeserverConnection;
use mas_storage::BoxRng;

use super::call_context::CallContext;
use crate::passwords::PasswordManager;

mod oauth2_sessions;
mod users;

pub fn router<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    BoxHomeserverConnection: FromRef<S>,
    PasswordManager: FromRef<S>,
    BoxRng: FromRequestParts<S>,
    CallContext: FromRequestParts<S>,
{
    ApiRouter::<S>::new()
        .api_route(
            "/oauth2-sessions",
            get_with(self::oauth2_sessions::list, self::oauth2_sessions::list_doc),
        )
        .api_route(
            "/oauth2-sessions/{id}",
            get_with(self::oauth2_sessions::get, self::oauth2_sessions::get_doc),
        )
        .api_route(
            "/users",
            get_with(self::users::list, self::users::list_doc)
                .post_with(self::users::add, self::users::add_doc),
        )
        .api_route(
            "/users/{id}",
            get_with(self::users::get, self::users::get_doc),
        )
        .api_route(
            "/users/{id}/emails",
            get_with(self::users::get_emails, self::users::get_emails_doc),
        )
        .api_route(
            "/users/{id}/set-password",
            post_with(self::users::set_password, self::users::set_password_doc),
        )
        .api_route(
            "/users/by-username/{username}",
            get_with(self::users::by_username, self::users::by_username_doc),
        )
        .api_route(
            "/users/{id}/set-admin",
            post_with(self::users::set_admin, self::users::set_admin_doc),
        )
        .api_route(
            "/users/{id}/deactivate",
            post_with(self::users::deactivate, self::users::deactivate_doc),
        )
        .api_route(
            "/users/{id}/lock",
            post_with(self::users::lock, self::users::lock_doc),
        )
        .api_route(
            "/users/{id}/unlock",
            post_with(self::users::unlock, self::users::unlock_doc),
        )
}
