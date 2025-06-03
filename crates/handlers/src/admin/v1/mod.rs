// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::sync::Arc;

use aide::axum::{
    ApiRouter,
    routing::{get_with, post_with},
};
use axum::extract::{FromRef, FromRequestParts};
use mas_matrix::HomeserverConnection;
use mas_policy::PolicyFactory;
use mas_storage::BoxRng;

use super::call_context::CallContext;
use crate::passwords::PasswordManager;

mod compat_sessions;
mod oauth2_sessions;
mod policy_data;
mod upstream_oauth_links;
mod user_emails;
mod user_registration_tokens;
mod user_sessions;
mod users;

#[allow(clippy::too_many_lines)]
pub fn router<S>() -> ApiRouter<S>
where
    S: Clone + Send + Sync + 'static,
    Arc<dyn HomeserverConnection>: FromRef<S>,
    PasswordManager: FromRef<S>,
    Arc<PolicyFactory>: FromRef<S>,
    BoxRng: FromRequestParts<S>,
    CallContext: FromRequestParts<S>,
{
    ApiRouter::<S>::new()
        .api_route(
            "/compat-sessions",
            get_with(self::compat_sessions::list, self::compat_sessions::list_doc),
        )
        .api_route(
            "/compat-sessions/{id}",
            get_with(self::compat_sessions::get, self::compat_sessions::get_doc),
        )
        .api_route(
            "/oauth2-sessions",
            get_with(self::oauth2_sessions::list, self::oauth2_sessions::list_doc),
        )
        .api_route(
            "/oauth2-sessions/{id}",
            get_with(self::oauth2_sessions::get, self::oauth2_sessions::get_doc),
        )
        .api_route(
            "/policy-data",
            post_with(self::policy_data::set, self::policy_data::set_doc),
        )
        .api_route(
            "/policy-data/latest",
            get_with(
                self::policy_data::get_latest,
                self::policy_data::get_latest_doc,
            ),
        )
        .api_route(
            "/policy-data/{id}",
            get_with(self::policy_data::get, self::policy_data::get_doc),
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
        .api_route(
            "/user-emails",
            get_with(self::user_emails::list, self::user_emails::list_doc)
                .post_with(self::user_emails::add, self::user_emails::add_doc),
        )
        .api_route(
            "/user-emails/{id}",
            get_with(self::user_emails::get, self::user_emails::get_doc)
                .delete_with(self::user_emails::delete, self::user_emails::delete_doc),
        )
        .api_route(
            "/user-sessions",
            get_with(self::user_sessions::list, self::user_sessions::list_doc),
        )
        .api_route(
            "/user-sessions/{id}",
            get_with(self::user_sessions::get, self::user_sessions::get_doc),
        )
        .api_route(
            "/user-registration-tokens",
            get_with(
                self::user_registration_tokens::list,
                self::user_registration_tokens::list_doc,
            )
            .post_with(
                self::user_registration_tokens::add,
                self::user_registration_tokens::add_doc,
            ),
        )
        .api_route(
            "/user-registration-tokens/{id}",
            get_with(
                self::user_registration_tokens::get,
                self::user_registration_tokens::get_doc,
            ),
        )
        .api_route(
            "/user-registration-tokens/{id}/revoke",
            post_with(
                self::user_registration_tokens::revoke,
                self::user_registration_tokens::revoke_doc,
            ),
        )
        .api_route(
            "/upstream-oauth-links",
            get_with(
                self::upstream_oauth_links::list,
                self::upstream_oauth_links::list_doc,
            )
            .post_with(
                self::upstream_oauth_links::add,
                self::upstream_oauth_links::add_doc,
            ),
        )
        .api_route(
            "/upstream-oauth-links/{id}",
            get_with(
                self::upstream_oauth_links::get,
                self::upstream_oauth_links::get_doc,
            )
            .delete_with(
                self::upstream_oauth_links::delete,
                self::upstream_oauth_links::delete_doc,
            ),
        )
}
