// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod browser_session;
mod compat_session;
mod matrix;
mod oauth2_session;
mod user;
mod user_email;

use async_graphql::MergedObject;

/// The mutations root of the GraphQL interface.
#[derive(Default, MergedObject)]
pub struct Mutation(
    user_email::UserEmailMutations,
    user::UserMutations,
    oauth2_session::OAuth2SessionMutations,
    compat_session::CompatSessionMutations,
    browser_session::BrowserSessionMutations,
    matrix::MatrixMutations,
);

impl Mutation {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}
