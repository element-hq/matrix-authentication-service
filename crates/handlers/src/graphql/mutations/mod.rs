// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

mod browser_session;
mod compat_session;
mod matrix;
mod oauth2_session;
mod user;
mod user_email;
mod user_passkey;

use anyhow::Context as _;
use async_graphql::MergedObject;
use mas_data_model::SiteConfig;
use mas_storage::BoxRepository;
use zeroize::Zeroizing;

use super::Requester;
use crate::passwords::PasswordManager;

/// The mutations root of the GraphQL interface.
#[derive(Default, MergedObject)]
pub struct Mutation(
    user_email::UserEmailMutations,
    user_passkey::UserPasskeyMutations,
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

/// Check the password if neeed
///
/// Returns true if password verification is not needed, or if the password is
/// correct. Returns false if the password is incorrect or missing.
async fn verify_password_if_needed(
    requester: &Requester,
    config: &SiteConfig,
    password_manager: &PasswordManager,
    password: Option<String>,
    user: &mas_data_model::User,
    repo: &mut BoxRepository,
) -> Result<bool, async_graphql::Error> {
    // If the requester is admin, they don't need to provide a password
    if requester.is_admin() {
        return Ok(true);
    }

    // If password login is disabled, assume we don't want the user to reauth
    if !config.password_login_enabled {
        return Ok(true);
    }

    // Else we need to check if the user has a password
    let Some(user_password) = repo
        .user_password()
        .active(user)
        .await
        .context("Failed to load user password")?
    else {
        // User has no password, so we don't need to verify the password
        return Ok(true);
    };

    let Some(password) = password else {
        // There is a password on the user, but not provided in the input
        return Ok(false);
    };

    let password = Zeroizing::new(password);

    let res = password_manager
        .verify(
            user_password.version,
            password,
            user_password.hashed_password,
        )
        .await?;

    Ok(res.is_success())
}
