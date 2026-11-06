// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use mas_data_model::{UserRegistration, UserRegistrationToken};

pub(crate) mod display_name;
pub(crate) mod finish;
pub(crate) mod registration_token;
pub(crate) mod verify_email;

/// Whether `token` can be used for `registration`, whose email address is
/// `email`: it pins no other username or email address, and it is passwordless
/// if the registration has neither a password nor an upstream link
fn token_fits(
    token: &UserRegistrationToken,
    registration: &UserRegistration,
    email: Option<&str>,
) -> bool {
    token
        .username
        .as_ref()
        .is_none_or(|username| *username == registration.username)
        && token
            .email
            .as_deref()
            .is_none_or(|pinned| email.is_some_and(|email| pinned.eq_ignore_ascii_case(email)))
        && (token.passwordless
            || registration.password.is_some()
            || registration
                .upstream_oauth_authorization_session_id
                .is_some())
}
