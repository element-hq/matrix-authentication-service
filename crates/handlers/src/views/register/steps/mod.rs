// Copyright 2026 Element Creations Ltd.
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
/// `email`: it pins no other username, and no other email address, ignoring
/// case
fn token_fits(
    token: &UserRegistrationToken,
    registration: &UserRegistration,
    email: Option<&str>,
) -> bool {
    let username_fits = token
        .username
        .as_ref()
        .is_none_or(|username| *username == registration.username);

    username_fits
        && email.map_or(token.email.is_none(), |email| {
            token
                .email
                .as_deref()
                .is_none_or(|pinned| pinned.eq_ignore_ascii_case(email))
        })
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use mas_data_model::{UserRegistration, UserRegistrationPassword, UserRegistrationToken};
    use ulid::Ulid;

    fn token(username: Option<&str>, email: Option<&str>) -> UserRegistrationToken {
        UserRegistrationToken {
            id: Ulid::nil(),
            token: "token".to_owned(),
            username: username.map(ToOwned::to_owned),
            email: email.map(ToOwned::to_owned),
            usage_limit: None,
            times_used: 0,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    fn registration(username: &str) -> UserRegistration {
        UserRegistration {
            id: Ulid::nil(),
            username: username.to_owned(),
            display_name: None,
            terms_url: None,
            email_authentication_id: None,
            user_registration_token_id: None,
            password: Some(UserRegistrationPassword {
                hashed_password: "hash".to_owned(),
                version: 1,
            }),
            upstream_oauth_authorization_session_id: None,
            post_auth_action: None,
            ip_address: None,
            user_agent: None,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            completed_at: None,
        }
    }

    const ALICE: Option<&str> = Some("alice@example.com");
    const ALICE_UPPER: Option<&str> = Some("ALICE@EXAMPLE.COM");
    const BOB: Option<&str> = Some("bob@example.com");

    #[test]
    fn test_token_fits() {
        let alice = registration("alice");
        let bob = registration("bob");
        let pins = token(Some("alice"), ALICE_UPPER);
        let plain = token(None, None);

        for (case, token, registration, email, fits) in [
            ("no pins", &plain, &alice, None, true),
            ("pins", &pins, &alice, ALICE, true),
            ("another username", &pins, &bob, ALICE, false),
            ("another email", &pins, &alice, BOB, false),
            ("no email for a pin", &pins, &alice, None, false),
        ] {
            assert_eq!(
                super::token_fits(token, registration, email),
                fits,
                "{case}"
            );
        }
    }
}
