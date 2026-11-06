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
/// `email`: it pins no other username, allows `email` if it pins or lists
/// addresses, and it is passwordless
/// if the registration has neither a password nor an upstream link. A rendered
/// name can't be checked against its template, so a username template fits
/// only the registration it was rendered for.
fn token_fits(
    token: &UserRegistrationToken,
    registration: &UserRegistration,
    email: Option<&str>,
) -> bool {
    let username_fits = if token.username_template().is_some() {
        registration.user_registration_token_id == Some(token.id)
    } else {
        token
            .username
            .as_ref()
            .is_none_or(|username| *username == registration.username)
    };

    username_fits
        && email.map_or(
            token.email.is_none() && token.allowed_emails.is_none(),
            |email| token.allows_email(email),
        )
        && (token.passwordless
            || registration.password.is_some()
            || registration
                .upstream_oauth_authorization_session_id
                .is_some())
}

#[cfg(test)]
mod tests {
    use chrono::{DateTime, Utc};
    use mas_data_model::{UserRegistration, UserRegistrationPassword, UserRegistrationToken};
    use ulid::Ulid;

    fn token(
        username: Option<&str>,
        email: Option<&str>,
        allowed_emails: Option<&[&str]>,
        passwordless: bool,
    ) -> UserRegistrationToken {
        UserRegistrationToken {
            id: Ulid::nil(),
            token: "token".to_owned(),
            username: username.map(ToOwned::to_owned),
            email: email.map(ToOwned::to_owned),
            allowed_emails: allowed_emails
                .map(|emails| emails.iter().map(|&email| email.to_owned()).collect()),
            passwordless,
            continue_url: None,
            usage_limit: None,
            times_used: 0,
            created_at: DateTime::<Utc>::UNIX_EPOCH,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    fn registration(username: &str, password: bool, upstream: bool) -> UserRegistration {
        UserRegistration {
            id: Ulid::nil(),
            username: username.to_owned(),
            display_name: None,
            terms_url: None,
            email_authentication_id: None,
            user_registration_token_id: None,
            password: password.then(|| UserRegistrationPassword {
                hashed_password: "hash".to_owned(),
                version: 1,
            }),
            upstream_oauth_authorization_session_id: upstream.then(Ulid::nil),
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
        let alice = registration("alice", true, false);
        let bob = registration("bob", true, false);
        let no_password = registration("alice", false, false);
        let upstream = registration("alice", false, true);
        let from_token = UserRegistration {
            user_registration_token_id: Some(Ulid::nil()),
            ..registration("guest-1", true, false)
        };
        let pins = token(Some("alice"), ALICE_UPPER, None, false);
        let template = token(Some("guest-{{ random }}"), None, None, false);
        let lists = token(None, None, Some(&["alice@example.com"]), false);
        let plain = token(None, None, None, false);
        let passwordless = token(None, None, None, true);

        for (case, token, registration, email, fits) in [
            ("no pins", &plain, &alice, None, true),
            ("pins", &pins, &alice, ALICE, true),
            ("another username", &pins, &bob, ALICE, false),
            ("another email", &pins, &alice, BOB, false),
            ("no email for a pin", &pins, &alice, None, false),
            ("own template", &template, &from_token, None, true),
            ("typed template", &template, &alice, None, false),
            ("listed email", &lists, &alice, ALICE_UPPER, true),
            ("unlisted email", &lists, &alice, BOB, false),
            ("no email for a list", &lists, &alice, None, false),
            ("no password", &plain, &no_password, None, false),
            ("passwordless", &passwordless, &no_password, None, true),
            ("upstream", &plain, &upstream, None, true),
        ] {
            assert_eq!(
                super::token_fits(token, registration, email),
                fits,
                "{case}"
            );
        }
    }
}
