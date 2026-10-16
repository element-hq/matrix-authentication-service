// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use rand::RngExt;
use serde::Serialize;
use ulid::Ulid;
use url::Url;

use crate::UlidExt as _;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatrixUser {
    pub mxid: String,
    pub display_name: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct User {
    pub id: Ulid,
    pub username: String,
    pub sub: String,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
    pub is_guest: bool,
}

impl User {
    /// Returns `true` unless the user is locked or deactivated.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.locked_at.is_none() && self.deactivated_at.is_none()
    }

    /// Returns `true` if the user is a valid actor, for example
    /// of a personal session.
    ///
    /// Currently: this is `true` unless the user is deactivated.
    ///
    /// This is a weaker form of validity: `is_valid` always implies
    /// `is_valid_actor`, but some users (currently: locked users)
    /// can be valid actors for personal sessions but aren't valid
    /// except through administrative access.
    #[must_use]
    pub fn is_valid_actor(&self) -> bool {
        self.deactivated_at.is_none()
    }
}

impl User {
    #[doc(hidden)]
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl RngExt) -> Vec<Self> {
        vec![User {
            id: Ulid::from_datetime_with_rng(now, rng),
            username: "john".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: false,
        }]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Password {
    pub id: Ulid,
    pub hashed_password: String,
    pub version: u16,
    pub upgraded_from_id: Option<Ulid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Authentication {
    pub id: Ulid,
    pub created_at: DateTime<Utc>,
    pub authentication_method: AuthenticationMethod,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum AuthenticationMethod {
    Password { user_password_id: Ulid },
    UpstreamOAuth2 { upstream_oauth2_session_id: Ulid },
    Unknown,
}

/// A session to recover a user if they have lost their credentials
///
/// For each session intiated, there may be multiple [`UserRecoveryTicket`]s
/// sent to the user, either because multiple [`User`] have the same email
/// address, or because the user asked to send the recovery email again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoverySession {
    pub id: Ulid,
    pub email: String,
    pub user_agent: String,
    pub ip_address: Option<IpAddr>,
    pub locale: String,
    pub created_at: DateTime<Utc>,
    pub consumed_at: Option<DateTime<Utc>>,
}

/// A single recovery ticket for a user recovery session
///
/// Whenever a new recovery session is initiated, a new ticket is created for
/// each email address matching in the database. That ticket is sent by email,
/// as a link that the user can click to recover their account.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRecoveryTicket {
    pub id: Ulid,
    pub user_recovery_session_id: Ulid,
    pub user_email_id: Ulid,
    pub ticket: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl UserRecoveryTicket {
    #[must_use]
    pub fn active(&self, now: DateTime<Utc>) -> bool {
        now < self.expires_at
    }
}

/// A user email authentication session
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailAuthentication {
    pub id: Ulid,
    pub user_session_id: Option<Ulid>,
    pub user_registration_id: Option<Ulid>,
    pub email: String,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

/// A user email authentication code
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmailAuthenticationCode {
    pub id: Ulid,
    pub user_email_authentication_id: Ulid,
    pub code: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BrowserSession {
    pub id: Ulid,
    pub user: User,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub user_agent: Option<String>,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
}

impl BrowserSession {
    #[must_use]
    pub fn active(&self) -> bool {
        self.finished_at.is_none() && self.user.is_valid()
    }
}

impl BrowserSession {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl RngExt) -> Vec<Self> {
        User::samples(now, rng)
            .into_iter()
            .map(|user| BrowserSession {
                id: Ulid::from_datetime_with_rng(now, rng),
                user,
                created_at: now,
                finished_at: None,
                user_agent: Some(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.0.0 Safari/537.36".to_owned()
                ),
                last_active_at: Some(now),
                last_active_ip: None,
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserEmail {
    pub id: Ulid,
    pub user_id: Ulid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl UserEmail {
    #[must_use]
    pub fn samples(now: chrono::DateTime<Utc>, rng: &mut impl RngExt) -> Vec<Self> {
        vec![
            Self {
                id: Ulid::from_datetime_with_rng(now, rng),
                user_id: Ulid::from_datetime_with_rng(now, rng),
                email: "alice@example.com".to_owned(),
                created_at: now,
            },
            Self {
                id: Ulid::from_datetime_with_rng(now, rng),
                user_id: Ulid::from_datetime_with_rng(now, rng),
                email: "bob@example.com".to_owned(),
                created_at: now,
            },
        ]
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistrationPassword {
    pub hashed_password: String,
    pub version: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistrationToken {
    pub id: Ulid,
    pub token: String,
    /// A localpart to impose, or a template for one: a value with exactly one
    /// `{random}`
    pub username: Option<String>,
    pub email: Option<String>,
    pub passwordless: bool,
    pub room_id: Option<String>,
    pub usage_limit: Option<u32>,
    pub times_used: u32,
    pub created_at: DateTime<Utc>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub expires_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

impl UserRegistrationToken {
    /// Returns `true` if the token is still valid and can be used
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        // Check if revoked
        if self.revoked_at.is_some() {
            return false;
        }

        // Check if expired
        if let Some(expires_at) = self.expires_at
            && now >= expires_at
        {
            return false;
        }

        // Check if usage limit exceeded
        if let Some(usage_limit) = self.usage_limit
            && self.times_used >= usage_limit
        {
            return false;
        }

        true
    }

    /// Returns `true` if the token is an invite: it registers without a
    /// password, as the username (or username template) and the email
    /// address it pins
    #[must_use]
    pub fn is_invite(&self) -> bool {
        self.passwordless && self.username.is_some() && self.email.is_some()
    }

    /// Returns `true` if the token can still be used (not expired and under
    /// usage limit)
    #[must_use]
    pub fn can_be_used(&self, now: DateTime<Utc>) -> bool {
        self.is_valid(now)
    }

    /// Returns `true` if the token allows registering `username`: it imposes
    /// none, it imposes this one, or its template fills in to it
    #[must_use]
    pub fn username_fits(&self, username: &str) -> bool {
        let Some(imposed) = &self.username else {
            return true;
        };

        match split_username_template(imposed) {
            Some((prefix, suffix)) => username
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .is_some_and(|random| {
                    random.len() == USERNAME_TEMPLATE_RANDOM_LENGTH
                        && random
                            .bytes()
                            .all(|c| USERNAME_TEMPLATE_CHARSET.contains(&c))
                }),
            // Multiple placeholders aren't resolved in a template, and braces
            // aren't allowed in a localpart, so nothing fits
            None => !imposed.contains(USERNAME_TEMPLATE_PLACEHOLDER) && imposed == username,
        }
    }

    /// The token's username template with its `{random}` filled in, if its
    /// username is one
    #[must_use]
    pub fn fill_username(&self, rng: &mut (impl RngExt + ?Sized)) -> Option<String> {
        let (prefix, suffix) = split_username_template(self.username.as_deref()?)?;

        let random: String = (0..USERNAME_TEMPLATE_RANDOM_LENGTH)
            .map(|_| {
                char::from(
                    USERNAME_TEMPLATE_CHARSET[rng.random_range(0..USERNAME_TEMPLATE_CHARSET.len())],
                )
            })
            .collect();
        Some(format!("{prefix}{random}{suffix}"))
    }
}

/// The literal parts before and after the `{random}` of `username`, if it is
/// a username template
fn split_username_template(username: &str) -> Option<(&str, &str)> {
    let (prefix, suffix) = username.split_once(USERNAME_TEMPLATE_PLACEHOLDER)?;
    (!suffix.contains(USERNAME_TEMPLATE_PLACEHOLDER)).then_some((prefix, suffix))
}

/// `username` with its `{random}` filled in with letters and digits in turn,
/// if it is a username template. A policy that refuses letters or digits
/// refuses the sample too, but one that refuses only long runs of either does
/// not.
#[must_use]
pub fn username_template_sample(username: &str) -> Option<String> {
    let (prefix, suffix) = split_username_template(username)?;

    let (letters, digits): (Vec<u8>, Vec<u8>) = USERNAME_TEMPLATE_CHARSET
        .iter()
        .partition(|c| c.is_ascii_lowercase());
    let random: String = letters
        .iter()
        .cycle()
        .zip(digits.iter().cycle())
        .flat_map(|(&letter, &digit)| [letter, digit])
        .take(USERNAME_TEMPLATE_RANDOM_LENGTH)
        .map(char::from)
        .collect();
    Some(format!("{prefix}{random}{suffix}"))
}

/// Stands for the random part of a [`UserRegistrationToken`]'s username
/// template. The registration policy refuses `{` and `}` in a localpart, so a
/// pin that can register never contains it.
pub const USERNAME_TEMPLATE_PLACEHOLDER: &str = "{random}";
/// 36^32 is about 2^165 names, so two filled-in templates never collide
const USERNAME_TEMPLATE_RANDOM_LENGTH: usize = 32;
/// The lowercase letters and digits of the localpart grammar
const USERNAME_TEMPLATE_CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct UserRegistration {
    pub id: Ulid,
    pub username: String,
    pub display_name: Option<String>,
    pub terms_url: Option<Url>,
    pub email_authentication_id: Option<Ulid>,
    pub user_registration_token_id: Option<Ulid>,
    pub password: Option<UserRegistrationPassword>,
    pub upstream_oauth_authorization_session_id: Option<Ulid>,
    pub post_auth_action: Option<serde_json::Value>,
    pub ip_address: Option<IpAddr>,
    pub user_agent: Option<String>,
    pub created_at: DateTime<Utc>,
    pub completed_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng as _;
    use rand_chacha::ChaChaRng;

    use super::*;

    fn with_username(username: Option<&str>) -> UserRegistrationToken {
        UserRegistrationToken {
            id: Ulid::nil(),
            token: "token".to_owned(),
            username: username.map(ToOwned::to_owned),
            email: None,
            passwordless: true,
            room_id: None,
            usage_limit: None,
            times_used: 0,
            created_at: DateTime::UNIX_EPOCH,
            last_used_at: None,
            expires_at: None,
            revoked_at: None,
        }
    }

    #[test]
    fn test_username_pin() {
        let mut rng = ChaChaRng::seed_from_u64(42);

        let token = with_username(None);
        assert!(token.username_fits("alice"));
        assert_eq!(token.fill_username(&mut rng), None);

        let token = with_username(Some("alice"));
        assert!(token.username_fits("alice"));
        assert!(!token.username_fits("bob"));
        assert_eq!(token.fill_username(&mut rng), None);
    }

    #[test]
    fn test_username_template() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let random = "a1".repeat(16);

        for (template, prefix, suffix) in [
            ("user-{random}", "user-", ""),
            ("{random}-user", "", "-user"),
            ("user-{random}-x", "user-", "-x"),
            ("{random}", "", ""),
        ] {
            let token = with_username(Some(template));

            let filled = token.fill_username(&mut rng).unwrap();
            let random_part = filled
                .strip_prefix(prefix)
                .and_then(|rest| rest.strip_suffix(suffix))
                .unwrap();
            assert_eq!(random_part.len(), 32, "{filled}");
            assert!(
                random_part
                    .bytes()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()),
                "{filled}"
            );
            assert!(token.username_fits(&filled), "{filled}");
            assert_ne!(token.fill_username(&mut rng).unwrap(), filled);

            assert!(token.username_fits(&format!("{prefix}{random}{suffix}")));
            assert!(!token.username_fits(template));
            // Too short, too long, not lowercase, or with other literal parts
            assert!(!token.username_fits(&format!("{prefix}{}{suffix}", &random[1..])));
            assert!(!token.username_fits(&format!("{prefix}{random}a{suffix}")));
            assert!(!token.username_fits(&format!("{prefix}{}{suffix}", random.to_uppercase())));
            assert!(!token.username_fits(&format!("x{prefix}{random}{suffix}")));
        }
    }

    #[test]
    fn test_username_two_placeholders() {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let random = "a".repeat(32);

        let token = with_username(Some("user-{random}-{random}"));
        assert!(!token.username_fits("user-{random}-{random}"));
        assert!(!token.username_fits(&format!("user-{random}-{random}")));
        assert_eq!(token.fill_username(&mut rng), None);
        assert_eq!(username_template_sample("user-{random}-{random}"), None);
    }

    #[test]
    fn test_username_template_sample() {
        let sample = username_template_sample("user-{random}-x").unwrap();
        assert_eq!(sample, "user-a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5-x");
        assert!(with_username(Some("user-{random}-x")).username_fits(&sample));

        assert_eq!(username_template_sample("alice"), None);
    }
}
