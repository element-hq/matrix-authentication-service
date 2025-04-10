// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use chrono::Duration;
use url::Url;

/// Which Captcha service is being used
#[derive(Debug, Clone, Copy)]
pub enum CaptchaService {
    RecaptchaV2,
    CloudflareTurnstile,
    HCaptcha,
}

/// Captcha configuration
#[derive(Debug, Clone)]
pub struct CaptchaConfig {
    /// Which Captcha service is being used
    pub service: CaptchaService,

    /// The site key used by the instance
    pub site_key: String,

    /// The secret key used by the instance
    pub secret_key: String,
}

/// Automatic session expiration configuration
#[derive(Debug, Clone)]
pub struct SessionExpirationConfig {
    pub user_session_inactivity_ttl: Option<Duration>,
    pub oauth_session_inactivity_ttl: Option<Duration>,
    pub compat_session_inactivity_ttl: Option<Duration>,
}

/// Random site configuration we want accessible in various places.
#[allow(clippy::struct_excessive_bools)]
#[derive(Debug, Clone)]
pub struct SiteConfig {
    /// Time-to-live of access tokens.
    pub access_token_ttl: Duration,

    /// Time-to-live of compatibility access tokens.
    pub compat_token_ttl: Duration,

    /// The server name, e.g. "matrix.org".
    pub server_name: String,

    /// The URL to the privacy policy.
    pub policy_uri: Option<Url>,

    /// The URL to the terms of service.
    pub tos_uri: Option<Url>,

    /// Imprint to show in the footer.
    pub imprint: Option<String>,

    /// Whether password login is enabled.
    pub password_login_enabled: bool,

    /// Whether password registration is enabled.
    pub password_registration_enabled: bool,

    /// Whether users can change their email.
    pub email_change_allowed: bool,

    /// Whether users can change their display name.
    pub displayname_change_allowed: bool,

    /// Whether users can change their password.
    pub password_change_allowed: bool,

    /// Whether users can recover their account via email.
    pub account_recovery_allowed: bool,

    /// Whether users can delete their own account.
    pub account_deactivation_allowed: bool,

    /// Captcha configuration
    pub captcha: Option<CaptchaConfig>,

    /// Minimum password complexity, between 0 and 4.
    /// This is a score from zxcvbn.
    pub minimum_password_complexity: u8,

    pub session_expiration: Option<SessionExpirationConfig>,

    /// Whether users can log in with their email address.
    pub login_with_email_allowed: bool,
}
