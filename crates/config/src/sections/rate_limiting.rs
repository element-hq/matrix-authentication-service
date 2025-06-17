// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{num::NonZeroU32, time::Duration};

use governor::Quota;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error as _};

use crate::ConfigurationSection;

/// Configuration related to sending emails
#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RateLimitingConfig {
    /// Account Recovery-specific rate limits
    #[serde(default)]
    pub account_recovery: AccountRecoveryRateLimitingConfig,

    /// Login-specific rate limits
    #[serde(default)]
    pub login: LoginRateLimitingConfig,

    /// Controls how many registrations attempts are permitted
    /// based on source address.
    #[serde(default = "default_registration")]
    pub registration: RateLimiterConfiguration,

    /// Email authentication-specific rate limits
    #[serde(default)]
    pub email_authentication: EmailauthenticationRateLimitingConfig,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct LoginRateLimitingConfig {
    /// Controls how many login attempts are permitted
    /// based on source IP address.
    /// This can protect against brute force login attempts.
    ///
    /// Note: this limit also applies to password checks when a user attempts to
    /// change their own password.
    #[serde(default = "default_login_per_ip")]
    pub per_ip: RateLimiterConfiguration,

    /// Controls how many login attempts are permitted
    /// based on the account that is being attempted to be logged into.
    /// This can protect against a distributed brute force attack
    /// but should be set high enough to prevent someone's account being
    /// casually locked out.
    ///
    /// Note: this limit also applies to password checks when a user attempts to
    /// change their own password.
    #[serde(default = "default_login_per_account")]
    pub per_account: RateLimiterConfiguration,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct AccountRecoveryRateLimitingConfig {
    /// Controls how many account recovery attempts are permitted
    /// based on source IP address.
    /// This can protect against causing e-mail spam to many targets.
    ///
    /// Note: this limit also applies to re-sends.
    #[serde(default = "default_account_recovery_per_ip")]
    pub per_ip: RateLimiterConfiguration,

    /// Controls how many account recovery attempts are permitted
    /// based on the e-mail address entered into the recovery form.
    /// This can protect against causing e-mail spam to one target.
    ///
    /// Note: this limit also applies to re-sends.
    #[serde(default = "default_account_recovery_per_address")]
    pub per_address: RateLimiterConfiguration,
}

#[derive(Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct EmailauthenticationRateLimitingConfig {
    /// Controls how many email authentication attempts are permitted
    /// based on the source IP address.
    /// This can protect against causing e-mail spam to many targets.
    #[serde(default = "default_email_authentication_per_ip")]
    pub per_ip: RateLimiterConfiguration,

    /// Controls how many email authentication attempts are permitted
    /// based on the e-mail address entered into the authentication form.
    /// This can protect against causing e-mail spam to one target.
    ///
    /// Note: this limit also applies to re-sends.
    #[serde(default = "default_email_authentication_per_address")]
    pub per_address: RateLimiterConfiguration,

    /// Controls how many authentication emails are permitted to be sent per
    /// authentication session. This ensures not too many authentication codes
    /// are created for the same authentication session.
    #[serde(default = "default_email_authentication_emails_per_session")]
    pub emails_per_session: RateLimiterConfiguration,

    /// Controls how many code authentication attempts are permitted per
    /// authentication session. This can protect against brute-forcing the
    /// code.
    #[serde(default = "default_email_authentication_attempt_per_session")]
    pub attempt_per_session: RateLimiterConfiguration,
}

#[derive(Copy, Clone, Debug, Serialize, Deserialize, JsonSchema, PartialEq)]
pub struct RateLimiterConfiguration {
    /// A one-off burst of actions that the user can perform
    /// in one go without waiting.
    pub burst: NonZeroU32,
    /// How quickly the allowance replenishes, in number of actions per second.
    /// Can be fractional to replenish slower.
    pub per_second: f64,
}

impl ConfigurationSection for RateLimitingConfig {
    const PATH: Option<&'static str> = Some("rate_limiting");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());

        let error_on_field = |mut error: figment::error::Error, field: &'static str| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned(), field.to_owned()];
            error
        };

        let error_on_nested_field =
            |mut error: figment::error::Error, container: &'static str, field: &'static str| {
                error.metadata = metadata.cloned();
                error.profile = Some(figment::Profile::Default);
                error.path = vec![
                    Self::PATH.unwrap().to_owned(),
                    container.to_owned(),
                    field.to_owned(),
                ];
                error
            };

        // Check one limiter's configuration for errors
        let error_on_limiter =
            |limiter: &RateLimiterConfiguration| -> Option<figment::error::Error> {
                let recip = limiter.per_second.recip();
                // period must be at least 1 nanosecond according to the governor library
                if recip < 1.0e-9 || !recip.is_finite() {
                    return Some(figment::error::Error::custom(
                        "`per_second` must be a number that is more than zero and less than 1_000_000_000 (1e9)",
                    ));
                }

                None
            };

        if let Some(error) = error_on_limiter(&self.account_recovery.per_ip) {
            return Err(error_on_nested_field(error, "account_recovery", "per_ip"));
        }
        if let Some(error) = error_on_limiter(&self.account_recovery.per_address) {
            return Err(error_on_nested_field(
                error,
                "account_recovery",
                "per_address",
            ));
        }

        if let Some(error) = error_on_limiter(&self.registration) {
            return Err(error_on_field(error, "registration"));
        }

        if let Some(error) = error_on_limiter(&self.login.per_ip) {
            return Err(error_on_nested_field(error, "login", "per_ip"));
        }
        if let Some(error) = error_on_limiter(&self.login.per_account) {
            return Err(error_on_nested_field(error, "login", "per_account"));
        }

        Ok(())
    }
}

impl RateLimitingConfig {
    pub(crate) fn is_default(config: &RateLimitingConfig) -> bool {
        config == &RateLimitingConfig::default()
    }
}

impl RateLimiterConfiguration {
    pub fn to_quota(self) -> Option<Quota> {
        let reciprocal = self.per_second.recip();
        if !reciprocal.is_finite() {
            return None;
        }
        Some(Quota::with_period(Duration::from_secs_f64(reciprocal))?.allow_burst(self.burst))
    }
}

fn default_login_per_ip() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(3).unwrap(),
        per_second: 3.0 / 60.0,
    }
}

fn default_login_per_account() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(1800).unwrap(),
        per_second: 1800.0 / 3600.0,
    }
}

fn default_registration() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(3).unwrap(),
        per_second: 3.0 / 3600.0,
    }
}

fn default_account_recovery_per_ip() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(3).unwrap(),
        per_second: 3.0 / 3600.0,
    }
}

fn default_account_recovery_per_address() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(3).unwrap(),
        per_second: 1.0 / 3600.0,
    }
}

fn default_email_authentication_per_ip() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(5).unwrap(),
        per_second: 1.0 / 60.0,
    }
}

fn default_email_authentication_per_address() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(3).unwrap(),
        per_second: 1.0 / 3600.0,
    }
}

fn default_email_authentication_emails_per_session() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(2).unwrap(),
        per_second: 1.0 / 300.0,
    }
}

fn default_email_authentication_attempt_per_session() -> RateLimiterConfiguration {
    RateLimiterConfiguration {
        burst: NonZeroU32::new(10).unwrap(),
        per_second: 1.0 / 60.0,
    }
}

impl Default for RateLimitingConfig {
    fn default() -> Self {
        RateLimitingConfig {
            login: LoginRateLimitingConfig::default(),
            registration: default_registration(),
            account_recovery: AccountRecoveryRateLimitingConfig::default(),
            email_authentication: EmailauthenticationRateLimitingConfig::default(),
        }
    }
}

impl Default for LoginRateLimitingConfig {
    fn default() -> Self {
        LoginRateLimitingConfig {
            per_ip: default_login_per_ip(),
            per_account: default_login_per_account(),
        }
    }
}

impl Default for AccountRecoveryRateLimitingConfig {
    fn default() -> Self {
        AccountRecoveryRateLimitingConfig {
            per_ip: default_account_recovery_per_ip(),
            per_address: default_account_recovery_per_address(),
        }
    }
}

impl Default for EmailauthenticationRateLimitingConfig {
    fn default() -> Self {
        EmailauthenticationRateLimitingConfig {
            per_ip: default_email_authentication_per_ip(),
            per_address: default_email_authentication_per_address(),
            emails_per_session: default_email_authentication_emails_per_session(),
            attempt_per_session: default_email_authentication_attempt_per_session(),
        }
    }
}
