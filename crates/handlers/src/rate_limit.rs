// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{
    convert::Infallible, future::ready, net::IpAddr, num::NonZeroU32, sync::Arc, time::Duration,
};

use axum::extract::FromRequestParts;
use governor::{Quota, RateLimiter, clock::QuantaClock, state::keyed::DashMapStateStore};
use mas_config::RateLimitingConfig;
use mas_data_model::{User, UserEmailAuthentication};
use oauth2_types::requests::DEFAULT_DEVICE_AUTHORIZATION_INTERVAL;
use ulid::Ulid;

use crate::ClientIp;

#[derive(Debug, Clone, thiserror::Error)]
pub enum AccountRecoveryLimitedError {
    #[error("Too many account recovery requests for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many account recovery requests for e-mail {0}")]
    Email(String),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum PasswordCheckLimitedError {
    #[error("Too many password checks for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many password checks for user {0}")]
    User(Ulid),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum RegistrationLimitedError {
    #[error("Too many account registration requests for requester {0}")]
    Requester(RequesterFingerprint),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum EmailAuthenticationLimitedError {
    #[error("Too many email authentication requests for requester {0}")]
    Requester(RequesterFingerprint),

    #[error("Too many email authentication requests for authentication session {0}")]
    Authentication(Ulid),

    #[error("Too many email authentication requests for email {0}")]
    Email(String),
}

#[derive(Debug, Clone, thiserror::Error)]
pub enum DeviceCodeExchangeLimitedError {
    #[error("Too many unknown device codes presented by requester {0}")]
    Requester(RequesterFingerprint),
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
pub enum DeviceCodePollLimitedError {
    #[error("Device code grant {0} was polled faster than the advertised interval")]
    Grant(Ulid),
}

/// Key used to rate limit requests per requester
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RequesterFingerprint {
    ip: Option<IpAddr>,
}

impl std::fmt::Display for RequesterFingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ip) = self.ip {
            write!(f, "{ip}")
        } else {
            write!(f, "(NO CLIENT IP)")
        }
    }
}

impl RequesterFingerprint {
    /// An anonymous key with no IP address set. This should not be used in
    /// production, and we should warn users if we can't find their client IPs.
    pub const EMPTY: Self = Self { ip: None };

    /// Create a new anonymous key with the given IP address
    #[must_use]
    pub const fn new(ip: IpAddr) -> Self {
        Self { ip: Some(ip) }
    }
}

impl<S: Send + Sync> FromRequestParts<S> for RequesterFingerprint {
    type Rejection = Infallible;

    fn from_request_parts(
        parts: &mut axum::http::request::Parts,
        _state: &S,
    ) -> impl Future<Output = Result<Self, Self::Rejection>> + Send {
        let ip = parts.extensions.get::<ClientIp>().and_then(|ip| ip.0);

        let fingerprint = if let Some(ip) = ip {
            Self::new(ip)
        } else {
            // If we can't infer the IP address, we'll just use an empty fingerprint and
            // warn about it
            tracing::warn!(
                "Could not infer client IP address for an operation which rate-limits based on IP addresses"
            );
            Self::EMPTY
        };

        ready(Ok(fingerprint))
    }
}

/// Rate limiters for the different operations
#[derive(Debug, Clone)]
pub struct Limiter {
    inner: Arc<LimiterInner>,
}

type KeyedRateLimiter<K> = RateLimiter<K, DashMapStateStore<K>, QuantaClock>;

#[derive(Debug)]
struct LimiterInner {
    account_recovery_per_requester: KeyedRateLimiter<RequesterFingerprint>,
    account_recovery_per_email: KeyedRateLimiter<String>,
    password_check_for_requester: KeyedRateLimiter<RequesterFingerprint>,
    password_check_for_user: KeyedRateLimiter<Ulid>,
    registration_per_requester: KeyedRateLimiter<RequesterFingerprint>,
    email_authentication_per_requester: KeyedRateLimiter<RequesterFingerprint>,
    email_authentication_per_email: KeyedRateLimiter<String>,
    email_authentication_emails_per_session: KeyedRateLimiter<Ulid>,
    email_authentication_attempt_per_session: KeyedRateLimiter<Ulid>,
    device_code_exchange_per_requester: KeyedRateLimiter<RequesterFingerprint>,
    device_code_poll_per_grant: KeyedRateLimiter<Ulid>,
}

impl LimiterInner {
    fn new(config: &RateLimitingConfig) -> Option<Self> {
        Some(Self {
            account_recovery_per_requester: RateLimiter::keyed(
                config.account_recovery.per_ip.to_quota()?,
            ),
            account_recovery_per_email: RateLimiter::keyed(
                config.account_recovery.per_address.to_quota()?,
            ),
            password_check_for_requester: RateLimiter::keyed(config.login.per_ip.to_quota()?),
            password_check_for_user: RateLimiter::keyed(config.login.per_account.to_quota()?),
            registration_per_requester: RateLimiter::keyed(config.registration.to_quota()?),
            email_authentication_per_email: RateLimiter::keyed(
                config.email_authentication.per_address.to_quota()?,
            ),
            email_authentication_per_requester: RateLimiter::keyed(
                config.email_authentication.per_ip.to_quota()?,
            ),
            email_authentication_emails_per_session: RateLimiter::keyed(
                config.email_authentication.emails_per_session.to_quota()?,
            ),
            email_authentication_attempt_per_session: RateLimiter::keyed(
                config.email_authentication.attempt_per_session.to_quota()?,
            ),
            device_code_exchange_per_requester: RateLimiter::keyed(
                config.device_code_exchange.to_quota()?,
            ),
            // This one isn't configurable: it has to match the polling interval we
            // advertise in the device authorization response, else we would be telling
            // clients to slow down whilst they poll at exactly the rate we asked for
            device_code_poll_per_grant: RateLimiter::keyed(
                Quota::with_period(DEFAULT_DEVICE_AUTHORIZATION_INTERVAL.to_std().ok()?)?
                    .allow_burst(NonZeroU32::MIN),
            ),
        })
    }
}

impl Limiter {
    /// Creates a new `Limiter` based on a `RateLimitingConfig`.
    ///
    /// If the config is not valid, returns `None`.
    /// (This should not happen if the config was validated, though.)
    #[must_use]
    pub fn new(config: &RateLimitingConfig) -> Option<Self> {
        Some(Self {
            inner: Arc::new(LimiterInner::new(config)?),
        })
    }

    /// Start the rate limiter housekeeping task
    ///
    /// This task will periodically remove old entries from the rate limiters,
    /// to make sure we don't build up a huge number of entries in memory.
    pub fn start(&self) {
        // Spawn a task that will periodically clean the rate limiters
        let this = self.clone();
        tokio::spawn(async move {
            // Run the task every minute
            let mut interval = tokio::time::interval(Duration::from_mins(1));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

            loop {
                // Call the retain_recent method on each rate limiter
                this.inner.account_recovery_per_email.retain_recent();
                this.inner.account_recovery_per_requester.retain_recent();
                this.inner.password_check_for_requester.retain_recent();
                this.inner.password_check_for_user.retain_recent();
                this.inner.registration_per_requester.retain_recent();
                this.inner.email_authentication_per_email.retain_recent();
                this.inner
                    .email_authentication_per_requester
                    .retain_recent();
                this.inner
                    .email_authentication_emails_per_session
                    .retain_recent();
                this.inner
                    .email_authentication_attempt_per_session
                    .retain_recent();
                this.inner
                    .device_code_exchange_per_requester
                    .retain_recent();
                this.inner.device_code_poll_per_grant.retain_recent();

                interval.tick().await;
            }
        });
    }

    /// Check if an account recovery can be performed
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_account_recovery(
        &self,
        requester: RequesterFingerprint,
        email_address: &str,
    ) -> Result<(), AccountRecoveryLimitedError> {
        self.inner
            .account_recovery_per_requester
            .check_key(&requester)
            .map_err(|_| AccountRecoveryLimitedError::Requester(requester))?;

        // Convert to lowercase to prevent bypassing the limit by enumerating different
        // case variations.
        // A case-folding transformation may be more proper.
        let canonical_email = email_address.to_lowercase();
        self.inner
            .account_recovery_per_email
            .check_key(&canonical_email)
            .map_err(|_| AccountRecoveryLimitedError::Email(canonical_email))?;

        Ok(())
    }

    /// Check if a password check can be performed
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited
    pub fn check_password(
        &self,
        key: RequesterFingerprint,
        user: &User,
    ) -> Result<(), PasswordCheckLimitedError> {
        self.inner
            .password_check_for_requester
            .check_key(&key)
            .map_err(|_| PasswordCheckLimitedError::Requester(key))?;

        self.inner
            .password_check_for_user
            .check_key(&user.id)
            .map_err(|_| PasswordCheckLimitedError::User(user.id))?;

        Ok(())
    }

    /// Check if an account registration can be performed
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_registration(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), RegistrationLimitedError> {
        self.inner
            .registration_per_requester
            .check_key(&requester)
            .map_err(|_| RegistrationLimitedError::Requester(requester))?;

        Ok(())
    }

    /// Check if an email can be sent to the address for an email
    /// authentication session
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_email_authentication_email(
        &self,
        requester: RequesterFingerprint,
        email: &str,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        self.inner
            .email_authentication_per_requester
            .check_key(&requester)
            .map_err(|_| EmailAuthenticationLimitedError::Requester(requester))?;

        // Convert to lowercase to prevent bypassing the limit by enumerating different
        // case variations.
        // A case-folding transformation may be more proper.
        let canonical_email = email.to_lowercase();
        self.inner
            .email_authentication_per_email
            .check_key(&canonical_email)
            .map_err(|_| EmailAuthenticationLimitedError::Email(email.to_owned()))?;
        Ok(())
    }

    /// Check if an attempt can be done on an email authentication session
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_email_authentication_attempt(
        &self,
        authentication: &UserEmailAuthentication,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        self.inner
            .email_authentication_attempt_per_session
            .check_key(&authentication.id)
            .map_err(|_| EmailAuthenticationLimitedError::Authentication(authentication.id))
    }

    /// Check if a new authentication code can be sent for an email
    /// authentication session
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_email_authentication_send_code(
        &self,
        requester: RequesterFingerprint,
        authentication: &UserEmailAuthentication,
    ) -> Result<(), EmailAuthenticationLimitedError> {
        self.check_email_authentication_email(requester, &authentication.email)?;
        self.inner
            .email_authentication_emails_per_session
            .check_key(&authentication.id)
            .map_err(|_| EmailAuthenticationLimitedError::Authentication(authentication.id))
    }

    /// Check if an unknown device code can be presented to the token endpoint
    ///
    /// This bounds how fast a requester can enumerate device codes, as
    /// described in RFC 8628 section 5.2. It is only consulted for device
    /// codes which don't match a grant, so that clients polling with a valid
    /// device code are never held back by it.
    ///
    /// # Errors
    ///
    /// Returns an error if the operation is rate limited.
    pub fn check_device_code_exchange(
        &self,
        requester: RequesterFingerprint,
    ) -> Result<(), DeviceCodeExchangeLimitedError> {
        self.inner
            .device_code_exchange_per_requester
            .check_key(&requester)
            .map_err(|_| DeviceCodeExchangeLimitedError::Requester(requester))?;

        Ok(())
    }

    /// Check if a pending device code grant can be polled again
    ///
    /// This enforces the interval we advertise in the device authorization
    /// response: clients polling faster than that should be told to slow
    /// down, as described in RFC 8628 section 3.5.
    ///
    /// # Errors
    ///
    /// Returns an error if the grant was polled too soon.
    pub fn check_device_code_poll(&self, grant_id: Ulid) -> Result<(), DeviceCodePollLimitedError> {
        self.inner
            .device_code_poll_per_grant
            .check_key(&grant_id)
            .map_err(|_| DeviceCodePollLimitedError::Grant(grant_id))?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use mas_data_model::{Clock, UlidExt as _, User, clock::MockClock};
    use rand::SeedableRng;

    use super::*;

    #[test]
    fn test_password_check_limiter() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        // Let's create a lot of requesters to test account-level rate limiting
        let requesters: [_; 768] = (0..=255)
            .flat_map(|a| (0..3).map(move |b| RequesterFingerprint::new([a, a, b, b].into())))
            .collect::<Vec<_>>()
            .try_into()
            .unwrap();

        let alice = User {
            id: Ulid::from_datetime_with_rng(now, &mut rng),
            username: "alice".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: true,
        };

        let bob = User {
            id: Ulid::from_datetime_with_rng(now, &mut rng),
            username: "bob".to_owned(),
            sub: "123-456".to_owned(),
            created_at: now,
            locked_at: None,
            deactivated_at: None,
            can_request_admin: false,
            is_guest: true,
        };

        // Three times the same IP address should be allowed
        assert!(limiter.check_password(requesters[0], &alice).is_ok());
        assert!(limiter.check_password(requesters[0], &alice).is_ok());
        assert!(limiter.check_password(requesters[0], &alice).is_ok());

        // But the fourth time should be rejected
        assert!(limiter.check_password(requesters[0], &alice).is_err());
        // Using another user should also be rejected
        assert!(limiter.check_password(requesters[0], &bob).is_err());

        // Using a different IP address should be allowed, the account isn't locked yet
        assert!(limiter.check_password(requesters[1], &alice).is_ok());

        // At this point, we consumed 4 cells out of 1800 on alice, let's distribute the
        // requests with other IPs so that we get rate-limited on the account-level
        for requester in requesters.iter().skip(2).take(598) {
            assert!(limiter.check_password(*requester, &alice).is_ok());
            assert!(limiter.check_password(*requester, &alice).is_ok());
            assert!(limiter.check_password(*requester, &alice).is_ok());
            assert!(limiter.check_password(*requester, &alice).is_err());
        }

        // We now have consumed 4+598*3 = 1798 cells on the account, so we should be
        // rejected soon
        assert!(limiter.check_password(requesters[600], &alice).is_ok());
        assert!(limiter.check_password(requesters[601], &alice).is_ok());
        assert!(limiter.check_password(requesters[602], &alice).is_err());

        // The other account isn't rate-limited
        assert!(limiter.check_password(requesters[603], &bob).is_ok());
    }

    #[test]
    fn test_device_code_exchange_limiter() {
        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let alice = RequesterFingerprint::new([1, 2, 3, 4].into());
        let bob = RequesterFingerprint::new([4, 3, 2, 1].into());

        // The default burst allowance is 10 unknown device codes per requester
        for _ in 0..10 {
            assert!(limiter.check_device_code_exchange(alice).is_ok());
        }
        assert!(limiter.check_device_code_exchange(alice).is_err());

        // Another requester is unaffected
        assert!(limiter.check_device_code_exchange(bob).is_ok());
    }

    #[test]
    fn test_device_code_poll_limiter() {
        let now = MockClock::default().now();
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);

        let limiter = Limiter::new(&RateLimitingConfig::default()).unwrap();

        let first = Ulid::from_datetime_with_rng(now, &mut rng);
        let second = Ulid::from_datetime_with_rng(now, &mut rng);

        // A grant may be polled once per advertised interval, so a second poll
        // straight away is refused
        assert!(limiter.check_device_code_poll(first).is_ok());
        assert!(limiter.check_device_code_poll(first).is_err());

        // Another grant has its own allowance
        assert!(limiter.check_device_code_poll(second).is_ok());
        assert!(limiter.check_device_code_poll(second).is_err());
    }
}
