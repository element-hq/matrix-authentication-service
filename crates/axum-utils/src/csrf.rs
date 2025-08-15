// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use mas_data_model::Clock;
use rand::{Rng, RngCore, distributions::Standard, prelude::Distribution as _};
use serde::{Deserialize, Serialize};
use serde_with::{TimestampSeconds, serde_as};
use thiserror::Error;

use crate::cookies::{CookieDecodeError, CookieJar};

/// Failed to validate CSRF token
#[derive(Debug, Error)]
pub enum CsrfError {
    /// The token in the form did not match the token in the cookie
    #[error("CSRF token mismatch")]
    Mismatch,

    /// The token in the form did not match the token in the cookie
    #[error("Missing CSRF cookie")]
    Missing,

    /// Failed to decode the token
    #[error("could not decode CSRF cookie")]
    DecodeCookie(#[from] CookieDecodeError),

    /// The token expired
    #[error("CSRF token expired")]
    Expired,

    /// Failed to decode the token
    #[error("could not decode CSRF token")]
    Decode(#[from] base64ct::Error),
}

/// A CSRF token
#[serde_as]
#[derive(Serialize, Deserialize, Debug)]
pub struct CsrfToken {
    #[serde_as(as = "TimestampSeconds<i64>")]
    expiration: DateTime<Utc>,
    token: [u8; 32],
}

impl CsrfToken {
    /// Create a new token from a defined value valid for a specified duration
    fn new(token: [u8; 32], now: DateTime<Utc>, ttl: Duration) -> Self {
        let expiration = now + ttl;
        Self { expiration, token }
    }

    /// Generate a new random token valid for a specified duration
    fn generate(now: DateTime<Utc>, mut rng: impl Rng, ttl: Duration) -> Self {
        let token = Standard.sample(&mut rng);
        Self::new(token, now, ttl)
    }

    /// Generate a new token with the same value but an up to date expiration
    fn refresh(self, now: DateTime<Utc>, ttl: Duration) -> Self {
        Self::new(self.token, now, ttl)
    }

    /// Get the value to include in HTML forms
    #[must_use]
    pub fn form_value(&self) -> String {
        Base64UrlUnpadded::encode_string(&self.token[..])
    }

    /// Verifies that the value got from an HTML form matches this token
    ///
    /// # Errors
    ///
    /// Returns an error if the value in the form does not match this token
    pub fn verify_form_value(&self, form_value: &str) -> Result<(), CsrfError> {
        let form_value = Base64UrlUnpadded::decode_vec(form_value)?;
        if self.token[..] == form_value {
            Ok(())
        } else {
            Err(CsrfError::Mismatch)
        }
    }

    fn verify_expiration(self, now: DateTime<Utc>) -> Result<Self, CsrfError> {
        if now < self.expiration {
            Ok(self)
        } else {
            Err(CsrfError::Expired)
        }
    }
}

// A CSRF-protected form
#[derive(Deserialize)]
pub struct ProtectedForm<T> {
    csrf: String,

    #[serde(flatten)]
    inner: T,
}

pub trait CsrfExt {
    /// Get the current CSRF token out of the cookie jar, generating a new one
    /// if necessary
    fn csrf_token<C, R>(self, clock: &C, rng: R) -> (CsrfToken, Self)
    where
        R: RngCore,
        C: Clock;

    /// Verify that the given CSRF-protected form is valid, returning the inner
    /// value
    ///
    /// # Errors
    ///
    /// Returns an error if the CSRF cookie is missing or if the value in the
    /// form is invalid
    fn verify_form<C, T>(&self, clock: &C, form: ProtectedForm<T>) -> Result<T, CsrfError>
    where
        C: Clock;
}

impl CsrfExt for CookieJar {
    fn csrf_token<C, R>(self, clock: &C, rng: R) -> (CsrfToken, Self)
    where
        R: RngCore,
        C: Clock,
    {
        let now = clock.now();
        let maybe_token = match self.load::<CsrfToken>("csrf") {
            Ok(Some(token)) => {
                let token = token.verify_expiration(now);

                // If the token is expired, just ignore it
                token.ok()
            }
            Ok(None) => None,
            Err(e) => {
                tracing::warn!("Failed to decode CSRF cookie: {}", e);
                None
            }
        };

        let token = maybe_token.map_or_else(
            || CsrfToken::generate(now, rng, Duration::try_hours(1).unwrap()),
            |token| token.refresh(now, Duration::try_hours(1).unwrap()),
        );

        let jar = self.save("csrf", &token, false);
        (token, jar)
    }

    fn verify_form<C, T>(&self, clock: &C, form: ProtectedForm<T>) -> Result<T, CsrfError>
    where
        C: Clock,
    {
        let token: CsrfToken = self.load("csrf")?.ok_or(CsrfError::Missing)?;
        let token = token.verify_expiration(clock.now())?;
        token.verify_form_value(&form.csrf)?;
        Ok(form.inner)
    }
}
