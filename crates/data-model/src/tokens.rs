// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Utc};
use crc::{CRC_32_ISO_HDLC, Crc};
use mas_iana::oauth::OAuthTokenTypeHint;
use rand::{Rng, RngCore, distributions::Alphanumeric};
use thiserror::Error;
use ulid::Ulid;

use crate::InvalidTransitionError;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum AccessTokenState {
    #[default]
    Valid,
    Revoked {
        revoked_at: DateTime<Utc>,
    },
}

impl AccessTokenState {
    fn revoke(self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Revoked { revoked_at }),
            Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the refresh token state is [`Valid`].
    ///
    /// [`Valid`]: AccessTokenState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns `true` if the refresh token state is [`Revoked`].
    ///
    /// [`Revoked`]: AccessTokenState::Revoked
    #[must_use]
    pub fn is_revoked(&self) -> bool {
        matches!(self, Self::Revoked { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessToken {
    pub id: Ulid,
    pub state: AccessTokenState,
    pub session_id: Ulid,
    pub access_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub first_used_at: Option<DateTime<Utc>>,
}

impl AccessToken {
    #[must_use]
    pub fn jti(&self) -> String {
        self.id.to_string()
    }

    /// Whether the access token is valid, i.e. not revoked and not expired
    ///
    /// # Parameters
    ///
    /// * `now` - The current time
    #[must_use]
    pub fn is_valid(&self, now: DateTime<Utc>) -> bool {
        self.state.is_valid() && !self.is_expired(now)
    }

    /// Whether the access token is expired
    ///
    /// Always returns `false` if the access token does not have an expiry time.
    ///
    /// # Parameters
    ///
    /// * `now` - The current time
    #[must_use]
    pub fn is_expired(&self, now: DateTime<Utc>) -> bool {
        match self.expires_at {
            Some(expires_at) => expires_at < now,
            None => false,
        }
    }

    /// Whether the access token was used at least once
    #[must_use]
    pub fn is_used(&self) -> bool {
        self.first_used_at.is_some()
    }

    /// Mark the access token as revoked
    ///
    /// # Parameters
    ///
    /// * `revoked_at` - The time at which the access token was revoked
    ///
    /// # Errors
    ///
    /// Returns an error if the access token is already revoked
    pub fn revoke(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.revoke(revoked_at)?;
        Ok(self)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum RefreshTokenState {
    #[default]
    Valid,
    Consumed {
        consumed_at: DateTime<Utc>,
        next_refresh_token_id: Option<Ulid>,
    },
    Revoked {
        revoked_at: DateTime<Utc>,
    },
}

impl RefreshTokenState {
    /// Consume the refresh token, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is revoked.
    fn consume(
        self,
        consumed_at: DateTime<Utc>,
        replaced_by: &RefreshToken,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid | Self::Consumed { .. } => Ok(Self::Consumed {
                consumed_at,
                next_refresh_token_id: Some(replaced_by.id),
            }),
            Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// Revoke the refresh token, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is already consumed or revoked.
    pub fn revoke(self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        match self {
            Self::Valid => Ok(Self::Revoked { revoked_at }),
            Self::Consumed { .. } | Self::Revoked { .. } => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the refresh token state is [`Valid`].
    ///
    /// [`Valid`]: RefreshTokenState::Valid
    #[must_use]
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    /// Returns the next refresh token ID, if any.
    #[must_use]
    pub fn next_refresh_token_id(&self) -> Option<Ulid> {
        match self {
            Self::Valid | Self::Revoked { .. } => None,
            Self::Consumed {
                next_refresh_token_id,
                ..
            } => *next_refresh_token_id,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshToken {
    pub id: Ulid,
    pub state: RefreshTokenState,
    pub refresh_token: String,
    pub session_id: Ulid,
    pub created_at: DateTime<Utc>,
    pub access_token_id: Option<Ulid>,
}

impl std::ops::Deref for RefreshToken {
    type Target = RefreshTokenState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl RefreshToken {
    #[must_use]
    pub fn jti(&self) -> String {
        self.id.to_string()
    }

    /// Consumes the refresh token and returns the consumed token.
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is revoked.
    pub fn consume(
        mut self,
        consumed_at: DateTime<Utc>,
        replaced_by: &Self,
    ) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.consume(consumed_at, replaced_by)?;
        Ok(self)
    }

    /// Revokes the refresh token and returns a new revoked token
    ///
    /// # Errors
    ///
    /// Returns an error if the refresh token is already revoked.
    pub fn revoke(mut self, revoked_at: DateTime<Utc>) -> Result<Self, InvalidTransitionError> {
        self.state = self.state.revoke(revoked_at)?;
        Ok(self)
    }
}

/// Type of token to generate or validate
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenType {
    /// An access token, used by Relying Parties to authenticate requests
    AccessToken,

    /// A refresh token, used by the refresh token grant
    RefreshToken,

    /// A legacy access token
    CompatAccessToken,

    /// A legacy refresh token
    CompatRefreshToken,
}

impl std::fmt::Display for TokenType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TokenType::AccessToken => write!(f, "access token"),
            TokenType::RefreshToken => write!(f, "refresh token"),
            TokenType::CompatAccessToken => write!(f, "compat access token"),
            TokenType::CompatRefreshToken => write!(f, "compat refresh token"),
        }
    }
}

impl TokenType {
    fn prefix(self) -> &'static str {
        match self {
            TokenType::AccessToken => "mat",
            TokenType::RefreshToken => "mar",
            TokenType::CompatAccessToken => "mct",
            TokenType::CompatRefreshToken => "mcr",
        }
    }

    fn match_prefix(prefix: &str) -> Option<Self> {
        match prefix {
            "mat" => Some(TokenType::AccessToken),
            "mar" => Some(TokenType::RefreshToken),
            "mct" | "syt" => Some(TokenType::CompatAccessToken),
            "mcr" | "syr" => Some(TokenType::CompatRefreshToken),
            _ => None,
        }
    }

    /// Generate a token for the given type
    pub fn generate(self, rng: &mut (impl RngCore + ?Sized)) -> String {
        let random_part: String = rng
            .sample_iter(&Alphanumeric)
            .take(30)
            .map(char::from)
            .collect();

        let base = format!("{prefix}_{random_part}", prefix = self.prefix());
        let crc = CRC.checksum(base.as_bytes());
        let crc = base62_encode(crc);
        format!("{base}_{crc}")
    }

    /// Check the format of a token and determine its type
    ///
    /// # Errors
    ///
    /// Returns an error if the token is not valid
    pub fn check(token: &str) -> Result<TokenType, TokenFormatError> {
        // these are legacy tokens imported from Synapse
        // we don't do any validation on them and continue as is
        if token.starts_with("syt_") || is_likely_synapse_macaroon(token) {
            return Ok(TokenType::CompatAccessToken);
        }
        if token.starts_with("syr_") {
            return Ok(TokenType::CompatRefreshToken);
        }

        let split: Vec<&str> = token.split('_').collect();
        let [prefix, random_part, crc]: [&str; 3] = split
            .try_into()
            .map_err(|_| TokenFormatError::InvalidFormat)?;

        if prefix.len() != 3 || random_part.len() != 30 || crc.len() != 6 {
            return Err(TokenFormatError::InvalidFormat);
        }

        let token_type =
            TokenType::match_prefix(prefix).ok_or_else(|| TokenFormatError::UnknownPrefix {
                prefix: prefix.to_owned(),
            })?;

        let base = format!("{prefix}_{random_part}", prefix = token_type.prefix());
        let expected_crc = CRC.checksum(base.as_bytes());
        let expected_crc = base62_encode(expected_crc);
        if crc != expected_crc {
            return Err(TokenFormatError::InvalidCrc {
                expected: expected_crc,
                got: crc.to_owned(),
            });
        }

        Ok(token_type)
    }
}

impl PartialEq<OAuthTokenTypeHint> for TokenType {
    fn eq(&self, other: &OAuthTokenTypeHint) -> bool {
        matches!(
            (self, other),
            (
                TokenType::AccessToken | TokenType::CompatAccessToken,
                OAuthTokenTypeHint::AccessToken
            ) | (
                TokenType::RefreshToken | TokenType::CompatRefreshToken,
                OAuthTokenTypeHint::RefreshToken
            )
        )
    }
}

/// Returns true if and only if a token looks like it may be a macaroon.
///
/// Macaroons are a standard for tokens that support attenuation.
/// Synapse used them for old sessions and for guest sessions.
///
/// We won't bother to decode them fully, but we can check to see if the first
/// constraint is the `location` constraint.
fn is_likely_synapse_macaroon(token: &str) -> bool {
    let Ok(decoded) = Base64UrlUnpadded::decode_vec(token) else {
        return false;
    };
    decoded.get(4..13) == Some(b"location ")
}

const NUM: [u8; 62] = *b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

fn base62_encode(mut num: u32) -> String {
    let mut res = String::with_capacity(6);
    while num > 0 {
        res.push(NUM[(num % 62) as usize] as char);
        num /= 62;
    }

    format!("{res:0>6}")
}

const CRC: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);

/// Invalid token
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TokenFormatError {
    /// Overall token format is invalid
    #[error("invalid token format")]
    InvalidFormat,

    /// Token used an unknown prefix
    #[error("unknown token prefix {prefix:?}")]
    UnknownPrefix {
        /// The prefix found in the token
        prefix: String,
    },

    /// The CRC checksum in the token is invalid
    #[error("invalid crc {got:?}, expected {expected:?}")]
    InvalidCrc {
        /// The CRC hash expected to be found in the token
        expected: String,
        /// The CRC found in the token
        got: String,
    },
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use rand::thread_rng;

    use super::*;

    #[test]
    fn test_prefix_match() {
        use TokenType::{AccessToken, CompatAccessToken, CompatRefreshToken, RefreshToken};
        assert_eq!(TokenType::match_prefix("syt"), Some(CompatAccessToken));
        assert_eq!(TokenType::match_prefix("syr"), Some(CompatRefreshToken));
        assert_eq!(TokenType::match_prefix("mct"), Some(CompatAccessToken));
        assert_eq!(TokenType::match_prefix("mcr"), Some(CompatRefreshToken));
        assert_eq!(TokenType::match_prefix("mat"), Some(AccessToken));
        assert_eq!(TokenType::match_prefix("mar"), Some(RefreshToken));
        assert_eq!(TokenType::match_prefix("matt"), None);
        assert_eq!(TokenType::match_prefix("marr"), None);
        assert_eq!(TokenType::match_prefix("ma"), None);
        assert_eq!(
            TokenType::match_prefix(TokenType::CompatAccessToken.prefix()),
            Some(TokenType::CompatAccessToken)
        );
        assert_eq!(
            TokenType::match_prefix(TokenType::CompatRefreshToken.prefix()),
            Some(TokenType::CompatRefreshToken)
        );
        assert_eq!(
            TokenType::match_prefix(TokenType::AccessToken.prefix()),
            Some(TokenType::AccessToken)
        );
        assert_eq!(
            TokenType::match_prefix(TokenType::RefreshToken.prefix()),
            Some(TokenType::RefreshToken)
        );
    }

    #[test]
    fn test_is_likely_synapse_macaroon() {
        // This is just the prefix of a Synapse macaroon, but it's enough to make the
        // sniffing work
        assert!(is_likely_synapse_macaroon(
            "MDAxYmxvY2F0aW9uIGxpYnJlcHVzaC5uZXQKMDAx"
        ));

        // This is a valid macaroon (even though Synapse did not generate this one)
        assert!(is_likely_synapse_macaroon(
            "MDAxY2xvY2F0aW9uIGh0dHA6Ly9teWJhbmsvCjAwMjZpZGVudGlmaWVyIHdlIHVzZWQgb3VyIHNlY3JldCBrZXkKMDAyZnNpZ25hdHVyZSDj2eApCFJsTAA5rhURQRXZf91ovyujebNCqvD2F9BVLwo"
        ));

        // None of these are macaroons
        assert!(!is_likely_synapse_macaroon(
            "eyJARTOhearotnaeisahtoarsnhiasra.arsohenaor.oarnsteao"
        ));
        assert!(!is_likely_synapse_macaroon("...."));
        assert!(!is_likely_synapse_macaroon("aaa"));
    }

    #[test]
    fn test_generate_and_check() {
        const COUNT: usize = 500; // Generate 500 of each token type

        #[allow(clippy::disallowed_methods)]
        let mut rng = thread_rng();

        for t in [
            TokenType::CompatAccessToken,
            TokenType::CompatRefreshToken,
            TokenType::AccessToken,
            TokenType::RefreshToken,
        ] {
            // Generate many tokens
            let tokens: HashSet<String> = (0..COUNT).map(|_| t.generate(&mut rng)).collect();

            // Check that they are all different
            assert_eq!(tokens.len(), COUNT, "All tokens are unique");

            // Check that they are all valid and detected as the right token type
            for token in tokens {
                assert_eq!(TokenType::check(&token).unwrap(), t);
            }
        }
    }
}
