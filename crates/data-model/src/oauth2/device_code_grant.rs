// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use chrono::{DateTime, Utc};
use oauth2_types::scope::Scope;
use rand::{Rng, RngCore};
use serde::Serialize;
use ulid::Ulid;

use crate::{BrowserSession, InvalidTransitionError, Session};

/// The [Crockford Base32] symbol set, used for device grant user codes.
///
/// `I`, `L` and `O` are excluded because they are easily confused with `1` and
/// `0`; `U` is excluded to reduce the chance of a code spelling something
/// obscene.
///
/// [Crockford Base32]: https://www.crockford.com/base32.html
const USER_CODE_ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/// The number of symbols in a generated user code.
///
/// The alphabet has 32 symbols, so each one carries exactly 5 bits: a
/// six-symbol code is 30 bits of entropy.
const USER_CODE_LENGTH: usize = 6;

/// Generate a random user code for a device code grant.
pub fn generate_user_code<R: RngCore + ?Sized>(rng: &mut R) -> String {
    (0..USER_CODE_LENGTH)
        .map(|_| char::from(USER_CODE_ALPHABET[rng.gen_range(0..USER_CODE_ALPHABET.len())]))
        .collect()
}

/// Apply the [Crockford Base32] decode mapping to a user code as typed by a
/// user.
///
/// On top of uppercasing, this folds `O` onto `0` and `I` and `L` onto `1`,
/// repairing a user who read a `0` as an `O` or a `1` as an `I`.
///
/// `U` is not in the alphabet but has no mapping defined for it either, so it
/// is passed through unchanged.
///
/// Crockford ignores hyphens when decoding, but we issue none, so nothing is
/// stripped here: hyphens, whitespace and punctuation all just fail to match.
///
/// The mapping is lossy, so a caller which looks up both the code as the user
/// typed and its normalized form should try the code as typed first: a legacy
/// code containing `I`, `L` or `O` is otherwise shadowed by any live grant at
/// the code it folds onto. See the lookup in the device link handler.
///
/// [Crockford Base32]: https://www.crockford.com/base32.html
#[must_use]
pub fn normalize_user_code(code: &str) -> String {
    code.to_uppercase()
        .chars()
        .map(|c| match c {
            'O' => '0',
            'I' | 'L' => '1',
            c => c,
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum DeviceCodeGrantState {
    /// The device code grant is pending.
    Pending,

    /// The device code grant has been fulfilled by a user.
    Fulfilled {
        /// The browser session which was used to complete this device code
        /// grant.
        browser_session_id: Ulid,

        /// The time at which this device code grant was fulfilled.
        fulfilled_at: DateTime<Utc>,
    },

    /// The device code grant has been rejected by a user.
    Rejected {
        /// The browser session which was used to reject this device code grant.
        browser_session_id: Ulid,

        /// The time at which this device code grant was rejected.
        rejected_at: DateTime<Utc>,
    },

    /// The device code grant was exchanged for an access token.
    Exchanged {
        /// The browser session which was used to exchange this device code
        /// grant.
        browser_session_id: Ulid,

        /// The time at which the device code grant was fulfilled.
        fulfilled_at: DateTime<Utc>,

        /// The time at which this device code grant was exchanged.
        exchanged_at: DateTime<Utc>,

        /// The OAuth 2.0 session ID which was created by this device code
        /// grant.
        session_id: Ulid,
    },
}

impl DeviceCodeGrantState {
    /// Mark this device code grant as fulfilled, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn fulfill(
        self,
        browser_session: &BrowserSession,
        fulfilled_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Pending => Ok(DeviceCodeGrantState::Fulfilled {
                browser_session_id: browser_session.id,
                fulfilled_at,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Mark this device code grant as rejected, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn reject(
        self,
        browser_session: &BrowserSession,
        rejected_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Pending => Ok(DeviceCodeGrantState::Rejected {
                browser_session_id: browser_session.id,
                rejected_at,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Mark this device code grant as exchanged, returning a new state.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Fulfilled`]
    /// state.
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    pub fn exchange(
        self,
        session: &Session,
        exchanged_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        match self {
            DeviceCodeGrantState::Fulfilled {
                fulfilled_at,
                browser_session_id,
                ..
            } => Ok(DeviceCodeGrantState::Exchanged {
                browser_session_id,
                fulfilled_at,
                exchanged_at,
                session_id: session.id,
            }),
            _ => Err(InvalidTransitionError),
        }
    }

    /// Returns `true` if the device code grant state is [`Pending`].
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    #[must_use]
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending)
    }

    /// Returns `true` if the device code grant state is [`Fulfilled`].
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    #[must_use]
    pub fn is_fulfilled(&self) -> bool {
        matches!(self, Self::Fulfilled { .. })
    }

    /// Returns `true` if the device code grant state is [`Rejected`].
    ///
    /// [`Rejected`]: DeviceCodeGrantState::Rejected
    #[must_use]
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// Returns `true` if the device code grant state is [`Exchanged`].
    ///
    /// [`Exchanged`]: DeviceCodeGrantState::Exchanged
    #[must_use]
    pub fn is_exchanged(&self) -> bool {
        matches!(self, Self::Exchanged { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceCodeGrant {
    pub id: Ulid,
    #[serde(flatten)]
    pub state: DeviceCodeGrantState,

    /// The client ID which requested this device code grant.
    pub client_id: Ulid,

    /// The scope which was requested by this device code grant.
    pub scope: Scope,

    /// The user code which was generated for this device code grant.
    /// This is the one that the user will enter into their client.
    pub user_code: String,

    /// The device code which was generated for this device code grant.
    /// This is the one that the client will use to poll for an access token.
    pub device_code: String,

    /// The time at which this device code grant was created.
    pub created_at: DateTime<Utc>,

    /// The time at which this device code grant will expire.
    pub expires_at: DateTime<Utc>,

    /// The IP address of the client which requested this device code grant.
    pub ip_address: Option<IpAddr>,

    /// The user agent used to request this device code grant.
    pub user_agent: Option<String>,

    /// The login hint within the request
    pub login_hint: Option<String>,

    /// The locale detected from the browser which fulfilled this device code
    /// grant. Used to render a human-readable device name. [`None`] until the
    /// grant is fulfilled.
    pub locale: Option<String>,
}

impl std::ops::Deref for DeviceCodeGrant {
    type Target = DeviceCodeGrantState;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl DeviceCodeGrant {
    /// Mark this device code grant as fulfilled, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    /// state.
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn fulfill(
        self,
        browser_session: &BrowserSession,
        locale: Option<String>,
        fulfilled_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.fulfill(browser_session, fulfilled_at)?,
            locale,
            ..self
        })
    }

    /// Mark this device code grant as rejected, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Pending`]
    ///
    /// [`Pending`]: DeviceCodeGrantState::Pending
    pub fn reject(
        self,
        browser_session: &BrowserSession,
        rejected_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.reject(browser_session, rejected_at)?,
            ..self
        })
    }

    /// Mark this device code grant as exchanged, returning the updated grant.
    ///
    /// # Errors
    ///
    /// Returns an error if the device code grant is not in the [`Fulfilled`]
    /// state.
    ///
    /// [`Fulfilled`]: DeviceCodeGrantState::Fulfilled
    pub fn exchange(
        self,
        session: &Session,
        exchanged_at: DateTime<Utc>,
    ) -> Result<Self, InvalidTransitionError> {
        Ok(Self {
            state: self.state.exchange(session, exchanged_at)?,
            ..self
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    #[test]
    fn test_generate_user_code_uses_the_crockford_alphabet() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for _ in 0..1000 {
            let code = generate_user_code(&mut rng);

            assert_eq!(code.chars().count(), USER_CODE_LENGTH);
            for c in code.chars() {
                assert!(
                    USER_CODE_ALPHABET.contains(&u8::try_from(c).unwrap()),
                    "generated code {code:?} has {c:?}, which is not in the alphabet"
                );
                // The whole point of the alphabet: these are the characters
                // which get confused for `0` and `1`, plus the one Crockford
                // drops to avoid obscenities.
                assert!(
                    !matches!(c, 'I' | 'L' | 'O' | 'U'),
                    "generated code {code:?} has an excluded character {c:?}"
                );
            }
        }
    }

    /// Normalising a freshly generated code must be a no-op, otherwise the
    /// codes we hand out would not match themselves when typed back in
    /// correctly. This holds by construction — the alphabet is uppercase and
    /// contains none of `I`, `L` or `O` — and this test is what keeps
    /// [`generate_user_code`] and [`normalize_user_code`] in step if either is
    /// edited later.
    #[test]
    fn test_generated_user_codes_normalize_to_themselves() {
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        for _ in 0..1000 {
            let code = generate_user_code(&mut rng);
            assert_eq!(normalize_user_code(&code), code);
        }
    }

    #[test]
    fn test_normalize_user_code_applies_the_decode_mapping() {
        assert_eq!(normalize_user_code("01ILO"), "01110");
        assert_eq!(normalize_user_code("hello"), "HE110");
        // Crockford defines no mapping for these, so both members of each pair
        // stay ambiguous and must be left as they are.
        assert_eq!(normalize_user_code("8bs5"), "8BS5");
        assert_eq!(normalize_user_code("2z6g9q"), "2Z6G9Q");
        // `U` is not in the alphabet but has no mapping either.
        assert_eq!(normalize_user_code("u"), "U");
    }

    /// We never put separators into the codes we hand out, so there is nothing
    /// for a user to optionally include and nothing to strip. Anything which
    /// isn't part of the code is passed through, and will simply fail to match.
    #[test]
    fn test_normalize_user_code_does_not_strip_separators() {
        assert_eq!(normalize_user_code("abc-def"), "ABC-DEF");
        assert_eq!(normalize_user_code(" abcdef "), " ABCDEF ");
        assert_eq!(normalize_user_code("---"), "---");
    }

    #[test]
    fn test_normalize_user_code_is_idempotent() {
        for input in ["01ILO", "hello", "abc-def", " 8b s5 ", "xil9oz", ""] {
            let once = normalize_user_code(input);
            assert_eq!(normalize_user_code(&once), once);
        }
    }
}
