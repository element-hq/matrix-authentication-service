// Copyright (C) 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use oauth2_types::scope::ScopeToken;
use rand::{
    distributions::{Alphanumeric, DistString},
    RngCore,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

static GENERATED_DEVICE_ID_LENGTH: usize = 10;
static DEVICE_SCOPE_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Device {
    id: String,
}

#[derive(Debug, Error)]
pub enum InvalidDeviceID {
    #[error("Device ID contains invalid characters")]
    InvalidCharacters,
}

impl Device {
    /// Get the corresponding [`ScopeToken`] for that device
    #[must_use]
    pub fn to_scope_token(&self) -> ScopeToken {
        // SAFETY: the inner id should only have valid scope characters
        let Ok(scope_token) = format!("{DEVICE_SCOPE_PREFIX}{}", self.id).parse() else {
            unreachable!()
        };

        scope_token
    }

    /// Get the corresponding [`Device`] from a [`ScopeToken`]
    ///
    /// Returns `None` if the [`ScopeToken`] is not a device scope
    #[must_use]
    pub fn from_scope_token(token: &ScopeToken) -> Option<Self> {
        let id = token.as_str().strip_prefix(DEVICE_SCOPE_PREFIX)?;
        // XXX: we might be silently ignoring errors here, but it's probably fine?
        Device::try_from(id.to_owned()).ok()
    }

    /// Generate a random device ID
    pub fn generate<R: RngCore + ?Sized>(rng: &mut R) -> Self {
        let id: String = Alphanumeric.sample_string(rng, GENERATED_DEVICE_ID_LENGTH);
        Self { id }
    }

    /// Get the inner device ID as [`&str`]
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.id
    }
}

const fn valid_device_chars(c: char) -> bool {
    // This matches the regex in the policy
    c.is_ascii_alphanumeric()
        || c == '.'
        || c == '_'
        || c == '~'
        || c == '!'
        || c == '$'
        || c == '&'
        || c == '\''
        || c == '('
        || c == ')'
        || c == '*'
        || c == '+'
        || c == ','
        || c == ';'
        || c == '='
        || c == ':'
        || c == '@'
        || c == '/'
        || c == '-'
}

impl TryFrom<String> for Device {
    type Error = InvalidDeviceID;

    /// Create a [`Device`] out of an ID, validating the ID has the right shape
    fn try_from(id: String) -> Result<Self, Self::Error> {
        if !id.chars().all(valid_device_chars) {
            return Err(InvalidDeviceID::InvalidCharacters);
        }

        Ok(Self { id })
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.id)
    }
}

#[cfg(test)]
mod test {
    use oauth2_types::scope::OPENID;

    use crate::Device;

    #[test]
    fn test_device_id_to_from_scope_token() {
        let device = Device::try_from("AABBCCDDEE".to_owned()).unwrap();
        let scope_token = device.to_scope_token();
        assert_eq!(
            scope_token.as_str(),
            "urn:matrix:org.matrix.msc2967.client:device:AABBCCDDEE"
        );
        assert_eq!(Device::from_scope_token(&scope_token), Some(device));
        assert_eq!(Device::from_scope_token(&OPENID), None);
    }
}
