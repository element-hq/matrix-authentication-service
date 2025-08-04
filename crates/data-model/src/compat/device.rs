// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use oauth2_types::scope::ScopeToken;
use rand::{
    RngCore,
    distributions::{Alphanumeric, DistString},
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

static GENERATED_DEVICE_ID_LENGTH: usize = 10;
static UNSTABLE_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:org.matrix.msc2967.client:device:";
static STABLE_DEVICE_SCOPE_PREFIX: &str = "urn:matrix:client:device:";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Device {
    id: String,
}

#[derive(Debug, Error)]
pub enum ToScopeTokenError {
    #[error("Device ID contains characters that can't be encoded in a scope")]
    InvalidCharacters,
}

impl Device {
    /// Get the corresponding stable and unstable [`ScopeToken`] for that device
    ///
    /// # Errors
    ///
    /// Returns an error if the device ID contains characters that can't be
    /// encoded in a scope
    pub fn to_scope_token(&self) -> Result<[ScopeToken; 2], ToScopeTokenError> {
        Ok([
            format!("{STABLE_DEVICE_SCOPE_PREFIX}{}", self.id)
                .parse()
                .map_err(|_| ToScopeTokenError::InvalidCharacters)?,
            format!("{UNSTABLE_DEVICE_SCOPE_PREFIX}{}", self.id)
                .parse()
                .map_err(|_| ToScopeTokenError::InvalidCharacters)?,
        ])
    }

    /// Get the corresponding [`Device`] from a [`ScopeToken`]
    ///
    /// Returns `None` if the [`ScopeToken`] is not a device scope
    #[must_use]
    pub fn from_scope_token(token: &ScopeToken) -> Option<Self> {
        let stable = token.as_str().strip_prefix(STABLE_DEVICE_SCOPE_PREFIX);
        let unstable = token.as_str().strip_prefix(UNSTABLE_DEVICE_SCOPE_PREFIX);
        let id = stable.or(unstable)?;
        Some(Device::from(id.to_owned()))
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

impl From<String> for Device {
    fn from(id: String) -> Self {
        Self { id }
    }
}

impl From<Device> for String {
    fn from(device: Device) -> Self {
        device.id
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
        let device = Device::from("AABBCCDDEE".to_owned());
        let [stable_scope_token, unstable_scope_token] = device.to_scope_token().unwrap();
        assert_eq!(
            stable_scope_token.as_str(),
            "urn:matrix:client:device:AABBCCDDEE"
        );
        assert_eq!(
            unstable_scope_token.as_str(),
            "urn:matrix:org.matrix.msc2967.client:device:AABBCCDDEE"
        );
        assert_eq!(
            Device::from_scope_token(&unstable_scope_token).as_ref(),
            Some(&device)
        );
        assert_eq!(
            Device::from_scope_token(&stable_scope_token).as_ref(),
            Some(&device)
        );
        assert_eq!(Device::from_scope_token(&OPENID), None);
    }
}
