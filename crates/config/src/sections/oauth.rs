// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

const fn default_true() -> bool {
    true
}

#[allow(clippy::trivially_copy_pass_by_ref)]
const fn is_default_true(value: &bool) -> bool {
    *value == default_true()
}

/// Configuration section for OAuth 2.0 protocol options
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct OAuthConfig {
    /// Whether the Device Authorization Grant (RFC 8628) is enabled. Defaults
    /// to `true`.
    ///
    /// When disabled, the device authorization endpoint will reject requests,
    /// the discovery metadata will not advertise the device authorization
    /// endpoint, and dynamic client registrations requesting the
    /// `urn:ietf:params:oauth:grant-type:device_code` grant type will be
    /// rejected.
    #[serde(default = "default_true", skip_serializing_if = "is_default_true")]
    pub device_code_grant_enabled: bool,
}

impl Default for OAuthConfig {
    fn default() -> Self {
        Self {
            device_code_grant_enabled: default_true(),
        }
    }
}

impl OAuthConfig {
    /// Returns true if the configuration is the default one
    pub(crate) fn is_default(&self) -> bool {
        is_default_true(&self.device_code_grant_enabled)
    }
}

impl ConfigurationSection for OAuthConfig {
    const PATH: Option<&'static str> = Some("oauth");
}
