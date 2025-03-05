// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::ConfigurationSection;

fn default_true() -> bool {
    true
}

fn default_token_ttl() -> Duration {
    Duration::microseconds(5 * 60 * 1000 * 1000)
}

fn is_default_token_ttl(value: &Duration) -> bool {
    *value == default_token_ttl()
}

/// Configuration options for the inactive session expiration feature
#[serde_as]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct InactiveSessionExpirationConfig {
    /// Time after which an inactive session is automatically finished
    #[schemars(with = "u64", range(min = 600, max = 7_776_000))]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub ttl: Duration,

    /// Should compatibility sessions expire after inactivity
    #[serde(default = "default_true")]
    pub expire_compat_sessions: bool,

    /// Should OAuth 2.0 sessions expire after inactivity
    #[serde(default = "default_true")]
    pub expire_oauth_sessions: bool,

    /// Should user sessions expire after inactivity
    #[serde(default = "default_true")]
    pub expire_user_sessions: bool,
}

/// Configuration options for passkeys
#[serde_as]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct PasskeysConfig {
    /// Whether passkeys are enabled or not
    #[serde(default)]
    pub enabled: bool,
    /// Relying Party Identifier to use
    ///
    /// If not set, the host from `public_base` is used
    #[serde(default)]
    pub rpid: Option<String>,
    /// Additional allowed origins. `rpid` and `public_base` are already allowed
    #[serde(default)]
    pub allowed_origins: Option<Vec<String>>,
}

/// Configuration sections for experimental options
///
/// Do not change these options unless you know what you are doing.
#[serde_as]
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct ExperimentalConfig {
    /// Time-to-live of access tokens in seconds. Defaults to 5 minutes.
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_token_ttl",
        skip_serializing_if = "is_default_token_ttl"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub access_token_ttl: Duration,

    /// Time-to-live of compatibility access tokens in seconds. Defaults to 5
    /// minutes.
    #[schemars(with = "u64", range(min = 60, max = 86400))]
    #[serde(
        default = "default_token_ttl",
        skip_serializing_if = "is_default_token_ttl"
    )]
    #[serde_as(as = "serde_with::DurationSeconds<i64>")]
    pub compat_token_ttl: Duration,

    /// Experimetal feature to automatically expire inactive sessions
    ///
    /// Disabled by default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub inactive_session_expiration: Option<InactiveSessionExpirationConfig>,

    /// Experimental feature to show a plan management tab and iframe.
    /// This value is passed through "as is" to the client without any
    /// validation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_management_iframe_uri: Option<String>,

    /// Experimental passkey support
    ///
    /// Disabled by default
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passkeys: Option<PasskeysConfig>,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: default_token_ttl(),
            compat_token_ttl: default_token_ttl(),
            inactive_session_expiration: None,
            plan_management_iframe_uri: None,
            passkeys: None,
        }
    }
}

impl ExperimentalConfig {
    pub(crate) fn is_default(&self) -> bool {
        is_default_token_ttl(&self.access_token_ttl)
            && is_default_token_ttl(&self.compat_token_ttl)
            && self.inactive_session_expiration.is_none()
            && self.plan_management_iframe_uri.is_none()
            && self.passkeys.is_none()
    }
}

impl ConfigurationSection for ExperimentalConfig {
    const PATH: Option<&'static str> = Some("experimental");
}
