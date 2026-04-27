// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroU64;

use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use crate::ConfigurationSection;

fn default_true() -> bool {
    true
}

fn default_false() -> bool {
    false
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

    /// Experimental feature to limit the number of application sessions per
    /// user.
    ///
    /// Disabled by default.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_limit: Option<SessionLimitConfig>,
}

impl Default for ExperimentalConfig {
    fn default() -> Self {
        Self {
            access_token_ttl: default_token_ttl(),
            compat_token_ttl: default_token_ttl(),
            inactive_session_expiration: None,
            plan_management_iframe_uri: None,
            session_limit: None,
        }
    }
}

impl ExperimentalConfig {
    pub(crate) fn is_default(&self) -> bool {
        is_default_token_ttl(&self.access_token_ttl)
            && is_default_token_ttl(&self.compat_token_ttl)
            && self.inactive_session_expiration.is_none()
            && self.plan_management_iframe_uri.is_none()
            && self.session_limit.is_none()
    }
}

impl ConfigurationSection for ExperimentalConfig {
    const PATH: Option<&'static str> = Some("experimental");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        if let Some(session_limit) = &self.session_limit {
            session_limit.validate().map_err(|mut err| {
                // Save the error location information in the error
                err.metadata = figment.find_metadata(Self::PATH.unwrap()).cloned();
                err.profile = Some(figment::Profile::Default);
                err.path.insert(0, Self::PATH.unwrap().to_owned());
                err.path.insert(1, "session_limit".to_owned());
                err
            })?;
        }
        Ok(())
    }
}

/// Configuration options for the session limit feature
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SessionLimitConfig {
    /// Upon login in interactive contexts (like OAuth 2.0 sessions, or
    /// `m.login.sso` compability login flow), if the soft limit is reached,
    /// it will display a policy violation screen (web UI) to remove
    /// sessions before creating the new session.
    ///
    /// This is not enforced in non-interactive contexts (like
    /// `m.login.password` login with the compability API) as there is no
    /// opportunity for us to show some UI for people remove some sessions.
    /// See [`hard_limit`] for enforcement on that side.
    ///
    /// [`hard_limit`]: Self::hard_limit
    pub soft_limit: NonZeroU64,
    /// Upon login, when `dangerous_hard_limit_eviction: false`, will refuse the
    /// new login (policy violation error), otherwise, see
    /// [`dangerous_hard_limit_eviction`].
    ///
    /// The hard limit is enforced in all contexts
    /// (interactive/non-interactive).
    ///
    /// [`dangerous_hard_limit_eviction`]: Self::dangerous_hard_limit_eviction
    pub hard_limit: NonZeroU64,
    /// Whether we should automatically choose the least recently used devices
    /// to remove when the [`Self::hard_limit`] is reached; in order to
    /// allow the new login to continue.
    ///
    /// Disabled by default
    ///
    /// WARNING: Removing sessions is a potentially damaging operation. Any
    /// end-to-end encrypted history on the device will be lost and can only
    /// be recovered if you have another verified active device or have a
    /// recovery key setup.
    ///
    /// When using [`dangerous_hard_limit_eviction`], the [`hard_limit`] must be
    /// at least 2 to avoid catastrophically losing encrypted history and
    /// digital identity in pathological cases. Keep in mind this is a bare
    /// minimum restriction and you can still run into trouble.
    ///
    /// This is most applicable in scenarios where your homeserver has many
    /// legacy bots/scripts that login over and over (which ideally should
    /// be using [personal access
    /// tokens](https://github.com/element-hq/matrix-authentication-service/issues/4492))
    /// and you want to avoid breaking their operation while maintaining some
    /// level of sanity with the number of devices that people can have.
    ///
    /// [`hard_limit`]: Self::hard_limit
    /// [`dangerous_hard_limit_eviction`]: Self::dangerous_hard_limit_eviction
    #[serde(default = "default_false")]
    pub dangerous_hard_limit_eviction: bool,
}

impl SessionLimitConfig {
    fn validate(&self) -> Result<(), Box<figment::error::Error>> {
        // See [`SessionLimitConfig::dangerous_hard_limit_eviction`] docstring
        if self.dangerous_hard_limit_eviction && self.hard_limit.get() < 2 {
            return Err(figment::error::Error::from(
                "Session `hard_limit` must be at least 2 when automatic `dangerous_hard_limit_eviction` is set. \
                See configuration docs for more info.",
            ).with_path("hard_limit").into());
        }

        Ok(())
    }
}
