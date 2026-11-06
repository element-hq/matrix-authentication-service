// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::HashMap, num::NonZeroU64};

use chrono::Duration;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use ulid::Ulid;

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
    /// `m.login.sso` compatibility login flow), if the soft limit is reached,
    /// it will display a policy violation screen (web UI) to remove
    /// sessions before creating the new session.
    ///
    /// This is not enforced in non-interactive contexts (like
    /// `m.login.password` login with the compatibility API) as there is no
    /// opportunity for us to show some UI for people remove some sessions.
    /// See [`hard_limit`] for enforcement on that side.
    ///
    /// This is the limit that is displayed in the UI
    ///
    /// [`hard_limit`]: Self::hard_limit
    ///
    /// May be omitted when [`per_client`] is set. In that case there is no
    /// global limit: only the listed OAuth 2.0 clients are limited.
    ///
    /// [`per_client`]: Self::per_client
    #[serde(default)]
    pub soft_limit: Option<NonZeroU64>,
    /// Upon login, when `dangerous_hard_limit_eviction: false`, will refuse the
    /// new login (policy violation error), otherwise, see
    /// [`dangerous_hard_limit_eviction`].
    ///
    /// The hard limit is enforced in all contexts
    /// (interactive/non-interactive).
    ///
    /// May be omitted together with [`soft_limit`] when [`per_client`] is set.
    ///
    /// [`dangerous_hard_limit_eviction`]: Self::dangerous_hard_limit_eviction
    /// [`soft_limit`]: Self::soft_limit
    /// [`per_client`]: Self::per_client
    #[serde(default)]
    pub hard_limit: Option<NonZeroU64>,
    /// When set, only accounts with <= `max_session_threshold` sessions have
    /// the session limits applied.
    ///
    /// This is most applicable in scenarios where your homeserver has many
    /// legacy bots/scripts that login over and over (which ideally should
    /// be using [personal access
    /// tokens](https://github.com/element-hq/matrix-authentication-service/issues/4492))
    /// and you want to avoid breaking their operation while maintaining some
    /// level of sanity with the number of devices that people can have.
    /// This will prevent anyone else from crossing the limit.
    pub max_session_threshold: Option<NonZeroU64>,
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
    /// Removing devices is a non-trivial task for some homeservers to tackle
    /// and can cause lots of device list changes, `/sync`, federation, and
    /// replication traffic. Consider using [`max_session_threshold`] to
    /// limit the size of accounts that are acted upon.
    ///
    /// [`hard_limit`]: Self::hard_limit
    /// [`dangerous_hard_limit_eviction`]: Self::dangerous_hard_limit_eviction
    /// [`max_session_threshold`]: Self::max_session_threshold
    #[serde(default = "default_false")]
    pub dangerous_hard_limit_eviction: bool,

    /// Optional session limits that apply when logging into a specific OAuth
    /// 2.0 client, replacing the top-level limits for that client.
    ///
    /// Keys are OAuth 2.0 client IDs (ULIDs). Values use the same fields as
    /// this section. Optional fields do not inherit from the top-level
    /// config: omitted `max_session_threshold` means limits always apply,
    /// and `dangerous_hard_limit_eviction` defaults to `false`.
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    #[schemars(with = "HashMap<String, SessionLimitRules>")]
    pub per_client: HashMap<Ulid, SessionLimitRules>,
}

/// Session limit numbers applied either globally or to one OAuth 2.0 client.
///
/// This is the value type of [`SessionLimitConfig::per_client`].
#[derive(Clone, Debug, Deserialize, JsonSchema, Serialize)]
pub struct SessionLimitRules {
    /// See [`SessionLimitConfig::soft_limit`]
    pub soft_limit: NonZeroU64,
    /// See [`SessionLimitConfig::hard_limit`]
    pub hard_limit: NonZeroU64,
    /// See [`SessionLimitConfig::max_session_threshold`]
    pub max_session_threshold: Option<NonZeroU64>,
    /// See [`SessionLimitConfig::dangerous_hard_limit_eviction`]
    #[serde(default = "default_false")]
    pub dangerous_hard_limit_eviction: bool,
}

impl SessionLimitRules {
    fn validate(&self) -> Result<(), Box<figment::error::Error>> {
        validate_session_limit_bounds(
            self.soft_limit,
            self.hard_limit,
            self.dangerous_hard_limit_eviction,
        )
    }
}

fn validate_session_limit_bounds(
    soft_limit: NonZeroU64,
    hard_limit: NonZeroU64,
    dangerous_hard_limit_eviction: bool,
) -> Result<(), Box<figment::error::Error>> {
    // We assume the `hard_limit` is >= the `soft_limit`
    //
    // Why? The UI only shows the soft_limit to users. If hard_limit were smaller
    // than soft_limit, users could hit the hard_limit without ever reaching the
    // visible soft_limit threshold — making the actual limit invisible and the
    // failure confusing.
    if hard_limit < soft_limit {
        return Err(figment::error::Error::from(
            "Session `hard_limit` must be greater than or equal to the user-facing `soft_limit`.",
        )
        .with_path("hard_limit")
        .into());
    }

    // See [`SessionLimitConfig::dangerous_hard_limit_eviction`] docstring
    if dangerous_hard_limit_eviction && hard_limit.get() < 2 {
        return Err(figment::error::Error::from(
            "Session `hard_limit` must be at least 2 when automatic `dangerous_hard_limit_eviction` is set. \
            See configuration docs for more info.",
        ).with_path("hard_limit").into());
    }

    Ok(())
}

impl SessionLimitConfig {
    fn validate(&self) -> Result<(), Box<figment::error::Error>> {
        match (self.soft_limit, self.hard_limit) {
            (Some(soft_limit), Some(hard_limit)) => {
                validate_session_limit_bounds(
                    soft_limit,
                    hard_limit,
                    self.dangerous_hard_limit_eviction,
                )?;
            }
            (None, None) => {
                if self.dangerous_hard_limit_eviction {
                    return Err(figment::error::Error::from(
                        "Session `dangerous_hard_limit_eviction` requires a global `hard_limit`.",
                    )
                    .with_path("dangerous_hard_limit_eviction")
                    .into());
                }
                if self.per_client.is_empty() {
                    return Err(figment::error::Error::from(
                        "Session limits require `soft_limit` and `hard_limit`, or a non-empty `per_client` map.",
                    )
                    .into());
                }
            }
            (Some(_), None) => {
                return Err(figment::error::Error::from(
                    "Session `hard_limit` is required when `soft_limit` is set.",
                )
                .with_path("hard_limit")
                .into());
            }
            (None, Some(_)) => {
                return Err(figment::error::Error::from(
                    "Session `soft_limit` is required when `hard_limit` is set.",
                )
                .with_path("soft_limit")
                .into());
            }
        }

        for (client_id, rules) in &self.per_client {
            rules
                .validate()
                .map_err(|err| Box::new((*err).with_path(&format!("per_client.{client_id}"))))?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![expect(clippy::result_large_err)]

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    #[test]
    fn per_client_hard_limit_must_be_at_least_soft_limit() {
        let config = SessionLimitConfig {
            soft_limit: Some(NonZeroU64::new(10).unwrap()),
            hard_limit: Some(NonZeroU64::new(10).unwrap()),
            max_session_threshold: None,
            dangerous_hard_limit_eviction: false,
            per_client: HashMap::from([(
                Ulid::nil(),
                SessionLimitRules {
                    soft_limit: NonZeroU64::new(5).unwrap(),
                    hard_limit: NonZeroU64::new(2).unwrap(),
                    max_session_threshold: None,
                    dangerous_hard_limit_eviction: false,
                },
            )]),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn per_client_eviction_requires_hard_limit_at_least_two() {
        let config = SessionLimitConfig {
            soft_limit: Some(NonZeroU64::new(1).unwrap()),
            hard_limit: Some(NonZeroU64::new(2).unwrap()),
            max_session_threshold: None,
            dangerous_hard_limit_eviction: false,
            per_client: HashMap::from([(
                Ulid::nil(),
                SessionLimitRules {
                    soft_limit: NonZeroU64::new(1).unwrap(),
                    hard_limit: NonZeroU64::new(1).unwrap(),
                    max_session_threshold: None,
                    dangerous_hard_limit_eviction: true,
                },
            )]),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn per_client_only_does_not_require_global_limits() {
        let config: SessionLimitConfig = serde_json::from_value(serde_json::json!({
            "per_client": {
                "00000000000000000000000000": {
                    "soft_limit": 2,
                    "hard_limit": 3
                }
            }
        }))
        .unwrap();

        assert!(config.soft_limit.is_none());
        assert!(config.hard_limit.is_none());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn session_limit_requires_global_limits_or_per_client() {
        let config = SessionLimitConfig {
            soft_limit: None,
            hard_limit: None,
            max_session_threshold: None,
            dangerous_hard_limit_eviction: false,
            per_client: HashMap::new(),
        };

        assert!(config.validate().is_err());
    }

    #[test]
    fn per_client_only_yaml_does_not_require_global_limits() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r"
                    experimental:
                      session_limit:
                        per_client:
                          '01FSHN9A2Q9FXBM5T1WDB4P6S0':
                            soft_limit: 2
                            hard_limit: 3
                ",
            )?;

            let figment = Figment::new().merge(Yaml::file("config.yaml"));
            let config = figment.extract_inner::<ExperimentalConfig>("experimental")?;
            let session_limit = config.session_limit.as_ref().unwrap();
            assert!(session_limit.soft_limit.is_none());
            assert!(session_limit.hard_limit.is_none());
            assert_eq!(session_limit.per_client.len(), 1);
            config
                .validate(&figment)
                .map_err(|err| figment::Error::from(err.to_string()))?;

            Ok(())
        });
    }
}
