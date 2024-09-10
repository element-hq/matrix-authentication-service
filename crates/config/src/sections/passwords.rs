// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::cmp::Reverse;

use anyhow::bail;
use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

fn default_schemes() -> Vec<HashingScheme> {
    vec![HashingScheme {
        version: 1,
        algorithm: Algorithm::Argon2id,
        cost: None,
        secret: None,
        secret_file: None,
    }]
}

fn default_enabled() -> bool {
    true
}

fn default_minimum_complexity() -> u8 {
    3
}

/// Configuration for REST password provider
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct RestAuthProviderConfig {
    /// The base URL where the identity service is implemented
    pub url: String,
    /// Implemented version of the identity service ("v1", "v2")
    pub version: String,
}

impl RestAuthProviderConfig {
    /// Constructor for RestAuthProviderConfig
    pub fn new(url: String, version: String) -> Self {
        Self { url, version }
    }
}

/// User password hashing config
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PasswordsConfig {
    /// Whether password-based authentication is enabled
    #[serde(default = "default_enabled")]
    enabled: bool,

    #[serde(default = "default_schemes")]
    schemes: Vec<HashingScheme>,

    /// Score between 0 and 4 determining the minimum allowed password
    /// complexity. Scores are based on the ESTIMATED number of guesses
    /// needed to guess the password.
    ///
    /// - 0: less than 10^2 (100)
    /// - 1: less than 10^4 (10'000)
    /// - 2: less than 10^6 (1'000'000)
    /// - 3: less than 10^8 (100'000'000)
    /// - 4: any more than that
    #[serde(default = "default_minimum_complexity")]
    minimum_complexity: u8,

    /// The REST authentication provider URL
    #[serde(skip_serializing_if = "Option::is_none")]
    rest_auth_provider: Option<RestAuthProviderConfig>,
}

impl Default for PasswordsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            schemes: default_schemes(),
            minimum_complexity: default_minimum_complexity(),
            rest_auth_provider: None,
        }
    }
}

impl ConfigurationSection for PasswordsConfig {
    const PATH: Option<&'static str> = Some("passwords");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        let annotate = |mut error: figment::Error| {
            error.metadata = figment.find_metadata(Self::PATH.unwrap()).cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned()];
            Err(error)
        };

        if !self.enabled {
            // Skip validation if password-based authentication is disabled
            return Ok(());
        }

        if self.schemes.is_empty() {
            return annotate(figment::Error::from(
                "Requires at least one password scheme in the config".to_owned(),
            ));
        }

        for scheme in &self.schemes {
            if scheme.secret.is_some() && scheme.secret_file.is_some() {
                return annotate(figment::Error::from(
                    "Cannot specify both `secret` and `secret_file`".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

impl PasswordsConfig {
    /// Whether password-based authentication is enabled
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// Minimum complexity of passwords, from 0 to 4, according to the zxcvbn
    /// scorer.
    #[must_use]
    pub fn minimum_complexity(&self) -> u8 {
        self.minimum_complexity
    }

    /// Load the password hashing schemes defined by the config
    ///
    /// # Errors
    ///
    /// Returns an error if the config is invalid, or if the secret file could
    /// not be read.
    pub async fn load(
        &self,
    ) -> Result<Vec<(u16, Algorithm, Option<u32>, Option<Vec<u8>>)>, anyhow::Error> {
        let mut schemes: Vec<&HashingScheme> = self.schemes.iter().collect();
        schemes.sort_unstable_by_key(|a| Reverse(a.version));
        schemes.dedup_by_key(|a| a.version);

        if schemes.len() != self.schemes.len() {
            // Some schemes had duplicated versions
            bail!("Multiple password schemes have the same versions");
        }

        if schemes.is_empty() {
            bail!("Requires at least one password scheme in the config");
        }

        let mut mapped_result = Vec::with_capacity(schemes.len());

        for scheme in schemes {
            let secret = match (&scheme.secret, &scheme.secret_file) {
                (Some(secret), None) => Some(secret.clone().into_bytes()),
                (None, Some(secret_file)) => {
                    let secret = tokio::fs::read(secret_file).await?;
                    Some(secret)
                }
                (Some(_), Some(_)) => bail!("Cannot specify both `secret` and `secret_file`"),
                (None, None) => None,
            };

            mapped_result.push((scheme.version, scheme.algorithm, scheme.cost, secret));
        }

        Ok(mapped_result)
    }

    /// Get the REST authentication config, if set.
    #[must_use]
    pub fn rest_auth_provider(&self) -> Option<&RestAuthProviderConfig> {
        self.rest_auth_provider.as_ref()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HashingScheme {
    version: u16,

    algorithm: Algorithm,

    /// Cost for the bcrypt algorithm
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default = "default_bcrypt_cost")]
    cost: Option<u32>,

    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    secret_file: Option<Utf8PathBuf>,
}

#[allow(clippy::unnecessary_wraps)]
fn default_bcrypt_cost() -> Option<u32> {
    Some(12)
}

/// A hashing algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// bcrypt
    Bcrypt,

    /// argon2id
    Argon2id,

    /// PBKDF2
    Pbkdf2,
}
