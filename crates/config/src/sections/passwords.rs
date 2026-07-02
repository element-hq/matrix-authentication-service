// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::cmp::Reverse;

use anyhow::bail;
use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

fn default_schemes() -> Vec<HashingScheme> {
    vec![HashingScheme {
        version: 1,
        algorithm: Algorithm::default(),
        cost: None,
        secret: None,
        secret_file: None,
        unicode_normalization: false,
    }]
}

fn default_enabled() -> bool {
    true
}

fn default_minimum_complexity() -> u8 {
    3
}

/// Settings related to the local password database
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct PasswordsConfig {
    /// Whether to enable the password database.
    ///
    /// If disabled, users will only be able to log in using upstream OIDC
    /// providers
    #[serde(default = "default_enabled")]
    pub enabled: bool,

    /// List of password hashing schemes being used
    ///
    /// /!\ Only change this if you know what you're doing
    #[serde(default = "default_schemes")]
    pub schemes: Vec<HashingScheme>,

    /// Minimum complexity required for passwords, estimated by the zxcvbn
    /// algorithm
    ///
    /// Must be between 0 and 4, default is 3
    ///
    /// See <https://github.com/dropbox/zxcvbn#usage> for more information
    #[serde(default = "default_minimum_complexity")]
    minimum_complexity: u8,
}

impl Default for PasswordsConfig {
    fn default() -> Self {
        Self {
            enabled: default_enabled(),
            schemes: default_schemes(),
            minimum_complexity: default_minimum_complexity(),
        }
    }
}

impl ConfigurationSection for PasswordsConfig {
    const PATH: Option<&'static str> = Some("passwords");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let annotate = |mut error: figment::Error| {
            error.metadata = figment.find_metadata(Self::PATH.unwrap()).cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned()];
            error
        };

        if !self.enabled {
            // Skip validation if password-based authentication is disabled
            return Ok(());
        }

        if self.schemes.is_empty() {
            return Err(annotate(figment::Error::from(
                "Requires at least one password scheme in the config".to_owned(),
            ))
            .into());
        }

        for scheme in &self.schemes {
            if scheme.secret.is_some() && scheme.secret_file.is_some() {
                return Err(annotate(figment::Error::from(
                    "Cannot specify both `secret` and `secret_file`".to_owned(),
                ))
                .into());
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
    ) -> Result<Vec<(u16, Algorithm, Option<u32>, Option<Vec<u8>>, bool)>, anyhow::Error> {
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

            mapped_result.push((
                scheme.version,
                scheme.algorithm,
                scheme.cost,
                secret,
                scheme.unicode_normalization,
            ));
        }

        Ok(mapped_result)
    }
}

#[expect(clippy::trivially_copy_pass_by_ref)]
const fn is_default_false(value: &bool) -> bool {
    !*value
}

/// Parameters for a password hashing scheme
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct HashingScheme {
    /// The version of the hashing scheme. Must be unique; the highest version
    /// is used for hashing new passwords, the others are kept to verify
    /// existing passwords.
    #[schemars(example = &1u16)]
    pub version: u16,

    /// The hashing algorithm to use.
    #[schemars(example = &Algorithm::Argon2id)]
    pub algorithm: Algorithm,

    /// Whether to apply Unicode normalization to the password before hashing.
    ///
    /// Defaults to `false`, and generally recommended to stay false. This is
    /// recommended when importing password hashes from Synapse, which applies
    /// an NFKC normalization to the password before hashing it.
    #[serde(default, skip_serializing_if = "is_default_false")]
    #[schemars(example = &false)]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub unicode_normalization: bool,

    /// Cost for the bcrypt algorithm. Defaults to `12`.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(default = "default_bcrypt_cost")]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub cost: Option<u32>,

    /// An optional secret ("pepper") to use when hashing passwords. This makes
    /// it harder to brute-force the passwords in case of a database leak.
    ///
    /// This must not be specified if `secret_file` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"<secret>")]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub secret: Option<String>,

    /// Same as `secret`, but read from a file.
    ///
    /// This must not be specified if `secret` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>", example = &"/path/to/secret")]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub secret_file: Option<Utf8PathBuf>,
}

#[expect(clippy::unnecessary_wraps)]
fn default_bcrypt_cost() -> Option<u32> {
    Some(12)
}

/// A hashing algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum Algorithm {
    /// The bcrypt password hashing algorithm.
    Bcrypt,

    /// The Argon2id password hashing algorithm. This is the default.
    #[default]
    Argon2id,

    /// The PBKDF2 password hashing algorithm.
    Pbkdf2,
}
