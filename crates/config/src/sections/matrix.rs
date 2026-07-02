// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use anyhow::bail;
use camino::Utf8PathBuf;
use rand::{
    Rng,
    distributions::{Alphanumeric, DistString},
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use url::Url;

use super::ConfigurationSection;

fn default_homeserver() -> String {
    "localhost:8008".to_owned()
}

fn default_endpoint() -> Url {
    Url::parse("http://localhost:8008/").unwrap()
}

/// The kind of homeserver it is.
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema, Default)]
#[serde(rename_all = "snake_case")]
pub enum HomeserverKind {
    /// Synapse, version 1.135.0 or newer
    #[default]
    Synapse,

    /// same as `synapse`, but in read-only mode. This is meant for testing
    /// rolling out MAS with no risk of writing data to the homeserver.
    SynapseReadOnly,

    /// Synapse with the modern admin API available (>= 1.135.0)
    SynapseModern,

    /// Synapse using the legacy admin API
    SynapseLegacy,
}

/// Shared secret between MAS and the homeserver.
///
/// It either holds the secret value directly or references a file where the
/// secret is stored.
#[derive(Clone, Debug)]
pub enum Secret {
    File(Utf8PathBuf),
    Value(String),
}

/// Secret fields as serialized in JSON.
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct SecretRaw {
    /// Shared secret used to authenticate the service to the homeserver.
    /// This must be of high entropy, because leaking this secret would allow
    /// anyone to perform admin actions on the homeserver.
    #[schemars(with = "Option<String>", example = &"/path/to/secret/file")]
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_file: Option<Utf8PathBuf>,

    /// Alternatively, the shared secret can be passed inline.
    #[schemars(example = &"SomeRandomSecret")]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
}

impl TryFrom<SecretRaw> for Secret {
    type Error = anyhow::Error;

    fn try_from(value: SecretRaw) -> Result<Self, Self::Error> {
        match (value.secret, value.secret_file) {
            (None, None) => bail!("Missing `secret` or `secret_file`"),
            (None, Some(path)) => Ok(Secret::File(path)),
            (Some(secret), None) => Ok(Secret::Value(secret)),
            (Some(_), Some(_)) => bail!("Cannot specify both `secret` and `secret_file`"),
        }
    }
}

impl From<Secret> for SecretRaw {
    fn from(value: Secret) -> Self {
        match value {
            Secret::File(path) => SecretRaw {
                secret_file: Some(path),
                secret: None,
            },
            Secret::Value(secret) => SecretRaw {
                secret_file: None,
                secret: Some(secret),
            },
        }
    }
}

/// Settings related to the connection to the Matrix homeserver
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct MatrixConfig {
    /// The kind of homeserver it is. Defaults to `synapse`.
    #[serde(default)]
    #[schemars(extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub kind: HomeserverKind,

    /// The homeserver name, as per the `server_name` in the Synapse
    /// configuration file.
    #[serde(default = "default_homeserver")]
    #[schemars(example = &"example.com")]
    pub homeserver: String,

    /// Shared secret to use for calls to the admin API
    #[schemars(with = "SecretRaw")]
    #[serde_as(as = "serde_with::TryFromInto<SecretRaw>")]
    #[serde(flatten)]
    pub secret: Secret,

    /// URL to which the homeserver is accessible from the service.
    #[serde(default = "default_endpoint")]
    #[schemars(example = &"http://localhost:8008")]
    pub endpoint: Url,
}

impl ConfigurationSection for MatrixConfig {
    const PATH: Option<&'static str> = Some("matrix");
}

impl MatrixConfig {
    /// Returns the shared secret.
    ///
    /// If `secret_file` was given, the secret is read from that file.
    ///
    /// # Errors
    ///
    /// Returns an error when the shared secret could not be read from file.
    pub async fn secret(&self) -> anyhow::Result<String> {
        Ok(match &self.secret {
            Secret::File(path) => {
                let raw = tokio::fs::read_to_string(path).await?;
                // Trim the secret when read from file to match Synapse's behaviour
                raw.trim().to_string()
            }
            Secret::Value(secret) => secret.clone(),
        })
    }

    pub(crate) fn generate<R>(mut rng: R) -> Self
    where
        R: Rng + Send,
    {
        Self {
            kind: HomeserverKind::default(),
            homeserver: default_homeserver(),
            secret: Secret::Value(Alphanumeric.sample_string(&mut rng, 32)),
            endpoint: default_endpoint(),
        }
    }

    pub(crate) fn test() -> Self {
        Self {
            kind: HomeserverKind::default(),
            homeserver: default_homeserver(),
            secret: Secret::Value("test".to_owned()),
            endpoint: default_endpoint(),
        }
    }
}

#[cfg(test)]
mod tests {
    // The closures passed to `Jail::expect_with` return `figment::Error`, which is
    // large, and we can't change figment's API.
    #![expect(clippy::result_large_err)]

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r"
                        matrix:
                          homeserver: matrix.org
                          secret_file: secret
                    ",
                )?;
                jail.create_file("secret", r"m472!x53c237")?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<MatrixConfig>("matrix")?;

                Handle::current().block_on(async move {
                    assert_eq!(&config.homeserver, "matrix.org");
                    assert!(matches!(config.secret, Secret::File(ref p) if p == "secret"));
                    assert_eq!(config.secret().await.unwrap(), "m472!x53c237");
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn load_config_inline_secrets() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    r"
                        matrix:
                          homeserver: matrix.org
                          secret: m472!x53c237
                    ",
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<MatrixConfig>("matrix")?;

                Handle::current().block_on(async move {
                    assert_eq!(&config.homeserver, "matrix.org");
                    assert!(matches!(config.secret, Secret::Value(ref v) if v == "m472!x53c237"));
                    assert_eq!(config.secret().await.unwrap(), "m472!x53c237");
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }
}
