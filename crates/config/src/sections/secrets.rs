// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::borrow::Cow;

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use mas_jose::jwk::{JsonWebKey, JsonWebKeySet};
use mas_keystore::{Encrypter, Keystore, PrivateKey};
use rand::{
    Rng, SeedableRng,
    distributions::{Alphanumeric, DistString, Standard},
    prelude::Distribution as _,
};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::task;
use tracing::info;

use super::ConfigurationSection;

fn example_secret() -> &'static str {
    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
}

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    kid: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    password_file: Option<Utf8PathBuf>,

    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    key_file: Option<Utf8PathBuf>,
}

/// Encryption config option.
#[derive(Debug, Clone)]
pub enum Encryption {
    File(Utf8PathBuf),
    Value([u8; 32]),
}

/// Encryption fields as serialized in JSON.
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Debug, Clone)]
struct EncryptionRaw {
    /// File containing the encryption key for secure cookies.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption_file: Option<Utf8PathBuf>,

    /// Encryption key for secure cookies.
    #[schemars(
        with = "Option<String>",
        regex(pattern = r"[0-9a-fA-F]{64}"),
        example = "example_secret"
    )]
    #[serde_as(as = "Option<serde_with::hex::Hex>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    encryption: Option<[u8; 32]>,
}

impl TryFrom<EncryptionRaw> for Encryption {
    type Error = anyhow::Error;

    fn try_from(value: EncryptionRaw) -> Result<Encryption, Self::Error> {
        match (value.encryption, value.encryption_file) {
            (None, None) => bail!("Missing `encryption` or `encryption_file`"),
            (None, Some(path)) => Ok(Encryption::File(path)),
            (Some(encryption), None) => Ok(Encryption::Value(encryption)),
            (Some(_), Some(_)) => bail!("Cannot specify both `encryption` and `encryption_file`"),
        }
    }
}

impl From<Encryption> for EncryptionRaw {
    fn from(value: Encryption) -> Self {
        match value {
            Encryption::File(path) => EncryptionRaw {
                encryption_file: Some(path),
                encryption: None,
            },
            Encryption::Value(encryption) => EncryptionRaw {
                encryption_file: None,
                encryption: Some(encryption),
            },
        }
    }
}

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretsConfig {
    /// Encryption key for secure cookies
    #[schemars(with = "EncryptionRaw")]
    #[serde_as(as = "serde_with::TryFromInto<EncryptionRaw>")]
    #[serde(flatten)]
    encryption: Encryption,

    /// List of private keys to use for signing and encrypting payloads
    #[serde(default)]
    keys: Vec<KeyConfig>,
}

impl SecretsConfig {
    /// Derive a signing and verifying keystore out of the config
    ///
    /// # Errors
    ///
    /// Returns an error when a key could not be imported
    #[tracing::instrument(name = "secrets.load", skip_all)]
    pub async fn key_store(&self) -> anyhow::Result<Keystore> {
        let mut keys = Vec::with_capacity(self.keys.len());
        for item in &self.keys {
            let password = match (&item.password, &item.password_file) {
                (None, None) => None,
                (Some(_), Some(_)) => {
                    bail!("Cannot specify both `password` and `password_file`")
                }
                (Some(password), None) => Some(Cow::Borrowed(password)),
                (None, Some(path)) => Some(Cow::Owned(tokio::fs::read_to_string(path).await?)),
            };

            // Read the key either embedded in the config file or on disk
            let key = match (&item.key, &item.key_file) {
                (None, None) => bail!("Missing `key` or `key_file`"),
                (Some(_), Some(_)) => bail!("Cannot specify both `key` and `key_file`"),
                (Some(key), None) => {
                    // If the key was embedded in the config file, assume it is formatted as PEM
                    if let Some(password) = password {
                        PrivateKey::load_encrypted_pem(key, password.as_bytes())?
                    } else {
                        PrivateKey::load_pem(key)?
                    }
                }
                (None, Some(path)) => {
                    // When reading from disk, it might be either PEM or DER. `PrivateKey::load*`
                    // will try both.
                    let key = tokio::fs::read(path).await?;
                    if let Some(password) = password {
                        PrivateKey::load_encrypted(&key, password.as_bytes())?
                    } else {
                        PrivateKey::load(&key)?
                    }
                }
            };

            let key = JsonWebKey::new(key)
                .with_kid(item.kid.clone())
                .with_use(mas_iana::jose::JsonWebKeyUse::Sig);
            keys.push(key);
        }

        let keys = JsonWebKeySet::new(keys);
        Ok(Keystore::new(keys))
    }

    /// Derive an [`Encrypter`] out of the config
    ///
    /// # Errors
    ///
    /// Returns an error when the Encryptor can not be created.
    pub async fn encrypter(&self) -> anyhow::Result<Encrypter> {
        Ok(Encrypter::new(&self.encryption().await?))
    }

    /// Returns the encryption secret.
    ///
    /// # Errors
    ///
    /// Returns an error when the encryption secret could not be read from file.
    pub async fn encryption(&self) -> anyhow::Result<[u8; 32]> {
        // Read the encryption secret either embedded in the config file or on disk
        match self.encryption {
            Encryption::Value(encryption) => Ok(encryption),
            Encryption::File(ref path) => {
                let mut bytes = [0; 32];
                let content = tokio::fs::read(path).await?;
                hex::decode_to_slice(content, &mut bytes).context(
                    "Content of `encryption_file` must contain hex characters \
                    encoding exactly 32 bytes",
                )?;
                Ok(bytes)
            }
        }
    }
}

impl ConfigurationSection for SecretsConfig {
    const PATH: Option<&'static str> = Some("secrets");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        for (index, key) in self.keys.iter().enumerate() {
            let annotate = |mut error: figment::Error| {
                error.metadata = figment
                    .find_metadata(&format!("{root}.keys", root = Self::PATH.unwrap()))
                    .cloned();
                error.profile = Some(figment::Profile::Default);
                error.path = vec![
                    Self::PATH.unwrap().to_owned(),
                    "keys".to_owned(),
                    index.to_string(),
                ];
                Err(error)
            };

            if key.key.is_none() && key.key_file.is_none() {
                return annotate(figment::Error::from(
                    "Missing `key` or `key_file`".to_owned(),
                ));
            }

            if key.key.is_some() && key.key_file.is_some() {
                return annotate(figment::Error::from(
                    "Cannot specify both `key` and `key_file`".to_owned(),
                ));
            }

            if key.password.is_some() && key.password_file.is_some() {
                return annotate(figment::Error::from(
                    "Cannot specify both `password` and `password_file`".to_owned(),
                ));
            }
        }

        Ok(())
    }
}

impl SecretsConfig {
    #[tracing::instrument(skip_all)]
    pub(crate) async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        info!("Generating keys...");

        let span = tracing::info_span!("rsa");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let rsa_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_rsa(key_rng).unwrap();
            info!("Done generating RSA key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let rsa_key = KeyConfig {
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            password_file: None,
            key: Some(rsa_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
            key_file: None,
        };

        let span = tracing::info_span!("ec_p256");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p256_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p256(key_rng);
            info!("Done generating EC P-256 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p256_key = KeyConfig {
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            password_file: None,
            key: Some(ec_p256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
            key_file: None,
        };

        let span = tracing::info_span!("ec_p384");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p384_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p384(key_rng);
            info!("Done generating EC P-256 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p384_key = KeyConfig {
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            password_file: None,
            key: Some(ec_p384_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
            key_file: None,
        };

        let span = tracing::info_span!("ec_k256");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_k256_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_k256(key_rng);
            info!("Done generating EC secp256k1 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_k256_key = KeyConfig {
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            password_file: None,
            key: Some(ec_k256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
            key_file: None,
        };

        Ok(Self {
            encryption: Encryption::Value(Standard.sample(&mut rng)),
            keys: vec![rsa_key, ec_p256_key, ec_p384_key, ec_k256_key],
        })
    }

    pub(crate) fn test() -> Self {
        let rsa_key = KeyConfig {
            kid: "abcdef".to_owned(),
            password: None,
            password_file: None,
            key: Some(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAymS2RkeIZo7pUeEN
                  QUGCG4GLJru5jzxomO9jiNr5D/oRcerhpQVc9aCpBfAAg4l4a1SmYdBzWqX0X5pU
                  scgTtQIDAQABAkEArNIMlrxUK4bSklkCcXtXdtdKE9vuWfGyOw0GyAB69fkEUBxh
                  3j65u+u3ZmW+bpMWHgp1FtdobE9nGwb2VBTWAQIhAOyU1jiUEkrwKK004+6b5QRE
                  vC9UI2vDWy5vioMNx5Y1AiEA2wGAJ6ETF8FF2Vd+kZlkKK7J0em9cl0gbJDsWIEw
                  N4ECIEyWYkMurD1WQdTQqnk0Po+DMOihdFYOiBYgRdbnPxWBAiEAmtd0xJAd7622
                  tPQniMnrBtiN2NxqFXHCev/8Gpc8gAECIBcaPcF59qVeRmYrfqzKBxFm7LmTwlAl
                  Gh7BNzCeN+D6
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
            key_file: None,
        };
        let ecdsa_key = KeyConfig {
            kid: "ghijkl".to_owned(),
            password: None,
            password_file: None,
            key: Some(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                  NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                  OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
            key_file: None,
        };

        Self {
            encryption: Encryption::Value([0xEA; 32]),
            keys: vec![rsa_key, ecdsa_key],
        }
    }
}
