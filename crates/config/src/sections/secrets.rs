// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::borrow::Cow;

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use futures_util::future::{try_join, try_join_all};
use mas_jose::jwk::{JsonWebKey, JsonWebKeySet, Thumbprint};
use mas_keystore::{Encrypter, Keystore, PrivateKey};
use rand::{Rng, SeedableRng, distributions::Standard, prelude::Distribution as _};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use tokio::task;
use tracing::info;

use super::ConfigurationSection;

fn example_secret() -> &'static str {
    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
}

/// Password config option.
///
/// It either holds the password value directly or references a file where the
/// password is stored.
#[derive(Clone, Debug)]
pub enum Password {
    File(Utf8PathBuf),
    Value(String),
}

/// Password fields as serialized in JSON.
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct PasswordRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    password_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    password: Option<String>,
}

impl TryFrom<PasswordRaw> for Option<Password> {
    type Error = anyhow::Error;

    fn try_from(value: PasswordRaw) -> Result<Self, Self::Error> {
        match (value.password, value.password_file) {
            (None, None) => Ok(None),
            (None, Some(path)) => Ok(Some(Password::File(path))),
            (Some(password), None) => Ok(Some(Password::Value(password))),
            (Some(_), Some(_)) => bail!("Cannot specify both `password` and `password_file`"),
        }
    }
}

impl From<Option<Password>> for PasswordRaw {
    fn from(value: Option<Password>) -> Self {
        match value {
            Some(Password::File(path)) => PasswordRaw {
                password_file: Some(path),
                password: None,
            },
            Some(Password::Value(password)) => PasswordRaw {
                password_file: None,
                password: Some(password),
            },
            None => PasswordRaw {
                password_file: None,
                password: None,
            },
        }
    }
}

/// Key config option.
///
/// It either holds the key value directly or references a file where the key is
/// stored.
#[derive(Clone, Debug)]
pub enum Key {
    File(Utf8PathBuf),
    Value(String),
}

/// Key fields as serialized in JSON.
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
struct KeyRaw {
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    key_file: Option<Utf8PathBuf>,
    #[serde(skip_serializing_if = "Option::is_none")]
    key: Option<String>,
}

impl TryFrom<KeyRaw> for Key {
    type Error = anyhow::Error;

    fn try_from(value: KeyRaw) -> Result<Key, Self::Error> {
        match (value.key, value.key_file) {
            (None, None) => bail!("Missing `key` or `key_file`"),
            (None, Some(path)) => Ok(Key::File(path)),
            (Some(key), None) => Ok(Key::Value(key)),
            (Some(_), Some(_)) => bail!("Cannot specify both `key` and `key_file`"),
        }
    }
}

impl From<Key> for KeyRaw {
    fn from(value: Key) -> Self {
        match value {
            Key::File(path) => KeyRaw {
                key_file: Some(path),
                key: None,
            },
            Key::Value(key) => KeyRaw {
                key_file: None,
                key: Some(key),
            },
        }
    }
}

/// A single key with its key ID and optional password.
#[serde_as]
#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
pub struct KeyConfig {
    /// The key ID `kid` of the key as used by JWKs.
    ///
    /// If not given, `kid` will be the key’s RFC 7638 JWK Thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,

    #[schemars(with = "PasswordRaw")]
    #[serde_as(as = "serde_with::TryFromInto<PasswordRaw>")]
    #[serde(flatten)]
    password: Option<Password>,

    #[schemars(with = "KeyRaw")]
    #[serde_as(as = "serde_with::TryFromInto<KeyRaw>")]
    #[serde(flatten)]
    key: Key,
}

impl KeyConfig {
    /// Returns the password in case any is provided.
    ///
    /// If `password_file` was given, the password is read from that file.
    async fn password(&self) -> anyhow::Result<Option<Cow<[u8]>>> {
        Ok(match &self.password {
            Some(Password::File(path)) => Some(Cow::Owned(tokio::fs::read(path).await?)),
            Some(Password::Value(password)) => Some(Cow::Borrowed(password.as_bytes())),
            None => None,
        })
    }

    /// Returns the key.
    ///
    /// If `key_file` was given, the key is read from that file.
    async fn key(&self) -> anyhow::Result<Cow<[u8]>> {
        Ok(match &self.key {
            Key::File(path) => Cow::Owned(tokio::fs::read(path).await?),
            Key::Value(key) => Cow::Borrowed(key.as_bytes()),
        })
    }

    /// Returns the JSON Web Key derived from this key config.
    ///
    /// Password and/or key are read from file if they’re given as path.
    async fn json_web_key(&self) -> anyhow::Result<JsonWebKey<mas_keystore::PrivateKey>> {
        let (key, password) = try_join(self.key(), self.password()).await?;

        let private_key = match password {
            Some(password) => PrivateKey::load_encrypted(&key, password)?,
            None => PrivateKey::load(&key)?,
        };

        let kid = match self.kid.clone() {
            Some(kid) => kid,
            None => private_key.thumbprint_sha256_base64(),
        };

        Ok(JsonWebKey::new(private_key)
            .with_kid(kid)
            .with_use(mas_iana::jose::JsonWebKeyUse::Sig))
    }
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
        let web_keys = try_join_all(self.keys.iter().map(KeyConfig::json_web_key)).await?;

        Ok(Keystore::new(JsonWebKeySet::new(web_keys)))
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
}

impl SecretsConfig {
    #[expect(clippy::similar_names, reason = "Key type names are very similar")]
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
            kid: None,
            password: None,
            key: Key::Value(rsa_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
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
            kid: None,
            password: None,
            key: Key::Value(ec_p256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        let span = tracing::info_span!("ec_p384");
        let key_rng = rand_chacha::ChaChaRng::from_rng(&mut rng)?;
        let ec_p384_key = task::spawn_blocking(move || {
            let _entered = span.enter();
            let ret = PrivateKey::generate_ec_p384(key_rng);
            info!("Done generating EC P-384 key");
            ret
        })
        .await
        .context("could not join blocking task")?;
        let ec_p384_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(ec_p384_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
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
            kid: None,
            password: None,
            key: Key::Value(ec_k256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        Ok(Self {
            encryption: Encryption::Value(Standard.sample(&mut rng)),
            keys: vec![rsa_key, ec_p256_key, ec_p384_key, ec_k256_key],
        })
    }

    pub(crate) fn test() -> Self {
        let rsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
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
        };
        let ecdsa_key = KeyConfig {
            kid: None,
            password: None,
            key: Key::Value(
                indoc::indoc! {r"
                  -----BEGIN PRIVATE KEY-----
                  MIGEAgEAMBAGByqGSM49AgEGBSuBBAAKBG0wawIBAQQgqfn5mYO/5Qq/wOOiWgHA
                  NaiDiepgUJ2GI5eq2V8D8nahRANCAARMK9aKUd/H28qaU+0qvS6bSJItzAge1VHn
                  OhBAAUVci1RpmUA+KdCL5sw9nadAEiONeiGr+28RYHZmlB9qXnjC
                  -----END PRIVATE KEY-----
                "}
                .to_owned(),
            ),
        };

        Self {
            encryption: Encryption::Value([0xEA; 32]),
            keys: vec![rsa_key, ecdsa_key],
        }
    }
}

#[cfg(test)]
mod tests {
    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };
    use mas_jose::constraints::Constrainable;
    use tokio::{runtime::Handle, task};

    use super::*;

    #[tokio::test]
    async fn load_config_inline_secrets() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption: >-
                            0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                            - key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIKlZz/GnH0idVH1PnAF4HQNwRafgBaE2tmyN1wjfdOQqoAoGCCqGSM49
                                AwEHoUQDQgAEHrgPeG+Mt8eahih1h4qaPjhl7jT25cdzBkg3dbVks6gBR2Rx4ug9
                                h27LAir5RqxByHvua2XsP46rSTChof78uw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;

                let config = Figment::new()
                    .merge(Yaml::file("config.yaml"))
                    .extract_inner::<SecretsConfig>("secrets")?;

                Handle::current().block_on(async move {
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let key_store = config.key_store().await.unwrap();
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }
}
