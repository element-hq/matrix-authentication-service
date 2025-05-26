// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::borrow::Cow;

use anyhow::{Context, bail};
use camino::Utf8PathBuf;
use futures::future::{try_join, try_join_all};
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
    password_file: Option<Utf8PathBuf>,
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
    key_file: Option<Utf8PathBuf>,
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
    kid: String,

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
    async fn password(&self) -> anyhow::Result<Option<Cow<String>>> {
        Ok(match &self.password {
            Some(Password::File(path)) => Some(Cow::Owned(tokio::fs::read_to_string(path).await?)),
            Some(Password::Value(password)) => Some(Cow::Borrowed(password)),
            None => None,
        })
    }

    /// Returns the key.
    ///
    /// If `key_file` was given, the key is read from that file.
    async fn key(&self) -> anyhow::Result<Cow<String>> {
        Ok(match &self.key {
            Key::File(path) => Cow::Owned(tokio::fs::read_to_string(path).await?),
            Key::Value(key) => Cow::Borrowed(key),
        })
    }

    /// Returns the JSON Web Key derived from this key config.
    ///
    /// Password and/or key are read from file if they’re given as path.
    async fn json_web_key(&self) -> anyhow::Result<JsonWebKey<mas_keystore::PrivateKey>> {
        let (key, password) = try_join(self.key(), self.password()).await?;

        let private_key = match password {
            Some(password) => PrivateKey::load_encrypted(key.as_bytes(), password.as_bytes())?,
            None => PrivateKey::load(key.as_bytes())?,
        };

        Ok(JsonWebKey::new(private_key)
            .with_kid(self.kid.clone())
            .with_use(mas_iana::jose::JsonWebKeyUse::Sig))
    }
}

/// Application secrets
#[serde_as]
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct SecretsConfig {
    /// Encryption key for secure cookies
    #[schemars(
        with = "String",
        regex(pattern = r"[0-9a-fA-F]{64}"),
        example = "example_secret"
    )]
    #[serde_as(as = "serde_with::hex::Hex")]
    pub encryption: [u8; 32],

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
    #[must_use]
    pub fn encrypter(&self) -> Encrypter {
        Encrypter::new(&self.encryption)
    }
}

impl ConfigurationSection for SecretsConfig {
    const PATH: Option<&'static str> = Some("secrets");

    fn validate(&self, _figment: &figment::Figment) -> Result<(), figment::Error> {
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
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            key: Key::Value(ec_p256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
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
            kid: Alphanumeric.sample_string(&mut rng, 10),
            password: None,
            key: Key::Value(ec_k256_key.to_pem(pem_rfc7468::LineEnding::LF)?.to_string()),
        };

        Ok(Self {
            encryption: Standard.sample(&mut rng),
            keys: vec![rsa_key, ec_p256_key, ec_p384_key, ec_k256_key],
        })
    }

    pub(crate) fn test() -> Self {
        let rsa_key = KeyConfig {
            kid: "abcdef".to_owned(),
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
            kid: "ghijkl".to_owned(),
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
            encryption: [0xEA; 32],
            keys: vec![rsa_key, ecdsa_key],
        }
    }
}
