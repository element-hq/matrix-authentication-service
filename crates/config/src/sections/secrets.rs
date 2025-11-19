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
    async fn password(&self) -> anyhow::Result<Option<Cow<'_, [u8]>>> {
        Ok(match &self.password {
            Some(Password::File(path)) => Some(Cow::Owned(tokio::fs::read(path).await?)),
            Some(Password::Value(password)) => Some(Cow::Borrowed(password.as_bytes())),
            None => None,
        })
    }

    /// Returns the key.
    ///
    /// If `key_file` was given, the key is read from that file.
    async fn key(&self) -> anyhow::Result<Cow<'_, [u8]>> {
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
        example = &"0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff"
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

/// Reads all keys from the given directory.
async fn key_configs_from_path(path: &Utf8PathBuf) -> anyhow::Result<Vec<KeyConfig>> {
    let mut result = vec![];
    let mut read_dir = tokio::fs::read_dir(path).await?;
    while let Some(dir_entry) = read_dir.next_entry().await? {
        if !dir_entry.path().is_file() {
            continue;
        }
        result.push(KeyConfig {
            kid: None,
            password: None,
            key: Key::File(dir_entry.path().try_into()?),
        });
    }
    Ok(result)
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

    /// List of private keys to use for signing and encrypting payloads.
    #[serde(skip_serializing_if = "Option::is_none")]
    keys: Option<Vec<KeyConfig>>,

    /// Directory of private keys to use for signing and encrypting payloads.
    #[schemars(with = "Option<String>")]
    #[serde(skip_serializing_if = "Option::is_none")]
    keys_dir: Option<Utf8PathBuf>,
}

impl SecretsConfig {
    /// Derive a signing and verifying keystore out of the config
    ///
    /// # Errors
    ///
    /// Returns an error when a key could not be imported
    #[tracing::instrument(name = "secrets.load", skip_all)]
    pub async fn key_store(&self) -> anyhow::Result<Keystore> {
        let key_configs = self.key_configs().await?;
        let web_keys = try_join_all(key_configs.iter().map(KeyConfig::json_web_key)).await?;

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

    /// Returns a combined list of key configs given inline and from files.
    ///
    /// If `keys_dir` was given, the keys are read from file.
    async fn key_configs(&self) -> anyhow::Result<Vec<KeyConfig>> {
        let mut key_configs = match &self.keys_dir {
            Some(keys_dir) => key_configs_from_path(keys_dir).await?,
            None => vec![],
        };

        let inline_key_configs = self.keys.as_deref().unwrap_or_default();
        key_configs.extend(inline_key_configs.iter().cloned());

        Ok(key_configs)
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
            keys: Some(vec![rsa_key, ec_p256_key, ec_p384_key, ec_k256_key]),
            keys_dir: None,
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
            keys: Some(vec![rsa_key, ecdsa_key]),
            keys_dir: None,
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
    async fn load_config() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                    "},
                )?;
                jail.create_file(
                    "encryption",
                    "0000111122223333444455556666777788889999aaaabbbbccccddddeeeeffff",
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key1",
                    indoc::indoc! {r"
                        -----BEGIN RSA PRIVATE KEY-----
                        MIIJKQIBAAKCAgEA6oR6LXzJOziUxcRryonLTM5Xkfr9cYPCKvnwsWoAHfd2MC6Q
                        OCAWSQnNcNz5RTeQUcLEaA8sxQi64zpCwO9iH8y8COCaO8u9qGkOOuJwWnmPfeLs
                        cEwALEp0LZ67eSUPsMaz533bs4C8p+2UPMd+v7Td8TkkYoqgUrfYuT0bDTMYVsSe
                        wcNB5qsI7hDLf1t5FX6KU79/Asn1K3UYHTdN83mghOlM4zh1l1CJdtgaE1jAg4Ml
                        1X8yG+cT+Ks8gCSGQfIAlVFV4fvvzmpokNKfwAI/b3LS2/ft4ZrK+RCTsWsjUu38
                        Zr8jbQMtDznzBHMw1LoaHpwRNjbJZ7uA6x5ikbwz5NAlfCITTta6xYn8qvaBfiYJ
                        YyUFl0kIHm9Kh9V9p54WPMCFCcQx12deovKV82S6zxTeMflDdosJDB/uG9dT2qPt
                        wkpTD6xAOx5h59IhfiY0j4ScTl725GygVzyK378soP3LQ/vBixQLpheALViotodH
                        fJknsrelaISNkrnapZL3QE5C1SUoaUtMG9ovRz5HDpMx5ooElEklq7shFWDhZXbp
                        2ndU5RPRCZO3Szop/Xhn2mNWQoEontFh79WIf+wS8TkJIRXhjtYBt3+s96z0iqSg
                        gDmE8BcP4lP1+TAUY1d7+QEhGCsTJa9TYtfDtNNfuYI9e3mq6LEpHYKWOvECAwEA
                        AQKCAgAlF60HaCGf50lzT6eePQCAdnEtWrMeyDCRgZTLStvCjEhk7d3LssTeP9mp
                        oe8fPomUv6c3BOds2/5LQFockABHd/y/CV9RA973NclAEQlPlhiBrb793Vd4VJJe
                        6331dveDW0+ggVdFjfVzjhqQfnE9ZcsQ2JvjpiTI0Iv2cy7F01tke0GCSMgx8W1p
                        J2jjDOxwNOKGGoIT8S4roHVJnFy3nM4sbNtyDj+zHimP4uBE8m2zSgQAP60E8sia
                        3+Ki1flnkXJRgQWCHR9cg5dkXfFRz56JmcdgxAHGWX2vD9XRuFi5nitPc6iTw8PV
                        u7GvS3+MC0oO+1pRkTAhOGv3RDK3Uqmy2zrMUuWkEsz6TVId6gPl7+biRJcP+aER
                        plJkeC9J9nSizbQPwErGByzoHGLjADgBs9hwqYkPcN38b6jR5S/VDQ+RncCyI87h
                        s/0pIs/fNlfw4LtpBrolP6g++vo6KUufmE3kRNN9dN4lNOoKjUGkcmX6MGnwxiw6
                        NN/uEqf9+CKQele1XeUhRPNJc9Gv+3Ly5y/wEi6FjfVQmCK4hNrl3tvuZw+qkGbq
                        Au9Jhk7wV81An7fbhBRIXrwOY9AbOKNqUfY+wpKi5vyJFS1yzkFaYSTKTBspkuHW
                        pWbohO+KreREwaR5HOMK8tQMTLEAeE3taXGsQMJSJ15lRrLc7QKCAQEA68TV/R8O
                        C4p+vnGJyhcfDJt6+KBKWlroBy75BG7Dg7/rUXaj+MXcqHi+whRNXMqZchSwzUfS
                        B2WK/HrOBye8JLKDeA3B5TumJaF19vV7EY/nBF2QdRmI1r33Cp+RWUvAcjKa/v2u
                        KksV3btnJKXCu/stdAyTK7nU0on4qBzm5WZxuIJv6VMHLDNPFdCk+4gM8LuJ3ITU
                        l7XuZd4gXccPNj0VTeOYiMjIwxtNmE9RpCkTLm92Z7MI+htciGk1xvV0N4m1BXwA
                        7qhl1nBgVuJyux4dEYFIeQNhLpHozkEz913QK2gDAHL9pAeiUYJntq4p8HNvfHiQ
                        vE3wTzil3aUFnwKCAQEA/qQm1Nx5By6an5UunrOvltbTMjsZSDnWspSQbX//j6mL
                        2atQLe3y/Nr7E5SGZ1kFD9tgAHTuTGVqjvTqp5dBPw4uo146K2RJwuvaYUzNK26c
                        VoGfMfsI+/bfMfjFnEmGRARZdMr8cvhU+2m04hglsSnNGxsvvPdsiIbRaVDx+JvN
                        C5C281WlN0WeVd7zNTZkdyUARNXfCxBHQPuYkP5Mz2roZeYlJMWU04i8Cx0/SEuu
                        bhZQDaNTccSdPDFYcyDDlpqp+mN+U7m+yUPOkVpaxQiSYJZ+NOQsNcAVYfjzyY0E
                        /VP3s2GddjCJs0amf9SeW0LiMAHPgTp8vbMSRPVVbwKCAQEAmZsSd+llsys2TEmY
                        pivONN6PjbCRALE9foCiCLtJcmr1m4uaZRg0HScd0UB87rmoo2TLk9L5CYyksr4n
                        wQ2oTJhpgywjaYAlTVsWiiGBXv3MW1HCLijGuHHno+o2PmFWLpC93ufUMwXcZywT
                        lRLR/rs07+jJcbGO8OSnNpAt9sN5z+Zblz5a6/c5zVK0SpRnKehld2CrSXRkr8W6
                        fJ6WUJYXbTmdRXDbLBJ7yYHUBQolzxkboZBJhvmQnec9/DQq1YxIfhw+Vz8rqjxo
                        5/J9IWALPD5owz7qb/bsIITmoIFkgQMxAXfpvJaksEov3Bs4g8oRlpzOX4C/0j1s
                        Ay3irQKCAQEAwRJ/qufcEFkCvjsj1QsS+MC785shyUSpiE/izlO91xTLx+f/7EM9
                        +QCkXK1B1zyE/Qft24rNYDmJOQl0nkuuGfxL2mzImDv7PYMM2reb3PGKMoEnzoKz
                        xi/h/YbNdnm9BvdxSH/cN+QYs2Pr1X5Pneu+622KnbHQphfq0fqg7Upchwdb4Faw
                        5Z6wthVMvK0YMcppUMgEzOOz0w6xGEbowGAkA5cj1KTG+jjzs02ivNM9V5Utb5nF
                        3D4iphAYK3rNMfTlKsejciIlCX+TMVyb9EdSjU+uM7ZJ2xtgWx+i4NA+10GCT42V
                        EZct4TORbN0ukK2+yH2m8yoAiOks0gJemwKCAQAMGROGt8O4HfhpUdOq01J2qvQL
                        m5oUXX8w1I95XcoAwCqb+dIan8UbCyl/79lbqNpQlHbRy3wlXzWwH9aHKsfPlCvk
                        5dE1qrdMdQhLXwP109bRmTiScuU4zfFgHw3XgQhMFXxNp9pze197amLws0TyuBW3
                        fupS4kM5u6HKCeBYcw2WP5ukxf8jtn29tohLBiA2A7NYtml9xTer6BBP0DTh+QUn
                        IJL6jSpuCNxBPKIK7p6tZZ0nMBEdAWMxglYm0bmHpTSd3pgu3ltCkYtDlDcTIaF0
                        Q4k44lxUTZQYwtKUVQXBe4ZvaT/jIEMS7K5bsAy7URv/toaTaiEh1hguwSmf
                        -----END RSA PRIVATE KEY-----
                    "},
                )?;
                jail.create_file(
                    "keys/key2",
                    indoc::indoc! {r"
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
                    assert!(
                        matches!(config.encryption, Encryption::File(ref p) if p == "encryption")
                    );
                    assert_eq!(
                        config.encryption().await.unwrap(),
                        [
                            0, 0, 17, 17, 34, 34, 51, 51, 68, 68, 85, 85, 102, 102, 119, 119, 136,
                            136, 153, 153, 170, 170, 187, 187, 204, 204, 221, 221, 238, 238, 255,
                            255
                        ]
                    );

                    let mut key_config = config.key_configs().await.unwrap();
                    key_config.sort_by_key(|a| {
                        if let Key::File(p) = &a.key {
                            Some(p.clone())
                        } else {
                            None
                        }
                    });
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key1"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("xmgGCzGtQFmhEOP0YAqBt-oZyVauSVMXcf4kwcgGZLc")));
                    assert!(key_config[1].kid.is_none());
                    assert!(matches!(&key_config[1].key, Key::File(p) if p == "keys/key2"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
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

    #[tokio::test]
    async fn load_config_mixed_key_sources() {
        task::spawn_blocking(|| {
            Jail::expect_with(|jail| {
                jail.create_file(
                    "config.yaml",
                    indoc::indoc! {r"
                        secrets:
                          encryption_file: encryption
                          keys_dir: keys
                          keys:
                            - kid: lekid0
                              key: |
                                -----BEGIN EC PRIVATE KEY-----
                                MHcCAQEEIOtZfDuXZr/NC0V3sisR4Chf7RZg6a2dpZesoXMlsPeRoAoGCCqGSM49
                                AwEHoUQDQgAECfpqx64lrR85MOhdMxNmIgmz8IfmM5VY9ICX9aoaArnD9FjgkBIl
                                fGmQWxxXDSWH6SQln9tROVZaduenJqDtDw==
                                -----END EC PRIVATE KEY-----
                    "},
                )?;
                jail.create_dir("keys")?;
                jail.create_file(
                    "keys/key_from_file",
                    indoc::indoc! {r"
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
                    let key_config = config.key_configs().await.unwrap();
                    let key_store = config.key_store().await.unwrap();

                    assert!(key_config[0].kid.is_none());
                    assert!(matches!(&key_config[0].key, Key::File(p) if p == "keys/key_from_file"));
                    assert!(key_store.iter().any(|k| k.kid() == Some("ONUCn80fsiISFWKrVMEiirNVr-QEvi7uQI0QH9q9q4o")));
                    assert!(key_store.iter().any(|k| k.kid() == Some("lekid0")));
                });

                Ok(())
            });
        })
        .await
        .unwrap();
    }
}
