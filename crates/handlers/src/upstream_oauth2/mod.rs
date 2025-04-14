// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::string::FromUtf8Error;

use camino::Utf8PathBuf;
use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderTokenAuthMethod};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_keystore::{DecryptError, Encrypter, Keystore};
use mas_oidc_client::types::client_credentials::ClientCredentials;
use pkcs8::DecodePrivateKey;
use schemars::JsonSchema;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub(crate) mod authorize;
pub(crate) mod cache;
pub(crate) mod callback;
mod cookie;
pub(crate) mod link;
mod template;

use self::cookie::UpstreamSessions as UpstreamSessionsCookie;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
enum ProviderCredentialsError {
    #[error("Provider doesn't have a client secret")]
    MissingClientSecret,

    #[error("Duplicate private key and private key file for Sign in with Apple")]
    DuplicatePrivateKey,

    #[error("Missing private key for signing the id_token")]
    MissingPrivateKey,

    #[error("Could not decrypt client secret")]
    DecryptClientSecret {
        #[from]
        inner: DecryptError,
    },

    #[error("Client secret is invalid")]
    InvalidClientSecret {
        #[from]
        inner: FromUtf8Error,
    },

    #[error("Invalid JSON in client secret")]
    InvalidClientSecretJson {
        #[from]
        inner: serde_json::Error,
    },

    #[error("Could not parse PEM encoded private key")]
    InvalidPrivateKey {
        #[from]
        inner: pkcs8::Error,
    },
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SignInWithApple {
    /// The private key file used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub private_key_file: Option<Utf8PathBuf>,

    /// The private key used to sign the `id_token`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<String>,

    /// The Team ID of the Apple Developer Portal
    pub team_id: String,

    /// The key ID of the Apple Developer Portal
    pub key_id: String,
}

async fn client_credentials_for_provider(
    provider: &UpstreamOAuthProvider,
    token_endpoint: &Url,
    keystore: &Keystore,
    encrypter: &Encrypter,
) -> Result<ClientCredentials, ProviderCredentialsError> {
    let client_id = provider.client_id.clone();

    let client_secret = provider
        .encrypted_client_secret
        .as_deref()
        .map(|encrypted_client_secret| {
            let decrypted = encrypter.decrypt_string(encrypted_client_secret)?;
            let decrypted = String::from_utf8(decrypted)?;
            Ok::<_, ProviderCredentialsError>(decrypted)
        })
        .transpose()?;

    let client_credentials = match provider.token_endpoint_auth_method {
        UpstreamOAuthProviderTokenAuthMethod::None => ClientCredentials::None { client_id },

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretPost => {
            ClientCredentials::ClientSecretPost {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretBasic => {
            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::ClientSecretJwt => {
            ClientCredentials::ClientSecretJwt {
                client_id,
                client_secret: client_secret
                    .ok_or(ProviderCredentialsError::MissingClientSecret)?,
                signing_algorithm: provider
                    .token_endpoint_signing_alg
                    .clone()
                    .unwrap_or(JsonWebSignatureAlg::Rs256),
                token_endpoint: token_endpoint.clone(),
            }
        }

        UpstreamOAuthProviderTokenAuthMethod::PrivateKeyJwt => ClientCredentials::PrivateKeyJwt {
            client_id,
            keystore: keystore.clone(),
            signing_algorithm: provider
                .token_endpoint_signing_alg
                .clone()
                .unwrap_or(JsonWebSignatureAlg::Rs256),
            token_endpoint: token_endpoint.clone(),
        },

        UpstreamOAuthProviderTokenAuthMethod::SignInWithApple => {
            let client_secret =
                client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?;

            let params: SignInWithApple = serde_json::from_str(&client_secret)
                .map_err(|inner| ProviderCredentialsError::InvalidClientSecretJson { inner })?;

            if params.private_key.is_none() && params.private_key_file.is_none() {
                return Err(ProviderCredentialsError::MissingPrivateKey);
            }

            if params.private_key.is_some() && params.private_key_file.is_some() {
                return Err(ProviderCredentialsError::DuplicatePrivateKey);
            }

            let private_key_pem = if let Some(private_key) = params.private_key {
                private_key
            } else if let Some(private_key_file) = params.private_key_file {
                tokio::fs::read_to_string(private_key_file)
                    .await
                    .map_err(|_| ProviderCredentialsError::MissingPrivateKey)?
            } else {
                unreachable!("already validated above")
            };

            let key = elliptic_curve::SecretKey::from_pkcs8_pem(&private_key_pem)
                .map_err(|inner| ProviderCredentialsError::InvalidPrivateKey { inner })?;

            ClientCredentials::SignInWithApple {
                client_id,
                key,
                key_id: params.key_id,
                team_id: params.team_id,
            }
        }
    };

    Ok(client_credentials)
}
