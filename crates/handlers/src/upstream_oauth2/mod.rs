// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::string::FromUtf8Error;

use mas_data_model::{UpstreamOAuthProvider, UpstreamOAuthProviderTokenAuthMethod};
use mas_iana::jose::JsonWebSignatureAlg;
use mas_keystore::{DecryptError, Encrypter, Keystore};
use mas_oidc_client::types::client_credentials::ClientCredentials;
use pkcs8::DecodePrivateKey;
use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub(crate) mod authorize;
pub(crate) mod cache;
pub(crate) mod callback;
mod cookie;
pub(crate) mod link;
pub(crate) mod logout;
mod template;

use self::cookie::UpstreamSessions as UpstreamSessionsCookie;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
enum ProviderCredentialsError {
    #[error("Provider doesn't have a client secret")]
    MissingClientSecret,

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

#[derive(Debug, Deserialize)]
pub struct SignInWithApple {
    pub private_key: String,
    pub team_id: String,
    pub key_id: String,
}

fn client_credentials_for_provider(
    provider: &UpstreamOAuthProvider,
    token_endpoint: &Url,
    keystore: &Keystore,
    encrypter: &Encrypter,
) -> Result<ClientCredentials, ProviderCredentialsError> {
    let client_id = provider.client_id.clone();

    // Decrypt the client secret
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
            let params = client_secret.ok_or(ProviderCredentialsError::MissingClientSecret)?;
            let params: SignInWithApple = serde_json::from_str(&params)?;

            let key = elliptic_curve::SecretKey::from_pkcs8_pem(&params.private_key)?;

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
