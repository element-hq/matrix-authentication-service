// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Types and methods for client credentials.

use std::{collections::HashMap, fmt};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
use mas_jose::{
    claims::{self, ClaimError},
    constraints::Constrainable,
    jwa::{AsymmetricSigningKey, SymmetricKey},
    jwt::{JsonWebSignatureHeader, Jwt},
};
use mas_keystore::Keystore;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use url::Url;

use crate::error::CredentialsError;

/// The supported authentication methods of this library.
///
/// During client registration, make sure that you only use one of the values
/// defined here.
pub const CLIENT_SUPPORTED_AUTH_METHODS: &[OAuthClientAuthenticationMethod] = &[
    OAuthClientAuthenticationMethod::None,
    OAuthClientAuthenticationMethod::ClientSecretBasic,
    OAuthClientAuthenticationMethod::ClientSecretPost,
    OAuthClientAuthenticationMethod::ClientSecretJwt,
    OAuthClientAuthenticationMethod::PrivateKeyJwt,
];

/// The credentials obtained during registration, to authenticate a client on
/// endpoints that require it.
#[derive(Clone)]
pub enum ClientCredentials {
    /// No client authentication is used.
    ///
    /// This is used if the client is public.
    None {
        /// The unique ID for the client.
        client_id: String,
    },

    /// The client authentication is sent via the Authorization HTTP header.
    ClientSecretBasic {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,
    },

    /// The client authentication is sent with the body of the request.
    ClientSecretPost {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,
    },

    /// The client authentication uses a JWT signed with a key derived from the
    /// client secret.
    ClientSecretJwt {
        /// The unique ID for the client.
        client_id: String,

        /// The secret of the client.
        client_secret: String,

        /// The algorithm used to sign the JWT.
        signing_algorithm: JsonWebSignatureAlg,

        /// The URL of the issuer's Token endpoint.
        token_endpoint: Url,
    },

    /// The client authentication uses a JWT signed with a private key.
    PrivateKeyJwt {
        /// The unique ID for the client.
        client_id: String,

        /// The keystore used to sign the JWT
        keystore: Keystore,

        /// The algorithm used to sign the JWT.
        signing_algorithm: JsonWebSignatureAlg,

        /// The URL of the issuer's Token endpoint.
        token_endpoint: Url,
    },

    /// The client authenticates like Sign in with Apple wants
    SignInWithApple {
        /// The unique ID for the client.
        client_id: String,

        /// The ECDSA key used to sign
        key: elliptic_curve::SecretKey<p256::NistP256>,

        /// The key ID
        key_id: String,

        /// The Apple Team ID
        team_id: String,
    },
}

impl ClientCredentials {
    /// Get the client ID of these `ClientCredentials`.
    #[must_use]
    pub fn client_id(&self) -> &str {
        match self {
            ClientCredentials::None { client_id }
            | ClientCredentials::ClientSecretBasic { client_id, .. }
            | ClientCredentials::ClientSecretPost { client_id, .. }
            | ClientCredentials::ClientSecretJwt { client_id, .. }
            | ClientCredentials::PrivateKeyJwt { client_id, .. }
            | ClientCredentials::SignInWithApple { client_id, .. } => client_id,
        }
    }

    /// Apply these [`ClientCredentials`] to the given request with the given
    /// form.
    pub(crate) fn authenticated_form<T: Serialize>(
        &self,
        request: reqwest::RequestBuilder,
        form: &T,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Result<reqwest::RequestBuilder, CredentialsError> {
        let request = match self {
            ClientCredentials::None { client_id } => request.form(&RequestWithClientCredentials {
                body: form,
                client_id: Some(client_id),
                client_secret: None,
                client_assertion: None,
                client_assertion_type: None,
            }),

            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret,
            } => {
                let username =
                    form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
                let password =
                    form_urlencoded::byte_serialize(client_secret.as_bytes()).collect::<String>();
                request
                    .basic_auth(username, Some(password))
                    .form(&RequestWithClientCredentials {
                        body: form,
                        client_id: None,
                        client_secret: None,
                        client_assertion: None,
                        client_assertion_type: None,
                    })
            }

            ClientCredentials::ClientSecretPost {
                client_id,
                client_secret,
            } => request.form(&RequestWithClientCredentials {
                body: form,
                client_id: Some(client_id),
                client_secret: Some(client_secret),
                client_assertion: None,
                client_assertion_type: None,
            }),

            ClientCredentials::ClientSecretJwt {
                client_id,
                client_secret,
                signing_algorithm,
                token_endpoint,
            } => {
                let claims =
                    prepare_claims(client_id.clone(), token_endpoint.to_string(), now, rng)?;
                let key = SymmetricKey::new_for_alg(
                    client_secret.as_bytes().to_vec(),
                    signing_algorithm,
                )?;
                let header = JsonWebSignatureHeader::new(signing_algorithm.clone());

                let jwt = Jwt::sign(header, claims, &key)?;

                request.form(&RequestWithClientCredentials {
                    body: form,
                    client_id: None,
                    client_secret: None,
                    client_assertion: Some(jwt.as_str()),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }

            ClientCredentials::PrivateKeyJwt {
                client_id,
                keystore,
                signing_algorithm,
                token_endpoint,
            } => {
                let claims =
                    prepare_claims(client_id.clone(), token_endpoint.to_string(), now, rng)?;

                let key = keystore
                    .signing_key_for_algorithm(signing_algorithm)
                    .ok_or(CredentialsError::NoPrivateKeyFound)?;
                let signer = key
                    .params()
                    .signing_key_for_alg(signing_algorithm)
                    .map_err(|_| CredentialsError::JwtWrongAlgorithm)?;
                let mut header = JsonWebSignatureHeader::new(signing_algorithm.clone());

                if let Some(kid) = key.kid() {
                    header = header.with_kid(kid);
                }

                let client_assertion = Jwt::sign(header, claims, &signer)?;

                request.form(&RequestWithClientCredentials {
                    body: form,
                    client_id: None,
                    client_secret: None,
                    client_assertion: Some(client_assertion.as_str()),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }

            ClientCredentials::SignInWithApple {
                client_id,
                key,
                key_id,
                team_id,
            } => {
                // SIWA expects a signed JWT as client secret
                // https://developer.apple.com/documentation/accountorganizationaldatasharing/creating-a-client-secret
                let signer = AsymmetricSigningKey::es256(key.clone());

                let mut claims = HashMap::new();

                claims::ISS.insert(&mut claims, team_id)?;
                claims::SUB.insert(&mut claims, client_id)?;
                claims::AUD.insert(&mut claims, "https://appleid.apple.com".to_owned())?;
                claims::IAT.insert(&mut claims, now)?;
                claims::EXP.insert(&mut claims, now + Duration::microseconds(60 * 1000 * 1000))?;

                let header =
                    JsonWebSignatureHeader::new(JsonWebSignatureAlg::Es256).with_kid(key_id);

                let client_secret = Jwt::sign(header, claims, &signer)?;

                request.form(&RequestWithClientCredentials {
                    body: form,
                    client_id: Some(client_id),
                    client_secret: Some(client_secret.as_str()),
                    client_assertion: None,
                    client_assertion_type: None,
                })
            }
        };

        Ok(request)
    }
}

impl fmt::Debug for ClientCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None { client_id } => f
                .debug_struct("None")
                .field("client_id", client_id)
                .finish(),
            Self::ClientSecretBasic { client_id, .. } => f
                .debug_struct("ClientSecretBasic")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::ClientSecretPost { client_id, .. } => f
                .debug_struct("ClientSecretPost")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::ClientSecretJwt {
                client_id,
                signing_algorithm,
                token_endpoint,
                ..
            } => f
                .debug_struct("ClientSecretJwt")
                .field("client_id", client_id)
                .field("signing_algorithm", signing_algorithm)
                .field("token_endpoint", token_endpoint)
                .finish_non_exhaustive(),
            Self::PrivateKeyJwt {
                client_id,
                signing_algorithm,
                token_endpoint,
                ..
            } => f
                .debug_struct("PrivateKeyJwt")
                .field("client_id", client_id)
                .field("signing_algorithm", signing_algorithm)
                .field("token_endpoint", token_endpoint)
                .finish_non_exhaustive(),
            Self::SignInWithApple {
                client_id,
                key_id,
                team_id,
                ..
            } => f
                .debug_struct("SignInWithApple")
                .field("client_id", client_id)
                .field("key_id", key_id)
                .field("team_id", team_id)
                .finish_non_exhaustive(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
struct JwtBearerClientAssertionType;

fn prepare_claims(
    iss: String,
    aud: String,
    now: DateTime<Utc>,
    rng: &mut impl Rng,
) -> Result<HashMap<String, Value>, ClaimError> {
    let mut claims = HashMap::new();

    claims::ISS.insert(&mut claims, iss.clone())?;
    claims::SUB.insert(&mut claims, iss)?;
    claims::AUD.insert(&mut claims, aud)?;
    claims::IAT.insert(&mut claims, now)?;
    claims::EXP.insert(
        &mut claims,
        now + Duration::microseconds(5 * 60 * 1000 * 1000),
    )?;

    let mut jti = [0u8; 16];
    rng.fill(&mut jti);
    let jti = Base64UrlUnpadded::encode_string(&jti);
    claims::JTI.insert(&mut claims, jti)?;

    Ok(claims)
}

/// A request with client credentials added to it.
#[derive(Clone, Serialize)]
struct RequestWithClientCredentials<'a, T> {
    #[serde(flatten)]
    body: T,

    #[serde(skip_serializing_if = "Option::is_none")]
    client_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_secret: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_assertion_type: Option<JwtBearerClientAssertionType>,
}
