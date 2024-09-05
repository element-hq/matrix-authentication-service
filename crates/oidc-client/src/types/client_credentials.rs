// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 Kévin Commaille.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Types and methods for client credentials.

use std::{collections::HashMap, fmt, sync::Arc};

use base64ct::{Base64UrlUnpadded, Encoding};
use chrono::{DateTime, Duration, Utc};
use headers::{Authorization, HeaderMapExt};
use http::Request;
use mas_iana::{jose::JsonWebSignatureAlg, oauth::OAuthClientAuthenticationMethod};
#[cfg(feature = "keystore")]
use mas_jose::constraints::Constrainable;
use mas_jose::{
    claims::{self, ClaimError},
    jwa::SymmetricKey,
    jwt::{JsonWebSignatureHeader, Jwt},
};
#[cfg(feature = "keystore")]
use mas_keystore::Keystore;
use rand::Rng;
use serde::Serialize;
use serde_json::Value;
use serde_with::skip_serializing_none;
use tower::BoxError;
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

/// A function that takes a map of claims and a signing algorithm and returns a
/// signed JWT.
pub type JwtSigningFn =
    dyn Fn(HashMap<String, Value>, JsonWebSignatureAlg) -> Result<String, BoxError> + Send + Sync;

/// The method used to sign JWTs with a private key.
#[derive(Clone)]
pub enum JwtSigningMethod {
    /// Sign the JWTs with this library, by providing the signing keys.
    #[cfg(feature = "keystore")]
    Keystore(Keystore),

    /// Sign the JWTs in a callback.
    Custom(Arc<JwtSigningFn>),
}

impl JwtSigningMethod {
    /// Creates a new [`JwtSigningMethod`] from a [`Keystore`].
    #[cfg(feature = "keystore")]
    #[must_use]
    pub fn with_keystore(keystore: Keystore) -> Self {
        Self::Keystore(keystore)
    }

    /// Creates a new [`JwtSigningMethod`] from a [`JwtSigningFn`].
    #[must_use]
    pub fn with_custom_signing_method<F>(signing_fn: F) -> Self
    where
        F: Fn(HashMap<String, Value>, JsonWebSignatureAlg) -> Result<String, BoxError>
            + Send
            + Sync
            + 'static,
    {
        Self::Custom(Arc::new(signing_fn))
    }

    /// Get the [`Keystore`] from this [`JwtSigningMethod`].
    #[cfg(feature = "keystore")]
    #[must_use]
    pub fn keystore(&self) -> Option<&Keystore> {
        match self {
            JwtSigningMethod::Keystore(k) => Some(k),
            JwtSigningMethod::Custom(_) => None,
        }
    }

    /// Get the [`JwtSigningFn`] from this [`JwtSigningMethod`].
    #[must_use]
    pub fn jwt_custom(&self) -> Option<&JwtSigningFn> {
        match self {
            JwtSigningMethod::Custom(s) => Some(s.as_ref()),
            #[cfg(feature = "keystore")]
            JwtSigningMethod::Keystore(_) => None,
        }
    }
}

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

        /// The method used to sign the JWT.
        jwt_signing_method: JwtSigningMethod,

        /// The algorithm used to sign the JWT.
        signing_algorithm: JsonWebSignatureAlg,

        /// The URL of the issuer's Token endpoint.
        token_endpoint: Url,
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
            | ClientCredentials::PrivateKeyJwt { client_id, .. } => client_id,
        }
    }

    /// Apply these `ClientCredentials` to the given request.
    pub(crate) fn apply_to_request<T: Serialize>(
        self,
        request: Request<T>,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Result<Request<RequestWithClientCredentials<T>>, CredentialsError> {
        let credentials = RequestClientCredentials::try_from_credentials(self, now, rng)?;

        let (parts, body) = request.into_parts();
        let mut body = RequestWithClientCredentials {
            body,
            credentials: None,
        };

        let request = match credentials {
            RequestClientCredentials::Body(credentials) => {
                body.credentials = Some(credentials);
                Request::from_parts(parts, body)
            }
            RequestClientCredentials::Header(credentials) => {
                let HeaderClientCredentials {
                    client_id,
                    client_secret,
                } = credentials;

                let mut request = Request::from_parts(parts, body);

                // Encode the values with `application/x-www-form-urlencoded`.
                let client_id =
                    form_urlencoded::byte_serialize(client_id.as_bytes()).collect::<String>();
                let client_secret =
                    form_urlencoded::byte_serialize(client_secret.as_bytes()).collect::<String>();

                let auth = Authorization::basic(&client_id, &client_secret);
                request.headers_mut().typed_insert(auth);

                request
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
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")]
pub(crate) struct JwtBearerClientAssertionType;

enum RequestClientCredentials {
    Body(BodyClientCredentials),
    Header(HeaderClientCredentials),
}

impl RequestClientCredentials {
    fn try_from_credentials(
        credentials: ClientCredentials,
        now: DateTime<Utc>,
        rng: &mut impl Rng,
    ) -> Result<Self, CredentialsError> {
        let res = match credentials {
            ClientCredentials::None { client_id } => Self::Body(BodyClientCredentials {
                client_id,
                client_secret: None,
                client_assertion: None,
                client_assertion_type: None,
            }),
            ClientCredentials::ClientSecretBasic {
                client_id,
                client_secret,
            } => Self::Header(HeaderClientCredentials {
                client_id,
                client_secret,
            }),
            ClientCredentials::ClientSecretPost {
                client_id,
                client_secret,
            } => Self::Body(BodyClientCredentials {
                client_id,
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
                let key = SymmetricKey::new_for_alg(client_secret.into(), &signing_algorithm)?;
                let header = JsonWebSignatureHeader::new(signing_algorithm);

                let jwt = Jwt::sign(header, claims, &key)?;

                Self::Body(BodyClientCredentials {
                    client_id,
                    client_secret: None,
                    client_assertion: Some(jwt.to_string()),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }
            ClientCredentials::PrivateKeyJwt {
                client_id,
                jwt_signing_method,
                signing_algorithm,
                token_endpoint,
            } => {
                let claims =
                    prepare_claims(client_id.clone(), token_endpoint.to_string(), now, rng)?;

                let client_assertion = match jwt_signing_method {
                    #[cfg(feature = "keystore")]
                    JwtSigningMethod::Keystore(keystore) => {
                        let key = keystore
                            .signing_key_for_algorithm(&signing_algorithm)
                            .ok_or(CredentialsError::NoPrivateKeyFound)?;
                        let signer = key
                            .params()
                            .signing_key_for_alg(&signing_algorithm)
                            .map_err(|_| CredentialsError::JwtWrongAlgorithm)?;
                        let mut header = JsonWebSignatureHeader::new(signing_algorithm);

                        if let Some(kid) = key.kid() {
                            header = header.with_kid(kid);
                        }

                        Jwt::sign(header, claims, &signer)?.to_string()
                    }
                    JwtSigningMethod::Custom(jwt_signing_fn) => {
                        jwt_signing_fn(claims, signing_algorithm)
                            .map_err(CredentialsError::Custom)?
                    }
                };

                Self::Body(BodyClientCredentials {
                    client_id,
                    client_secret: None,
                    client_assertion: Some(client_assertion),
                    client_assertion_type: Some(JwtBearerClientAssertionType),
                })
            }
        };

        Ok(res)
    }
}

#[allow(clippy::struct_field_names)] // All the fields start with `client_`
#[skip_serializing_none]
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct BodyClientCredentials {
    client_id: String,
    client_secret: Option<String>,
    client_assertion: Option<String>,
    client_assertion_type: Option<JwtBearerClientAssertionType>,
}

#[derive(Debug, Clone)]
struct HeaderClientCredentials {
    client_id: String,
    client_secret: String,
}

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
#[skip_serializing_none]
pub struct RequestWithClientCredentials<T> {
    #[serde(flatten)]
    pub(crate) body: T,
    #[serde(flatten)]
    pub(crate) credentials: Option<BodyClientCredentials>,
}

#[cfg(test)]
mod test {
    use assert_matches::assert_matches;
    use headers::authorization::Basic;
    #[cfg(feature = "keystore")]
    use mas_keystore::{JsonWebKey, JsonWebKeySet, Keystore, PrivateKey};
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    use super::*;

    const CLIENT_ID: &str = "abcd$++";
    const CLIENT_SECRET: &str = "xyz!;?";
    const REQUEST_BODY: &str = "some_body";

    #[derive(Serialize)]
    struct Body {
        body: &'static str,
    }

    fn now() -> DateTime<Utc> {
        #[allow(clippy::disallowed_methods)]
        Utc::now()
    }

    #[test]
    fn serialize_credentials() {
        assert_eq!(
            serde_urlencoded::to_string(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_assertion: None,
                client_assertion_type: None,
            })
            .unwrap(),
            "client_id=abcd%24%2B%2B"
        );
        assert_eq!(
            serde_urlencoded::to_string(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                client_assertion: None,
                client_assertion_type: None,
            })
            .unwrap(),
            "client_id=abcd%24%2B%2B&client_secret=xyz%21%3B%3F"
        );
        assert_eq!(
            serde_urlencoded::to_string(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_assertion: Some(CLIENT_SECRET.to_owned()),
                client_assertion_type: Some(JwtBearerClientAssertionType)
            })
            .unwrap(),
            "client_id=abcd%24%2B%2B&client_assertion=xyz%21%3B%3F&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        );
    }

    #[test]
    fn serialize_request_with_credentials() {
        let req = RequestWithClientCredentials {
            body: Body { body: REQUEST_BODY },
            credentials: None,
        };
        assert_eq!(serde_urlencoded::to_string(req).unwrap(), "body=some_body");

        let req = RequestWithClientCredentials {
            body: Body { body: REQUEST_BODY },
            credentials: Some(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_assertion: None,
                client_assertion_type: None,
            }),
        };
        assert_eq!(
            serde_urlencoded::to_string(req).unwrap(),
            "body=some_body&client_id=abcd%24%2B%2B"
        );

        let req = RequestWithClientCredentials {
            body: Body { body: REQUEST_BODY },
            credentials: Some(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: Some(CLIENT_SECRET.to_owned()),
                client_assertion: None,
                client_assertion_type: None,
            }),
        };
        assert_eq!(
            serde_urlencoded::to_string(req).unwrap(),
            "body=some_body&client_id=abcd%24%2B%2B&client_secret=xyz%21%3B%3F"
        );

        let req = RequestWithClientCredentials {
            body: Body { body: REQUEST_BODY },
            credentials: Some(BodyClientCredentials {
                client_id: CLIENT_ID.to_owned(),
                client_secret: None,
                client_assertion: Some(CLIENT_SECRET.to_owned()),
                client_assertion_type: Some(JwtBearerClientAssertionType),
            }),
        };
        assert_eq!(
            serde_urlencoded::to_string(req).unwrap(),
            "body=some_body&client_id=abcd%24%2B%2B&client_assertion=xyz%21%3B%3F&client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer"
        );
    }

    #[tokio::test]
    async fn build_request_none() {
        let credentials = ClientCredentials::None {
            client_id: CLIENT_ID.to_owned(),
        };
        let request = Request::new(Body { body: REQUEST_BODY });
        let now = now();
        let mut rng = ChaCha8Rng::seed_from_u64(42);
        let request = credentials
            .apply_to_request(request, now, &mut rng)
            .unwrap();

        assert_eq!(request.headers().typed_get::<Authorization<Basic>>(), None);

        let body = request.into_body();
        assert_eq!(body.body.body, REQUEST_BODY);

        let credentials = body.credentials.unwrap();
        assert_eq!(credentials.client_id, CLIENT_ID);
        assert_eq!(credentials.client_secret, None);
        assert_eq!(credentials.client_assertion, None);
        assert_eq!(credentials.client_assertion_type, None);
    }

    #[tokio::test]
    async fn build_request_client_secret_basic() {
        let credentials = ClientCredentials::ClientSecretBasic {
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
        };
        let now = now();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let request = Request::new(Body { body: REQUEST_BODY });
        let request = credentials
            .apply_to_request(request, now, &mut rng)
            .unwrap();

        let auth = assert_matches!(
            request.headers().typed_get::<Authorization<Basic>>(),
            Some(auth) => auth
        );
        assert_eq!(
            form_urlencoded::parse(auth.username().as_bytes())
                .next()
                .unwrap()
                .0,
            CLIENT_ID
        );
        assert_eq!(
            form_urlencoded::parse(auth.password().as_bytes())
                .next()
                .unwrap()
                .0,
            CLIENT_SECRET
        );

        let body = request.into_body();
        assert_eq!(body.body.body, REQUEST_BODY);
        assert_eq!(body.credentials, None);
    }

    #[tokio::test]
    async fn build_request_client_secret_post() {
        let credentials = ClientCredentials::ClientSecretPost {
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
        };
        let now = now();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let request = Request::new(Body { body: REQUEST_BODY });
        let request = credentials
            .apply_to_request(request, now, &mut rng)
            .unwrap();

        assert_eq!(request.headers().typed_get::<Authorization<Basic>>(), None);

        let body = request.into_body();
        assert_eq!(body.body.body, REQUEST_BODY);

        let credentials = body.credentials.unwrap();
        assert_eq!(credentials.client_id, CLIENT_ID);
        assert_eq!(credentials.client_secret.unwrap(), CLIENT_SECRET);
        assert_eq!(credentials.client_assertion, None);
        assert_eq!(credentials.client_assertion_type, None);
    }

    #[tokio::test]
    async fn build_request_client_secret_jwt() {
        let credentials = ClientCredentials::ClientSecretJwt {
            client_id: CLIENT_ID.to_owned(),
            client_secret: CLIENT_SECRET.to_owned(),
            signing_algorithm: JsonWebSignatureAlg::Hs256,
            token_endpoint: Url::parse("http://localhost").unwrap(),
        };
        let now = now();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let request = Request::new(Body { body: REQUEST_BODY });
        let request = credentials
            .apply_to_request(request, now, &mut rng)
            .unwrap();

        assert_eq!(request.headers().typed_get::<Authorization<Basic>>(), None);

        let body = request.into_body();
        assert_eq!(body.body.body, REQUEST_BODY);

        let credentials = body.credentials.unwrap();
        assert_eq!(credentials.client_id, CLIENT_ID);
        assert_eq!(credentials.client_secret, None);
        credentials.client_assertion.unwrap();
        credentials.client_assertion_type.unwrap();
    }

    #[tokio::test]
    #[cfg(feature = "keystore")]
    async fn build_request_private_key_jwt() {
        let rng = rand_chacha::ChaCha8Rng::seed_from_u64(42);
        let key = PrivateKey::generate_rsa(rng).unwrap();
        let keystore = Keystore::new(JsonWebKeySet::<PrivateKey>::new(vec![JsonWebKey::new(key)]));
        let jwt_signing_method = JwtSigningMethod::with_keystore(keystore);
        let now = now();
        let mut rng = ChaCha8Rng::seed_from_u64(42);

        let credentials = ClientCredentials::PrivateKeyJwt {
            client_id: CLIENT_ID.to_owned(),
            jwt_signing_method,
            signing_algorithm: JsonWebSignatureAlg::Rs256,
            token_endpoint: Url::parse("http://localhost").unwrap(),
        };

        let request = Request::new(Body { body: REQUEST_BODY });
        let request = credentials
            .apply_to_request(request, now, &mut rng)
            .unwrap();

        assert_eq!(request.headers().typed_get::<Authorization<Basic>>(), None);

        let body = request.into_body();
        assert_eq!(body.body.body, REQUEST_BODY);

        let credentials = body.credentials.unwrap();
        assert_eq!(credentials.client_id, CLIENT_ID);
        assert_eq!(credentials.client_secret, None);
        credentials.client_assertion.unwrap();
        credentials.client_assertion_type.unwrap();
    }
}
