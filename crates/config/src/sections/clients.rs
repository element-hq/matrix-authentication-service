// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::ops::Deref;

use mas_iana::oauth::OAuthClientAuthenticationMethod;
use mas_jose::jwk::PublicJsonWebKeySet;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize, de::Error};
use ulid::Ulid;
use url::Url;

use super::ConfigurationSection;

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum JwksOrJwksUri {
    Jwks(PublicJsonWebKeySet),
    JwksUri(Url),
}

impl From<PublicJsonWebKeySet> for JwksOrJwksUri {
    fn from(jwks: PublicJsonWebKeySet) -> Self {
        Self::Jwks(jwks)
    }
}

/// Authentication method used by clients
#[derive(JsonSchema, Serialize, Deserialize, Copy, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ClientAuthMethodConfig {
    /// `none`: No authentication
    None,

    /// `client_secret_basic`: `client_id` and `client_secret` used as basic
    /// authorization credentials
    ClientSecretBasic,

    /// `client_secret_post`: `client_id` and `client_secret` sent in the
    /// request body
    ClientSecretPost,

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed using the `client_secret`
    ClientSecretJwt,

    /// `client_secret_basic`: a `client_assertion` sent in the request body and
    /// signed by an asymmetric key
    PrivateKeyJwt,
}

impl std::fmt::Display for ClientAuthMethodConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientAuthMethodConfig::None => write!(f, "none"),
            ClientAuthMethodConfig::ClientSecretBasic => write!(f, "client_secret_basic"),
            ClientAuthMethodConfig::ClientSecretPost => write!(f, "client_secret_post"),
            ClientAuthMethodConfig::ClientSecretJwt => write!(f, "client_secret_jwt"),
            ClientAuthMethodConfig::PrivateKeyJwt => write!(f, "private_key_jwt"),
        }
    }
}

/// An OAuth 2.0 client configuration
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
pub struct ClientConfig {
    /// The client ID
    #[schemars(
        with = "String",
        regex(pattern = r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$"),
        description = "A ULID as per https://github.com/ulid/spec"
    )]
    pub client_id: Ulid,

    /// Authentication method used for this client
    client_auth_method: ClientAuthMethodConfig,

    /// Name of the `OAuth2` client
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,

    /// The client secret, used by the `client_secret_basic`,
    /// `client_secret_post` and `client_secret_jwt` authentication methods
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,

    /// The JSON Web Key Set (JWKS) used by the `private_key_jwt` authentication
    /// method. Mutually exclusive with `jwks_uri`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks: Option<PublicJsonWebKeySet>,

    /// The URL of the JSON Web Key Set (JWKS) used by the `private_key_jwt`
    /// authentication method. Mutually exclusive with `jwks`
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<Url>,

    /// List of allowed redirect URIs
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub redirect_uris: Vec<Url>,
}

impl ClientConfig {
    fn validate(&self) -> Result<(), Box<figment::error::Error>> {
        let auth_method = self.client_auth_method;
        match self.client_auth_method {
            ClientAuthMethodConfig::PrivateKeyJwt => {
                if self.jwks.is_none() && self.jwks_uri.is_none() {
                    let error = figment::error::Error::custom(
                        "jwks or jwks_uri is required for private_key_jwt",
                    );
                    return Err(Box::new(error.with_path("client_auth_method")));
                }

                if self.jwks.is_some() && self.jwks_uri.is_some() {
                    let error =
                        figment::error::Error::custom("jwks and jwks_uri are mutually exclusive");
                    return Err(Box::new(error.with_path("jwks")));
                }

                if self.client_secret.is_some() {
                    let error = figment::error::Error::custom(
                        "client_secret is not allowed with private_key_jwt",
                    );
                    return Err(Box::new(error.with_path("client_secret")));
                }
            }

            ClientAuthMethodConfig::ClientSecretPost
            | ClientAuthMethodConfig::ClientSecretBasic
            | ClientAuthMethodConfig::ClientSecretJwt => {
                if self.client_secret.is_none() {
                    let error = figment::error::Error::custom(format!(
                        "client_secret is required for {auth_method}"
                    ));
                    return Err(Box::new(error.with_path("client_auth_method")));
                }

                if self.jwks.is_some() {
                    let error = figment::error::Error::custom(format!(
                        "jwks is not allowed with {auth_method}"
                    ));
                    return Err(Box::new(error.with_path("jwks")));
                }

                if self.jwks_uri.is_some() {
                    let error = figment::error::Error::custom(format!(
                        "jwks_uri is not allowed with {auth_method}"
                    ));
                    return Err(Box::new(error.with_path("jwks_uri")));
                }
            }

            ClientAuthMethodConfig::None => {
                if self.client_secret.is_some() {
                    let error = figment::error::Error::custom(
                        "client_secret is not allowed with none authentication method",
                    );
                    return Err(Box::new(error.with_path("client_secret")));
                }

                if self.jwks.is_some() {
                    let error = figment::error::Error::custom(
                        "jwks is not allowed with none authentication method",
                    );
                    return Err(Box::new(error));
                }

                if self.jwks_uri.is_some() {
                    let error = figment::error::Error::custom(
                        "jwks_uri is not allowed with none authentication method",
                    );
                    return Err(Box::new(error));
                }
            }
        }

        Ok(())
    }

    /// Authentication method used for this client
    #[must_use]
    pub fn client_auth_method(&self) -> OAuthClientAuthenticationMethod {
        match self.client_auth_method {
            ClientAuthMethodConfig::None => OAuthClientAuthenticationMethod::None,
            ClientAuthMethodConfig::ClientSecretBasic => {
                OAuthClientAuthenticationMethod::ClientSecretBasic
            }
            ClientAuthMethodConfig::ClientSecretPost => {
                OAuthClientAuthenticationMethod::ClientSecretPost
            }
            ClientAuthMethodConfig::ClientSecretJwt => {
                OAuthClientAuthenticationMethod::ClientSecretJwt
            }
            ClientAuthMethodConfig::PrivateKeyJwt => OAuthClientAuthenticationMethod::PrivateKeyJwt,
        }
    }
}

/// List of OAuth 2.0/OIDC clients config
#[derive(Debug, Clone, Default, Serialize, Deserialize, JsonSchema)]
#[serde(transparent)]
pub struct ClientsConfig(#[schemars(with = "Vec::<ClientConfig>")] Vec<ClientConfig>);

impl ClientsConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        self.0.is_empty()
    }
}

impl Deref for ClientsConfig {
    type Target = Vec<ClientConfig>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl IntoIterator for ClientsConfig {
    type Item = ClientConfig;
    type IntoIter = std::vec::IntoIter<ClientConfig>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl ConfigurationSection for ClientsConfig {
    const PATH: Option<&'static str> = Some("clients");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        for (index, client) in self.0.iter().enumerate() {
            client.validate().map_err(|mut err| {
                // Save the error location information in the error
                err.metadata = figment.find_metadata(Self::PATH.unwrap()).cloned();
                err.profile = Some(figment::Profile::Default);
                err.path.insert(0, Self::PATH.unwrap().to_owned());
                err.path.insert(1, format!("{index}"));
                err
            })?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use figment::{
        Figment, Jail,
        providers::{Format, Yaml},
    };

    use super::*;

    #[test]
    fn load_config() {
        Jail::expect_with(|jail| {
            jail.create_file(
                "config.yaml",
                r#"
                  clients:
                    - client_id: 01GFWR28C4KNE04WG3HKXB7C9R
                      client_auth_method: none
                      redirect_uris:
                        - https://exemple.fr/callback

                    - client_id: 01GFWR32NCQ12B8Z0J8CPXRRB6
                      client_auth_method: client_secret_basic
                      client_secret: hello

                    - client_id: 01GFWR3WHR93Y5HK389H28VHZ9
                      client_auth_method: client_secret_post
                      client_secret: hello

                    - client_id: 01GFWR43R2ZZ8HX9CVBNW9TJWG
                      client_auth_method: client_secret_jwt
                      client_secret: hello

                    - client_id: 01GFWR4BNFDCC4QDG6AMSP1VRR
                      client_auth_method: private_key_jwt
                      jwks:
                        keys:
                        - kid: "03e84aed4ef4431014e8617567864c4efaaaede9"
                          kty: "RSA"
                          alg: "RS256"
                          use: "sig"
                          e: "AQAB"
                          n: "ma2uRyBeSEOatGuDpCiV9oIxlDWix_KypDYuhQfEzqi_BiF4fV266OWfyjcABbam59aJMNvOnKW3u_eZM-PhMCBij5MZ-vcBJ4GfxDJeKSn-GP_dJ09rpDcILh8HaWAnPmMoi4DC0nrfE241wPISvZaaZnGHkOrfN_EnA5DligLgVUbrA5rJhQ1aSEQO_gf1raEOW3DZ_ACU3qhtgO0ZBG3a5h7BPiRs2sXqb2UCmBBgwyvYLDebnpE7AotF6_xBIlR-Cykdap3GHVMXhrIpvU195HF30ZoBU4dMd-AeG6HgRt4Cqy1moGoDgMQfbmQ48Hlunv9_Vi2e2CLvYECcBw"

                        - kid: "d01c1abe249269f72ef7ca2613a86c9f05e59567"
                          kty: "RSA"
                          alg: "RS256"
                          use: "sig"
                          e: "AQAB"
                          n: "0hukqytPwrj1RbMYhYoepCi3CN5k7DwYkTe_Cmb7cP9_qv4ok78KdvFXt5AnQxCRwBD7-qTNkkfMWO2RxUMBdQD0ED6tsSb1n5dp0XY8dSWiBDCX8f6Hr-KolOpvMLZKRy01HdAWcM6RoL9ikbjYHUEW1C8IJnw3MzVHkpKFDL354aptdNLaAdTCBvKzU9WpXo10g-5ctzSlWWjQuecLMQ4G1mNdsR1LHhUENEnOvgT8cDkX0fJzLbEbyBYkdMgKggyVPEB1bg6evG4fTKawgnf0IDSPxIU-wdS9wdSP9ZCJJPLi5CEp-6t6rE_sb2dGcnzjCGlembC57VwpkUvyMw"
                "#,
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<ClientsConfig>("clients")?;

            assert_eq!(config.0.len(), 5);

            assert_eq!(
                config.0[0].client_id,
                Ulid::from_str("01GFWR28C4KNE04WG3HKXB7C9R").unwrap()
            );
            assert_eq!(
                config.0[0].redirect_uris,
                vec!["https://exemple.fr/callback".parse().unwrap()]
            );

            assert_eq!(
                config.0[1].client_id,
                Ulid::from_str("01GFWR32NCQ12B8Z0J8CPXRRB6").unwrap()
            );
            assert_eq!(config.0[1].redirect_uris, Vec::new());

            Ok(())
        });
    }
}
