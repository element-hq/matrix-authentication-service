// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![allow(deprecated)]

use std::{borrow::Cow, io::Cursor};

use anyhow::bail;
use camino::Utf8PathBuf;
use ipnetwork::IpNetwork;
use mas_keystore::PrivateKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use url::Url;

use super::ConfigurationSection;

fn default_public_base() -> Url {
    "http://[::]:8080".parse().unwrap()
}

#[cfg(not(any(feature = "docker", feature = "dist")))]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "./frontend/dist/".into()
}

#[cfg(feature = "docker")]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "/usr/local/share/mas-cli/assets/".into()
}

#[cfg(feature = "dist")]
fn http_listener_assets_path_default() -> Utf8PathBuf {
    "./share/assets/".into()
}

fn is_default_http_listener_assets_path(value: &Utf8PathBuf) -> bool {
    *value == http_listener_assets_path_default()
}

fn default_trusted_proxies() -> Vec<IpNetwork> {
    vec![
        IpNetwork::new([192, 168, 0, 0].into(), 16).unwrap(),
        IpNetwork::new([172, 16, 0, 0].into(), 12).unwrap(),
        IpNetwork::new([10, 0, 0, 0].into(), 10).unwrap(),
        IpNetwork::new(std::net::Ipv4Addr::LOCALHOST.into(), 8).unwrap(),
        IpNetwork::new([0xfd00, 0, 0, 0, 0, 0, 0, 0].into(), 8).unwrap(),
        IpNetwork::new(std::net::Ipv6Addr::LOCALHOST.into(), 128).unwrap(),
    ]
}

/// Kind of socket
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone, Copy)]
#[serde(rename_all = "lowercase")]
pub enum UnixOrTcp {
    /// UNIX domain socket
    Unix,

    /// TCP socket
    Tcp,
}

impl UnixOrTcp {
    /// UNIX domain socket
    #[must_use]
    pub const fn unix() -> Self {
        Self::Unix
    }

    /// TCP socket
    #[must_use]
    pub const fn tcp() -> Self {
        Self::Tcp
    }
}

/// Configuration of a single listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(untagged)]
pub enum BindConfig {
    /// Listen on the specified host and port
    Listen {
        /// Host on which to listen.
        ///
        /// Defaults to listening on all addresses
        #[serde(skip_serializing_if = "Option::is_none")]
        host: Option<String>,

        /// Port on which to listen.
        port: u16,
    },

    /// Listen on the specified address
    Address {
        /// Host and port on which to listen
        #[schemars(
            example = &"[::1]:8080",
            example = &"[::]:8080",
            example = &"127.0.0.1:8080",
            example = &"0.0.0.0:8080",
        )]
        address: String,
    },

    /// Listen on a UNIX domain socket
    Unix {
        /// Path to the socket
        #[schemars(with = "String")]
        socket: Utf8PathBuf,
    },

    /// Accept connections on file descriptors passed by the parent process.
    ///
    /// This is useful for grabbing sockets passed by systemd.
    ///
    /// See <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
    FileDescriptor {
        /// Index of the file descriptor. Note that this is offseted by 3
        /// because of the standard input/output sockets, so setting
        /// here a value of `0` will grab the file descriptor `3`
        #[serde(default)]
        fd: usize,

        /// Whether the socket is a TCP socket or a UNIX domain socket. Defaults
        /// to TCP.
        #[serde(default = "UnixOrTcp::tcp")]
        kind: UnixOrTcp,
    },
}

/// Configuration related to TLS on a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TlsConfig {
    /// PEM-encoded X509 certificate chain
    ///
    /// Exactly one of `certificate` or `certificate_file` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,

    /// File containing the PEM-encoded X509 certificate chain
    ///
    /// Exactly one of `certificate` or `certificate_file` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub certificate_file: Option<Utf8PathBuf>,

    /// PEM-encoded private key
    ///
    /// Exactly one of `key` or `key_file` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// File containing a PEM or DER-encoded private key
    ///
    /// Exactly one of `key` or `key_file` must be set.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub key_file: Option<Utf8PathBuf>,

    /// Password used to decode the private key
    ///
    /// One of `password` or `password_file` must be set if the key is
    /// encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Password file used to decode the private key
    ///
    /// One of `password` or `password_file` must be set if the key is
    /// encrypted.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub password_file: Option<Utf8PathBuf>,
}

impl TlsConfig {
    /// Load the TLS certificate chain and key file from disk
    ///
    /// # Errors
    ///
    /// Returns an error if an error was encountered either while:
    ///   - reading the certificate, key or password files
    ///   - decoding the key as PEM or DER
    ///   - decrypting the key if encrypted
    ///   - a password was provided but the key was not encrypted
    ///   - decoding the certificate chain as PEM
    ///   - the certificate chain is empty
    pub fn load(
        &self,
    ) -> Result<(PrivateKeyDer<'static>, Vec<CertificateDer<'static>>), anyhow::Error> {
        let password = match (&self.password, &self.password_file) {
            (None, None) => None,
            (Some(_), Some(_)) => {
                bail!("Only one of `password` or `password_file` can be set at a time")
            }
            (Some(password), None) => Some(Cow::Borrowed(password)),
            (None, Some(path)) => Some(Cow::Owned(std::fs::read_to_string(path)?)),
        };

        // Read the key either embedded in the config file or on disk
        let key = match (&self.key, &self.key_file) {
            (None, None) => bail!("Either `key` or `key_file` must be set"),
            (Some(_), Some(_)) => bail!("Only one of `key` or `key_file` can be set at a time"),
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
                let key = std::fs::read(path)?;
                if let Some(password) = password {
                    PrivateKey::load_encrypted(&key, password.as_bytes())?
                } else {
                    PrivateKey::load(&key)?
                }
            }
        };

        // Re-serialize the key to PKCS#8 DER, so rustls can consume it
        let key = key.to_pkcs8_der()?;
        let key = PrivatePkcs8KeyDer::from(key.to_vec()).into();

        let certificate_chain_pem = match (&self.certificate, &self.certificate_file) {
            (None, None) => bail!("Either `certificate` or `certificate_file` must be set"),
            (Some(_), Some(_)) => {
                bail!("Only one of `certificate` or `certificate_file` can be set at a time")
            }
            (Some(certificate), None) => Cow::Borrowed(certificate),
            (None, Some(path)) => Cow::Owned(std::fs::read_to_string(path)?),
        };

        let mut certificate_chain_reader = Cursor::new(certificate_chain_pem.as_bytes());
        let certificate_chain: Result<Vec<_>, _> =
            rustls_pemfile::certs(&mut certificate_chain_reader).collect();
        let certificate_chain = certificate_chain?;

        if certificate_chain.is_empty() {
            bail!("TLS certificate chain is empty (or invalid)")
        }

        Ok((key, certificate_chain))
    }
}

/// HTTP resources to mount
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
#[serde(tag = "name", rename_all = "lowercase")]
pub enum Resource {
    /// Healthcheck endpoint (/health)
    Health,

    /// Prometheus metrics endpoint (/metrics)
    Prometheus,

    /// OIDC discovery endpoints
    Discovery,

    /// Pages destined to be viewed by humans
    Human,

    /// GraphQL endpoint
    GraphQL {
        /// Enabled the GraphQL playground
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        playground: bool,

        /// Allow access for OAuth 2.0 clients (undocumented)
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        undocumented_oauth2_access: bool,
    },

    /// OAuth-related APIs
    OAuth,

    /// Matrix compatibility API
    Compat,

    /// Static files
    Assets {
        /// Path to the directory to serve.
        #[serde(
            default = "http_listener_assets_path_default",
            skip_serializing_if = "is_default_http_listener_assets_path"
        )]
        #[schemars(with = "String")]
        path: Utf8PathBuf,
    },

    /// Admin API, served at `/api/admin/v1`
    AdminApi,

    /// Mount a "/connection-info" handler which helps debugging informations on
    /// the upstream connection
    #[serde(rename = "connection-info")]
    ConnectionInfo,
}

/// Configuration of a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListenerConfig {
    /// A unique name for this listener which will be shown in traces and in
    /// metrics labels
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// List of resources to mount
    pub resources: Vec<Resource>,

    /// HTTP prefix to mount the resources on
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,

    /// List of sockets to bind
    pub binds: Vec<BindConfig>,

    /// Accept `HAProxy`'s Proxy Protocol V1
    #[serde(default)]
    pub proxy_protocol: bool,

    /// If set, makes the listener use TLS with the provided certificate and key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

/// Configuration related to the web server
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// List of listeners to run
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// List of trusted reverse proxies that can set the `X-Forwarded-For`
    /// header
    #[serde(default = "default_trusted_proxies")]
    #[schemars(with = "Vec<String>", inner(ip))]
    pub trusted_proxies: Vec<IpNetwork>,

    /// Public URL base from where the authentication service is reachable
    pub public_base: Url,

    /// OIDC issuer URL. Defaults to `public_base` if not set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<Url>,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            listeners: vec![
                ListenerConfig {
                    name: Some("web".to_owned()),
                    resources: vec![
                        Resource::Discovery,
                        Resource::Human,
                        Resource::OAuth,
                        Resource::Compat,
                        Resource::GraphQL {
                            playground: false,
                            undocumented_oauth2_access: false,
                        },
                        Resource::Assets {
                            path: http_listener_assets_path_default(),
                        },
                    ],
                    prefix: None,
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Address {
                        address: "[::]:8080".into(),
                    }],
                },
                ListenerConfig {
                    name: Some("internal".to_owned()),
                    resources: vec![Resource::Health],
                    prefix: None,
                    tls: None,
                    proxy_protocol: false,
                    binds: vec![BindConfig::Listen {
                        host: Some("localhost".to_owned()),
                        port: 8081,
                    }],
                },
            ],
            trusted_proxies: default_trusted_proxies(),
            issuer: Some(default_public_base()),
            public_base: default_public_base(),
        }
    }
}

impl ConfigurationSection for HttpConfig {
    const PATH: Option<&'static str> = Some("http");

    fn validate(&self, figment: &figment::Figment) -> Result<(), figment::Error> {
        for (index, listener) in self.listeners.iter().enumerate() {
            let annotate = |mut error: figment::Error| {
                error.metadata = figment
                    .find_metadata(&format!("{root}.listeners", root = Self::PATH.unwrap()))
                    .cloned();
                error.profile = Some(figment::Profile::Default);
                error.path = vec![
                    Self::PATH.unwrap().to_owned(),
                    "listeners".to_owned(),
                    index.to_string(),
                ];
                Err(error)
            };

            if listener.resources.is_empty() {
                return annotate(figment::Error::from("listener has no resources".to_owned()));
            }

            if listener.binds.is_empty() {
                return annotate(figment::Error::from(
                    "listener does not bind to any address".to_owned(),
                ));
            }

            if let Some(tls_config) = &listener.tls {
                if tls_config.certificate.is_some() && tls_config.certificate_file.is_some() {
                    return annotate(figment::Error::from(
                        "Only one of `certificate` or `certificate_file` can be set at a time"
                            .to_owned(),
                    ));
                }

                if tls_config.certificate.is_none() && tls_config.certificate_file.is_none() {
                    return annotate(figment::Error::from(
                        "TLS configuration is missing a certificate".to_owned(),
                    ));
                }

                if tls_config.key.is_some() && tls_config.key_file.is_some() {
                    return annotate(figment::Error::from(
                        "Only one of `key` or `key_file` can be set at a time".to_owned(),
                    ));
                }

                if tls_config.key.is_none() && tls_config.key_file.is_none() {
                    return annotate(figment::Error::from(
                        "TLS configuration is missing a private key".to_owned(),
                    ));
                }

                if tls_config.password.is_some() && tls_config.password_file.is_some() {
                    return annotate(figment::Error::from(
                        "Only one of `password` or `password_file` can be set at a time".to_owned(),
                    ));
                }
            }
        }

        Ok(())
    }
}
