// Copyright 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![allow(deprecated)]

use std::borrow::Cow;

use anyhow::bail;
use camino::Utf8PathBuf;
use ipnetwork::IpNetwork;
use mas_keystore::PrivateKey;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, pem::PemObject};
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
    /// Listen on the given host and port combination
    Listen {
        /// Host on which to listen, defaults to all addresses
        #[serde(skip_serializing_if = "Option::is_none")]
        #[schemars(example = &"localhost")]
        host: Option<String>,

        /// Port on which to listen
        #[schemars(example = &8081u16)]
        port: u16,
    },

    /// Listen on the given address
    Address {
        /// Host and port on which to listen
        #[schemars(
            example = &"[::]:8080",
            example = &"[::1]:8080",
            example = &"127.0.0.1:8080",
            example = &"0.0.0.0:8080",
        )]
        address: String,
    },

    /// Listen on the given UNIX socket
    Unix {
        /// Path to the socket
        #[schemars(with = "String", example = &"/tmp/mas.sock")]
        socket: Utf8PathBuf,
    },

    /// Grab an already open file descriptor given by the parent process.
    ///
    /// This is useful when using systemd socket activation.
    ///
    /// The file descriptor index is offset by 3, to account for the standard
    /// input, output and error streams, so a value of `0` grabs the file
    /// descriptor `3`.
    ///
    /// See <https://www.freedesktop.org/software/systemd/man/sd_listen_fds.html>
    FileDescriptor {
        /// Index of the file descriptor to grab
        #[serde(default)]
        #[schemars(example = &1usize)]
        fd: usize,

        /// Kind of socket that was passed, defaults to tcp
        #[serde(default = "UnixOrTcp::tcp")]
        #[schemars(example = &UnixOrTcp::Tcp)]
        kind: UnixOrTcp,
    },
}

/// Configuration related to TLS on a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct TlsConfig {
    /// Inline PEM-encoded X509 certificate chain (alternative to
    /// `certificate_file`)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"<inline PEM>", extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub certificate: Option<String>,

    /// Path to a file containing the PEM-encoded X509 certificate chain
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>", example = &"/path/to/cert.pem")]
    pub certificate_file: Option<Utf8PathBuf>,

    /// Inline PEM-encoded private key (alternative to `key_file`)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"<inline PEM>", extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub key: Option<String>,

    /// Path to a file containing a PEM or DER-encoded private key
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>", example = &"/path/to/key.pem")]
    pub key_file: Option<Utf8PathBuf>,

    /// Inline password used to decrypt the private key, if it is encrypted
    /// (alternative to `password_file`)
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"<password to decrypt the key>", extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub password: Option<String>,

    /// Path to a file containing the password used to decrypt the private key
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>", example = &"/path/to/password.txt", extend("x-doc" = serde_json::json!({ "commented": true })))]
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

        let certificate_chain = CertificateDer::pem_slice_iter(certificate_chain_pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()?;

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
    /// Serves the health check endpoint on `/health`
    Health,

    /// Serves a Prometheus-compatible metrics endpoint on `/metrics`, if the
    /// Prometheus exporter is enabled in `telemetry.metrics.exporter`
    Prometheus,

    /// Serves the `.well-known/openid-configuration` document
    Discovery,

    /// Serves the human-facing pages, such as the login page
    Human,

    /// Serves the GraphQL API used by the frontend, and optionally the GraphQL
    /// playground
    GraphQL {
        /// Enable the GraphQL playground
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        #[schemars(example = &true)]
        playground: bool,

        /// Allow access for OAuth 2.0 clients (undocumented)
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        #[schemars(extend("x-doc" = serde_json::json!({ "skip": true })))]
        undocumented_oauth2_access: bool,
    },

    /// Serves the OAuth 2.0/OIDC endpoints
    OAuth,

    /// Serves the Matrix C-S API compatibility endpoints
    Compat,

    /// Serves the given folder on the `/assets/` path
    Assets {
        /// Path to the directory to serve
        #[serde(
            default = "http_listener_assets_path_default",
            skip_serializing_if = "is_default_http_listener_assets_path"
        )]
        #[schemars(with = "String", example = &"./share/assets/")]
        path: Utf8PathBuf,
    },

    /// Serves the admin API on the `/api/admin/v1/` path. Disabled by default
    AdminApi,

    /// Mounts a `/connection-info` handler which shows debugging information
    /// about the upstream connection
    #[serde(rename = "connection-info")]
    ConnectionInfo,
}

/// Configuration of a listener
#[derive(Debug, Serialize, Deserialize, JsonSchema, Clone)]
pub struct ListenerConfig {
    /// The name of the listener, used in logs and metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"web")]
    pub name: Option<String>,

    /// List of resources to serve
    pub resources: Vec<Resource>,

    /// Optional URL prefix to mount all the resources of this listener under
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"/auth", extend("x-doc" = serde_json::json!({ "commented": true })))]
    pub prefix: Option<String>,

    /// List of addresses and ports to listen to
    pub binds: Vec<BindConfig>,

    /// Whether to enable the PROXY protocol on the listener
    #[serde(default)]
    #[schemars(example = &false)]
    pub proxy_protocol: bool,

    /// If set, makes the listener use TLS with the provided certificate and key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,
}

/// Controls the web server.
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct HttpConfig {
    /// Each listener can serve multiple resources, and listen on multiple TCP
    /// ports or UNIX sockets.
    ///
    /// <!-- more -->
    ///
    /// The following additional resources are available, although it is
    /// recommended to serve them on a separate listener, not exposed to the
    /// public internet:
    ///
    /// - `name: prometheus`: serves a Prometheus-compatible metrics endpoint on
    ///   `/metrics`, if the Prometheus exporter is enabled in
    ///   `telemetry.metrics.exporter`.
    /// - `name: health`: serves the health check endpoint on `/health`.
    #[serde(default)]
    pub listeners: Vec<ListenerConfig>,

    /// List of trusted reverse proxies that are allowed to set the
    /// `X-Forwarded-For` header.
    ///
    /// Defaults to the usual private IP ranges:
    ///   192.168.0.0/16, 172.16.0.0/12, 10.0.0.0/8, 127.0.0.0/8,
    ///   fd00::/8 and ::1/128
    #[expect(
        clippy::doc_markdown,
        reason = "the IPv6 ranges are shown verbatim in the rendered config reference"
    )]
    #[serde(default = "default_trusted_proxies")]
    #[schemars(
        with = "Vec<String>",
        inner(ip),
        example = &["192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8", "127.0.0.0/8", "fd00::/8", "::1/128"],
        extend("x-doc" = serde_json::json!({ "commented": true }))
    )]
    pub trusted_proxies: Vec<IpNetwork>,

    /// Public URL base used when building absolute public URLs
    #[schemars(example = &"https://auth.example.com/")]
    pub public_base: Url,

    /// OIDC issuer advertised by the service. Defaults to `public_base`
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(example = &"https://example.com/")]
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

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
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
                error
            };

            if listener.resources.is_empty() {
                return Err(
                    annotate(figment::Error::from("listener has no resources".to_owned())).into(),
                );
            }

            if listener.binds.is_empty() {
                return Err(annotate(figment::Error::from(
                    "listener does not bind to any address".to_owned(),
                ))
                .into());
            }

            if let Some(tls_config) = &listener.tls {
                if tls_config.certificate.is_some() && tls_config.certificate_file.is_some() {
                    return Err(annotate(figment::Error::from(
                        "Only one of `certificate` or `certificate_file` can be set at a time"
                            .to_owned(),
                    ))
                    .into());
                }

                if tls_config.certificate.is_none() && tls_config.certificate_file.is_none() {
                    return Err(annotate(figment::Error::from(
                        "TLS configuration is missing a certificate".to_owned(),
                    ))
                    .into());
                }

                if tls_config.key.is_some() && tls_config.key_file.is_some() {
                    return Err(annotate(figment::Error::from(
                        "Only one of `key` or `key_file` can be set at a time".to_owned(),
                    ))
                    .into());
                }

                if tls_config.key.is_none() && tls_config.key_file.is_none() {
                    return Err(annotate(figment::Error::from(
                        "TLS configuration is missing a private key".to_owned(),
                    ))
                    .into());
                }

                if tls_config.password.is_some() && tls_config.password_file.is_some() {
                    return Err(annotate(figment::Error::from(
                        "Only one of `password` or `password_file` can be set at a time".to_owned(),
                    ))
                    .into());
                }
            }
        }

        Ok(())
    }
}
