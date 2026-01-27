// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{num::NonZeroU32, time::Duration};

use camino::Utf8PathBuf;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

use super::ConfigurationSection;
use crate::schema;

#[allow(clippy::unnecessary_wraps)]
fn default_connection_string() -> Option<String> {
    Some("postgresql://".to_owned())
}

fn default_max_connections() -> NonZeroU32 {
    NonZeroU32::new(10).unwrap()
}

fn default_connect_timeout() -> Duration {
    Duration::from_secs(30)
}

#[allow(clippy::unnecessary_wraps)]
fn default_idle_timeout() -> Option<Duration> {
    Some(Duration::from_secs(10 * 60))
}

#[allow(clippy::unnecessary_wraps)]
fn default_max_lifetime() -> Option<Duration> {
    Some(Duration::from_secs(30 * 60))
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            uri: default_connection_string(),
            host: None,
            port: None,
            socket: None,
            username: None,
            password: None,
            password_file: None,
            database: None,
            ssl_mode: None,
            ssl_ca: None,
            ssl_ca_file: None,
            ssl_certificate: None,
            ssl_certificate_file: None,
            ssl_key: None,
            ssl_key_file: None,
            max_connections: default_max_connections(),
            min_connections: Default::default(),
            connect_timeout: default_connect_timeout(),
            idle_timeout: default_idle_timeout(),
            max_lifetime: default_max_lifetime(),
        }
    }
}

/// Options for controlling the level of protection provided for PostgreSQL SSL
/// connections.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "kebab-case")]
pub enum PgSslMode {
    /// Only try a non-SSL connection.
    Disable,

    /// First try a non-SSL connection; if that fails, try an SSL connection.
    Allow,

    /// First try an SSL connection; if that fails, try a non-SSL connection.
    Prefer,

    /// Only try an SSL connection. If a root CA file is present, verify the
    /// connection in the same way as if `VerifyCa` was specified.
    Require,

    /// Only try an SSL connection, and verify that the server certificate is
    /// issued by a trusted certificate authority (CA).
    VerifyCa,

    /// Only try an SSL connection; verify that the server certificate is issued
    /// by a trusted CA and that the requested server host name matches that
    /// in the certificate.
    VerifyFull,
}

/// Database connection configuration
#[serde_as]
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct DatabaseConfig {
    /// Connection URI
    ///
    /// This must not be specified if `host`, `port`, `socket`, `username`,
    /// `password`, or `database` are specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(url, default = "default_connection_string")]
    pub uri: Option<String>,

    /// Name of host to connect to
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option::<schema::Hostname>")]
    pub host: Option<String>,

    /// Port number to connect at the server host
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: Option<u16>,

    /// Directory containing the UNIX socket to connect to
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub socket: Option<Utf8PathBuf>,

    /// PostgreSQL user name to connect as
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    /// Password to be used if the server demands password authentication
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    /// Path to the password to be used if the server demands password
    /// authentication
    ///
    /// This must not be specified if the `password` or `uri` option is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub password_file: Option<Utf8PathBuf>,

    /// The database name
    ///
    /// This must not be specified if `uri` is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub database: Option<String>,

    /// How to handle SSL connections
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_mode: Option<PgSslMode>,

    /// The PEM-encoded root certificate for SSL connections
    ///
    /// This must not be specified if the `ssl_ca_file` option is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_ca: Option<String>,

    /// Path to the root certificate for SSL connections
    ///
    /// This must not be specified if the `ssl_ca` option is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_ca_file: Option<Utf8PathBuf>,

    /// The PEM-encoded client certificate for SSL connections
    ///
    /// This must not be specified if the `ssl_certificate_file` option is
    /// specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_certificate: Option<String>,

    /// Path to the client certificate for SSL connections
    ///
    /// This must not be specified if the `ssl_certificate` option is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_certificate_file: Option<Utf8PathBuf>,

    /// The PEM-encoded client key for SSL connections
    ///
    /// This must not be specified if the `ssl_key_file` option is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssl_key: Option<String>,

    /// Path to the client key for SSL connections
    ///
    /// This must not be specified if the `ssl_key` option is specified.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[schemars(with = "Option<String>")]
    pub ssl_key_file: Option<Utf8PathBuf>,

    /// Set the maximum number of connections the pool should maintain
    #[serde(default = "default_max_connections")]
    pub max_connections: NonZeroU32,

    /// Set the minimum number of connections the pool should maintain
    #[serde(default)]
    pub min_connections: u32,

    /// Set the amount of time to attempt connecting to the database
    #[schemars(with = "u64")]
    #[serde(default = "default_connect_timeout")]
    #[serde_as(as = "serde_with::DurationSeconds<u64>")]
    pub connect_timeout: Duration,

    /// Set a maximum idle duration for individual connections
    #[schemars(with = "Option<u64>")]
    #[serde(
        default = "default_idle_timeout",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub idle_timeout: Option<Duration>,

    /// Set the maximum lifetime of individual connections
    #[schemars(with = "u64")]
    #[serde(
        default = "default_max_lifetime",
        skip_serializing_if = "Option::is_none"
    )]
    #[serde_as(as = "Option<serde_with::DurationSeconds<u64>>")]
    pub max_lifetime: Option<Duration>,
}

impl ConfigurationSection for DatabaseConfig {
    const PATH: Option<&'static str> = Some("database");

    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        let metadata = figment.find_metadata(Self::PATH.unwrap());
        let annotate = |mut error: figment::Error| {
            error.metadata = metadata.cloned();
            error.profile = Some(figment::Profile::Default);
            error.path = vec![Self::PATH.unwrap().to_owned()];
            error
        };

        // Check that the user did not specify both `uri` and the split options at the
        // same time
        let has_split_options = self.host.is_some()
            || self.port.is_some()
            || self.socket.is_some()
            || self.username.is_some()
            || self.password.is_some()
            || self.password_file.is_some()
            || self.database.is_some();

        if self.uri.is_some() && has_split_options {
            return Err(annotate(figment::error::Error::from(
                "uri must not be specified if host, port, socket, username, password, password_file, or database are specified".to_owned(),
            )).into());
        }

        if self.password.is_some() && self.password_file.is_some() {
            return Err(annotate(figment::error::Error::from(
                "password must not be specified if password_file is specified".to_owned(),
            ))
            .into());
        }

        if self.ssl_ca.is_some() && self.ssl_ca_file.is_some() {
            return Err(annotate(figment::error::Error::from(
                "ssl_ca must not be specified if ssl_ca_file is specified".to_owned(),
            ))
            .into());
        }

        if self.ssl_certificate.is_some() && self.ssl_certificate_file.is_some() {
            return Err(annotate(figment::error::Error::from(
                "ssl_certificate must not be specified if ssl_certificate_file is specified"
                    .to_owned(),
            ))
            .into());
        }

        if self.ssl_key.is_some() && self.ssl_key_file.is_some() {
            return Err(annotate(figment::error::Error::from(
                "ssl_key must not be specified if ssl_key_file is specified".to_owned(),
            ))
            .into());
        }

        if (self.ssl_key.is_some() || self.ssl_key_file.is_some())
            ^ (self.ssl_certificate.is_some() || self.ssl_certificate_file.is_some())
        {
            return Err(annotate(figment::error::Error::from(
                "both a ssl_certificate and a ssl_key must be set at the same time or none of them"
                    .to_owned(),
            ))
            .into());
        }

        Ok(())
    }
}
#[cfg(test)]
mod tests {
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
                r"
                    database:
                      uri: postgresql://user:password@host/database
                ",
            )?;

            let config = Figment::new()
                .merge(Yaml::file("config.yaml"))
                .extract_inner::<DatabaseConfig>("database")?;

            assert_eq!(
                config.uri.as_deref(),
                Some("postgresql://user:password@host/database")
            );

            Ok(())
        });
    }
}
