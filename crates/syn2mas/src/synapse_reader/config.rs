// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use figment::providers::{Format, Yaml};
use serde::Deserialize;
use sqlx::postgres::PgConnectOptions;

/// The root of a Synapse configuration.
/// This struct only includes fields which the Synapse-to-MAS migration is
/// interested in.
///
/// See: <https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html>
#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub database: DatabaseSection,

    #[serde(default)]
    pub password_config: PasswordSection,

    #[serde(default)]
    pub allow_guest_access: bool,

    #[serde(default)]
    pub enable_registration: bool,

    #[serde(default)]
    pub enable_registration_captcha: bool,

    /// Normally this defaults to true, but when MAS integration is enabled in
    /// Synapse it defaults to false.
    #[serde(default)]
    pub enable_3pid_changes: bool,

    #[serde(default)]
    pub user_consent: Option<UserConsentSection>,

    #[serde(default)]
    pub registrations_require_3pid: Vec<String>,

    #[serde(default)]
    pub registration_requires_token: bool,

    pub registration_shared_secret: Option<String>,

    #[serde(default)]
    pub login_via_existing_session: EnableableSection,

    #[serde(default)]
    pub cas_config: EnableableSection,

    #[serde(default)]
    pub saml2_config: EnableableSection,

    #[serde(default)]
    pub jwt_config: EnableableSection,

    #[serde(default)]
    pub oidc_config: Option<OidcProvider>,

    #[serde(default)]
    pub oidc_providers: Vec<OidcProvider>,

    pub server_name: String,
}

impl Config {
    /// Load a Synapse configuration from the given list of configuration files.
    ///
    /// # Errors
    ///
    /// - If there is a problem reading any of the files.
    /// - If the configuration is not valid.
    pub fn load(files: &[Utf8PathBuf]) -> Result<Config, figment::Error> {
        let mut figment = figment::Figment::new();
        for file in files {
            // TODO this is not exactly correct behaviour — Synapse does not merge anything
            // other than the top level dict.
            // https://github.com/element-hq/matrix-authentication-service/pull/3805#discussion_r1922680825
            // https://github.com/element-hq/synapse/blob/develop/synapse/config/_base.py?rgh-link-date=2025-01-20T17%3A02%3A56Z#L870
            figment = figment.merge(Yaml::file(file));
        }
        figment.extract::<Config>()
    }

    /// Returns a map of all OIDC providers from the Synapse configuration.
    ///
    /// The keys are the `auth_provider` IDs as they would have been stored in
    /// Synapse's database.
    ///
    /// These are compatible with the `synapse_idp_id` field of
    /// [`mas_config::UpstreamOAuth2Provider`].
    #[must_use]
    pub fn all_oidc_providers(&self) -> BTreeMap<String, OidcProvider> {
        let mut out = BTreeMap::new();

        if let Some(provider) = &self.oidc_config {
            if provider.issuer.is_some() {
                // The legacy configuration has an implied IdP ID of `oidc`.
                out.insert("oidc".to_owned(), provider.clone());
            }
        }

        for provider in &self.oidc_providers {
            if let Some(idp_id) = &provider.idp_id {
                // Synapse internally prefixes the IdP IDs with `oidc-`.
                out.insert(format!("oidc-{idp_id}"), provider.clone());
            }
        }

        out
    }
}

/// The `database` section of the Synapse configuration.
///
/// See: <https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html#database>
#[derive(Deserialize)]
pub struct DatabaseSection {
    /// Expecting `psycopg2` for Postgres or `sqlite3` for `SQLite3`, but may be
    /// an arbitrary string and future versions of Synapse may support other
    /// database drivers, e.g. psycopg3.
    pub name: String,
    #[serde(default)]
    pub args: DatabaseArgsSuboption,
}

/// The database driver name for Synapse when it is using Postgres via psycopg2.
pub const SYNAPSE_DATABASE_DRIVER_NAME_PSYCOPG2: &str = "psycopg2";
/// The database driver name for Synapse when it is using SQLite 3.
pub const SYNAPSE_DATABASE_DRIVER_NAME_SQLITE3: &str = "sqlite3";

impl DatabaseSection {
    /// Process the configuration into Postgres connection options.
    ///
    /// Environment variables and libpq defaults will be used as fallback for
    /// any missing values; this should match what Synapse does.
    /// But note that if syn2mas is not run in the same context (host, user,
    /// environment variables) as Synapse normally runs, then the connection
    /// options may not be valid.
    ///
    /// Returns `None` if this database configuration is not configured for
    /// Postgres.
    #[must_use]
    pub fn to_sqlx_postgres(&self) -> Option<PgConnectOptions> {
        if self.name != SYNAPSE_DATABASE_DRIVER_NAME_PSYCOPG2 {
            return None;
        }
        let mut opts = PgConnectOptions::new().application_name("syn2mas-synapse");

        if let Some(host) = &self.args.host {
            opts = opts.host(host);
        }
        if let Some(port) = self.args.port {
            opts = opts.port(port);
        }
        if let Some(dbname) = &self.args.dbname {
            opts = opts.database(dbname);
        }
        if let Some(user) = &self.args.user {
            opts = opts.username(user);
        }
        if let Some(password) = &self.args.password {
            opts = opts.password(password);
        }

        Some(opts)
    }
}

/// The `args` suboption of the `database` section of the Synapse configuration.
/// This struct assumes Postgres is in use and does not represent fields used by
/// SQLite.
#[derive(Deserialize, Default)]
pub struct DatabaseArgsSuboption {
    pub user: Option<String>,
    pub password: Option<String>,
    pub dbname: Option<String>,
    pub host: Option<String>,
    pub port: Option<u16>,
}

/// The `password_config` section of the Synapse configuration.
///
/// See: <https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html#password_config>
#[derive(Deserialize)]
pub struct PasswordSection {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub localdb_enabled: bool,
    pub pepper: Option<String>,
}

impl Default for PasswordSection {
    fn default() -> Self {
        PasswordSection {
            enabled: true,
            localdb_enabled: true,
            pepper: None,
        }
    }
}

/// A section that we only care about whether it's enabled or not, but is not
/// enabled by default.
#[derive(Default, Deserialize)]
pub struct EnableableSection {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Deserialize)]
pub struct OidcProvider {
    /// At least for `oidc_config`, if the dict is present but left empty then
    /// the config should be ignored, so this field must be optional.
    pub issuer: Option<String>,

    /// Required, except for the old `oidc_config` where this is implied to be
    /// "oidc".
    pub idp_id: Option<String>,
}

fn default_true() -> bool {
    true
}

#[cfg(test)]
mod test {
    use sqlx::postgres::PgConnectOptions;

    use super::{DatabaseArgsSuboption, DatabaseSection};

    #[test]
    fn test_to_sqlx_postgres() {
        #[track_caller]
        #[allow(clippy::needless_pass_by_value)]
        fn assert_eq_options(config: DatabaseSection, uri: &str) {
            let config_connect_options = config
                .to_sqlx_postgres()
                .expect("no connection options generated by config");
            let uri_connect_options: PgConnectOptions = uri
                .parse()
                .expect("example URI did not parse as PgConnectionOptions");

            assert_eq!(
                config_connect_options.get_host(),
                uri_connect_options.get_host()
            );
            assert_eq!(
                config_connect_options.get_port(),
                uri_connect_options.get_port()
            );
            assert_eq!(
                config_connect_options.get_username(),
                uri_connect_options.get_username()
            );
            // The password is not public so we can't assert it. But that's hopefully fine.
            assert_eq!(
                config_connect_options.get_database(),
                uri_connect_options.get_database()
            );
        }

        // SQLite configs are not accepted
        assert!(
            DatabaseSection {
                name: "sqlite3".to_owned(),
                args: DatabaseArgsSuboption::default(),
            }
            .to_sqlx_postgres()
            .is_none()
        );

        assert_eq_options(
            DatabaseSection {
                name: "psycopg2".to_owned(),
                args: DatabaseArgsSuboption::default(),
            },
            "postgresql:///",
        );
        assert_eq_options(
            DatabaseSection {
                name: "psycopg2".to_owned(),
                args: DatabaseArgsSuboption {
                    user: Some("synapse_user".to_owned()),
                    password: Some("verysecret".to_owned()),
                    dbname: Some("synapse_db".to_owned()),
                    host: Some("synapse-db.example.com".to_owned()),
                    port: Some(42),
                },
            },
            "postgresql://synapse_user:verysecret@synapse-db.example.com:42/synapse_db",
        );
    }
}

/// We don't care about any of the fields in this section,
/// just whether it's present.
#[derive(Deserialize)]
pub struct UserConsentSection {}
