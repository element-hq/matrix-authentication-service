// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod oidc;

use std::collections::BTreeMap;

use camino::Utf8PathBuf;
use chrono::{DateTime, Utc};
use figment::providers::{Format, Yaml};
use mas_config::{PasswordAlgorithm, PasswordHashingScheme};
use rand::Rng;
use serde::Deserialize;
use sqlx::postgres::PgConnectOptions;
use tracing::warn;
use url::Url;

pub use self::oidc::OidcProvider;

/// The root of a Synapse configuration.
/// This struct only includes fields which the Synapse-to-MAS migration is
/// interested in.
///
/// See: <https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html>
#[derive(Deserialize)]
#[expect(clippy::struct_excessive_bools)]
pub struct Config {
    pub database: DatabaseSection,

    #[serde(default)]
    pub password_config: PasswordSection,

    pub bcrypt_rounds: Option<u32>,

    #[serde(default)]
    pub allow_guest_access: bool,

    #[serde(default)]
    pub enable_registration: bool,

    #[serde(default)]
    pub enable_registration_captcha: bool,
    pub recaptcha_public_key: Option<String>,
    pub recaptcha_private_key: Option<String>,

    /// Normally this defaults to true, but when MAS integration is enabled in
    /// Synapse it defaults to false.
    #[serde(default)]
    pub enable_3pid_changes: Option<bool>,

    #[serde(default = "default_true")]
    enable_set_display_name: bool,

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

    pub public_baseurl: Option<Url>,
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
            if provider.has_required_fields() {
                let mut provider = provider.clone();
                // The legacy configuration has an implied IdP ID of `oidc`.
                let idp_id = provider.idp_id.take().unwrap_or("oidc".to_owned());
                provider.idp_id = Some(idp_id.clone());
                out.insert(idp_id, provider);
            }
        }

        for provider in &self.oidc_providers {
            let mut provider = provider.clone();
            let idp_id = match provider.idp_id.take() {
                None => "oidc".to_owned(),
                Some(idp_id) if idp_id == "oidc" => idp_id,
                // Synapse internally prefixes the IdP IDs with `oidc-`.
                Some(idp_id) => format!("oidc-{idp_id}"),
            };
            provider.idp_id = Some(idp_id.clone());
            out.insert(idp_id, provider);
        }

        out
    }

    /// Adjust a MAS configuration to match this Synapse configuration.
    #[must_use]
    pub fn adjust_mas_config(
        self,
        mut mas_config: mas_config::RootConfig,
        rng: &mut impl Rng,
        now: DateTime<Utc>,
    ) -> mas_config::RootConfig {
        let providers = self.all_oidc_providers();
        for provider in providers.into_values() {
            let Some(mas_provider_config) = provider.into_mas_config(rng, now) else {
                // TODO: better log message
                warn!("Could not convert OIDC provider to MAS config");
                continue;
            };

            mas_config
                .upstream_oauth2
                .providers
                .push(mas_provider_config);
        }

        // TODO: manage when the option is not set
        if let Some(enable_3pid_changes) = self.enable_3pid_changes {
            mas_config.account.email_change_allowed = enable_3pid_changes;
        }
        mas_config.account.displayname_change_allowed = self.enable_set_display_name;
        if self.password_config.enabled {
            mas_config.passwords.enabled = true;
            mas_config.passwords.schemes = vec![
                // This is the password hashing scheme synapse uses
                PasswordHashingScheme {
                    version: 1,
                    algorithm: PasswordAlgorithm::Bcrypt,
                    cost: self.bcrypt_rounds,
                    secret: self.password_config.pepper,
                    secret_file: None,
                },
                // Use the default algorithm MAS uses as a second hashing scheme, so that users
                // will get their password hash upgraded to a more modern algorithm over time
                PasswordHashingScheme {
                    version: 2,
                    algorithm: PasswordAlgorithm::default(),
                    cost: None,
                    secret: None,
                    secret_file: None,
                },
            ];

            mas_config.account.password_registration_enabled = self.enable_registration;
        } else {
            mas_config.passwords.enabled = false;
        }

        if self.enable_registration_captcha {
            mas_config.captcha.service = Some(mas_config::CaptchaServiceKind::RecaptchaV2);
            mas_config.captcha.site_key = self.recaptcha_public_key;
            mas_config.captcha.secret_key = self.recaptcha_private_key;
        }

        mas_config.matrix.homeserver = self.server_name;
        if let Some(public_baseurl) = self.public_baseurl {
            mas_config.matrix.endpoint = public_baseurl;
        }

        mas_config
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
    /// # Errors
    ///
    /// Returns an error if this database configuration is invalid or
    /// unsupported.
    pub fn to_sqlx_postgres(&self) -> Result<PgConnectOptions, anyhow::Error> {
        if self.name != SYNAPSE_DATABASE_DRIVER_NAME_PSYCOPG2 {
            anyhow::bail!("syn2mas does not support the {} database driver", self.name);
        }

        if self.args.database.is_some() && self.args.dbname.is_some() {
            anyhow::bail!(
                "Only one of `database` and `dbname` may be specified in the Synapse database configuration, not both."
            );
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
        if let Some(database) = &self.args.database {
            opts = opts.database(database);
        }
        if let Some(user) = &self.args.user {
            opts = opts.username(user);
        }
        if let Some(password) = &self.args.password {
            opts = opts.password(password);
        }

        Ok(opts)
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
    // This is a deperecated way of specifying the database name.
    pub database: Option<String>,
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
        #[expect(clippy::needless_pass_by_value)]
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
            .is_err()
        );

        // Only one of `database` and `dbname` may be specified
        assert!(
            DatabaseSection {
                name: "psycopg2".to_owned(),
                args: DatabaseArgsSuboption {
                    user: Some("synapse_user".to_owned()),
                    password: Some("verysecret".to_owned()),
                    dbname: Some("synapse_db".to_owned()),
                    database: Some("synapse_db".to_owned()),
                    host: Some("synapse-db.example.com".to_owned()),
                    port: Some(42),
                },
            }
            .to_sqlx_postgres()
            .is_err()
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
                    database: None,
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
