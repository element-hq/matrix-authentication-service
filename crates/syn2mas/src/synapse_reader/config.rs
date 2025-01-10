// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use camino::Utf8PathBuf;
use figment::providers::{Format, Yaml};
use serde::Deserialize;

/// The root of a Synapse configuration.
/// This struct only includes fields which the Synapse-to-MAS migration is interested in.
///
/// See: <https://element-hq.github.io/synapse/latest/usage/configuration/config_documentation.html>
#[derive(Deserialize)]
#[allow(clippy::struct_excessive_bools)]
pub struct Config {
    pub database: DatabaseSection,
    pub password_config: PasswordSection,

    #[serde(default)]
    pub allow_guest_access: bool,

    #[serde(default)]
    pub enable_registration: bool,

    #[serde(default)]
    pub enable_registration_captcha: bool,

    /// Normally this defaults to true, but when MAS integration is enabled in Synapse it defaults to false.
    #[serde(default)]
    pub enable_3pid_changes: bool,

    #[serde(default)]
    pub user_consent: bool,

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
            figment = figment.merge(Yaml::file(file));
        }
        figment.extract::<Config>()
    }

    #[must_use]
    pub fn all_oidc_providers(&self) -> Vec<OidcProvider> {
        let mut out = Vec::new();

        if let Some(ref provider) = self.oidc_config {
            if provider.issuer.is_some() {
                let mut provider = provider.clone();
                provider.idp_id = Some("oidc".to_owned());
                out.push(provider.clone());
            }
        }

        for provider in &self.oidc_providers {
            if provider.issuer.is_some() {
                out.push(provider.clone());
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
    /// Expecting `psycopg2` for Postgres or `sqlite3` for `SQLite3`, but may be an arbitrary string and future versions
    /// of Synapse may support other database drivers, e.g. psycopg3.
    pub name: String,
    #[serde(default)]
    pub args: DatabaseArgsSuboption,
}

/// The `args` suboption of the `database` section of the Synapse configuration.
/// This struct assumes Postgres is in use and does not represent fields used by SQLite.
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

/// A section that we only care about whether it's enabled or not, but is not enabled by default.
#[derive(Default, Deserialize)]
pub struct EnableableSection {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Deserialize)]
pub struct OidcProvider {
    /// At least for `oidc_config`, if the dict is present but left empty then the config should be ignored,
    /// so this field must be optional.
    pub issuer: Option<String>,

    /// Required, except for the old `oidc_config` where this is implied to be "oidc".
    pub idp_id: Option<String>,
}

fn default_true() -> bool {
    true
}
