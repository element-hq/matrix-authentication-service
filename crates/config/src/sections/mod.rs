// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use rand::Rng;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

mod account;
mod branding;
mod captcha;
mod clients;
mod database;
mod email;
mod experimental;
mod http;
mod matrix;
mod passwords;
mod policy;
mod rate_limiting;
mod secrets;
mod telemetry;
mod templates;
mod upstream_oauth2;

pub use self::{
    account::AccountConfig,
    branding::BrandingConfig,
    captcha::{CaptchaConfig, CaptchaServiceKind},
    clients::{ClientAuthMethodConfig, ClientConfig, ClientsConfig},
    database::{DatabaseConfig, PgSslMode},
    email::{EmailConfig, EmailSmtpMode, EmailTransportKind},
    experimental::ExperimentalConfig,
    http::{
        BindConfig as HttpBindConfig, HttpConfig, ListenerConfig as HttpListenerConfig,
        Resource as HttpResource, TlsConfig as HttpTlsConfig, UnixOrTcp,
    },
    matrix::{HomeserverKind, MatrixConfig},
    passwords::{
        Algorithm as PasswordAlgorithm, HashingScheme as PasswordHashingScheme, PasswordsConfig,
    },
    policy::PolicyConfig,
    rate_limiting::RateLimitingConfig,
    secrets::SecretsConfig,
    telemetry::{
        MetricsConfig, MetricsExporterKind, Propagator, TelemetryConfig, TracingConfig,
        TracingExporterKind,
    },
    templates::TemplatesConfig,
    upstream_oauth2::{
        ClaimsImports as UpstreamOAuth2ClaimsImports, DiscoveryMode as UpstreamOAuth2DiscoveryMode,
        EmailImportPreference as UpstreamOAuth2EmailImportPreference,
        ImportAction as UpstreamOAuth2ImportAction,
        OnBackchannelLogout as UpstreamOAuth2OnBackchannelLogout,
        PkceMethod as UpstreamOAuth2PkceMethod, Provider as UpstreamOAuth2Provider,
        ResponseMode as UpstreamOAuth2ResponseMode,
        TokenAuthMethod as UpstreamOAuth2TokenAuthMethod, UpstreamOAuth2Config,
    },
};
use crate::util::ConfigurationSection;

/// Application configuration root
#[derive(Debug, Serialize, Deserialize, JsonSchema)]
pub struct RootConfig {
    /// List of OAuth 2.0/OIDC clients config
    #[serde(default, skip_serializing_if = "ClientsConfig::is_default")]
    pub clients: ClientsConfig,

    /// Configuration of the HTTP server
    #[serde(default)]
    pub http: HttpConfig,

    /// Database connection configuration
    #[serde(default)]
    pub database: DatabaseConfig,

    /// Configuration related to sending monitoring data
    #[serde(default, skip_serializing_if = "TelemetryConfig::is_default")]
    pub telemetry: TelemetryConfig,

    /// Configuration related to templates
    #[serde(default, skip_serializing_if = "TemplatesConfig::is_default")]
    pub templates: TemplatesConfig,

    /// Configuration related to sending emails
    #[serde(default)]
    pub email: EmailConfig,

    /// Application secrets
    pub secrets: SecretsConfig,

    /// Configuration related to user passwords
    #[serde(default)]
    pub passwords: PasswordsConfig,

    /// Configuration related to the homeserver
    pub matrix: MatrixConfig,

    /// Configuration related to the OPA policies
    #[serde(default, skip_serializing_if = "PolicyConfig::is_default")]
    pub policy: PolicyConfig,

    /// Configuration related to limiting the rate of user actions to prevent
    /// abuse
    #[serde(default, skip_serializing_if = "RateLimitingConfig::is_default")]
    pub rate_limiting: RateLimitingConfig,

    /// Configuration related to upstream OAuth providers
    #[serde(default, skip_serializing_if = "UpstreamOAuth2Config::is_default")]
    pub upstream_oauth2: UpstreamOAuth2Config,

    /// Configuration section for tweaking the branding of the service
    #[serde(default, skip_serializing_if = "BrandingConfig::is_default")]
    pub branding: BrandingConfig,

    /// Configuration section to setup CAPTCHA protection on a few operations
    #[serde(default, skip_serializing_if = "CaptchaConfig::is_default")]
    pub captcha: CaptchaConfig,

    /// Configuration section to configure features related to account
    /// management
    #[serde(default, skip_serializing_if = "AccountConfig::is_default")]
    pub account: AccountConfig,

    /// Experimental configuration options
    #[serde(default, skip_serializing_if = "ExperimentalConfig::is_default")]
    pub experimental: ExperimentalConfig,
}

impl ConfigurationSection for RootConfig {
    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.clients.validate(figment)?;
        self.http.validate(figment)?;
        self.database.validate(figment)?;
        self.telemetry.validate(figment)?;
        self.templates.validate(figment)?;
        self.email.validate(figment)?;
        self.passwords.validate(figment)?;
        self.secrets.validate(figment)?;
        self.matrix.validate(figment)?;
        self.policy.validate(figment)?;
        self.rate_limiting.validate(figment)?;
        self.upstream_oauth2.validate(figment)?;
        self.branding.validate(figment)?;
        self.captcha.validate(figment)?;
        self.account.validate(figment)?;
        self.experimental.validate(figment)?;

        Ok(())
    }
}

impl RootConfig {
    /// Generate a new configuration with random secrets
    ///
    /// # Errors
    ///
    /// Returns an error if the secrets could not be generated
    pub async fn generate<R>(mut rng: R) -> anyhow::Result<Self>
    where
        R: Rng + Send,
    {
        Ok(Self {
            clients: ClientsConfig::default(),
            http: HttpConfig::default(),
            database: DatabaseConfig::default(),
            telemetry: TelemetryConfig::default(),
            templates: TemplatesConfig::default(),
            email: EmailConfig::default(),
            passwords: PasswordsConfig::default(),
            secrets: SecretsConfig::generate(&mut rng).await?,
            matrix: MatrixConfig::generate(&mut rng),
            policy: PolicyConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            upstream_oauth2: UpstreamOAuth2Config::default(),
            branding: BrandingConfig::default(),
            captcha: CaptchaConfig::default(),
            account: AccountConfig::default(),
            experimental: ExperimentalConfig::default(),
        })
    }

    /// Configuration used in tests
    #[must_use]
    pub fn test() -> Self {
        Self {
            clients: ClientsConfig::default(),
            http: HttpConfig::default(),
            database: DatabaseConfig::default(),
            telemetry: TelemetryConfig::default(),
            templates: TemplatesConfig::default(),
            passwords: PasswordsConfig::default(),
            email: EmailConfig::default(),
            secrets: SecretsConfig::test(),
            matrix: MatrixConfig::test(),
            policy: PolicyConfig::default(),
            rate_limiting: RateLimitingConfig::default(),
            upstream_oauth2: UpstreamOAuth2Config::default(),
            branding: BrandingConfig::default(),
            captcha: CaptchaConfig::default(),
            account: AccountConfig::default(),
            experimental: ExperimentalConfig::default(),
        }
    }
}

/// Partial configuration actually used by the server
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct AppConfig {
    #[serde(default)]
    pub http: HttpConfig,

    #[serde(default)]
    pub database: DatabaseConfig,

    #[serde(default)]
    pub templates: TemplatesConfig,

    #[serde(default)]
    pub email: EmailConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub passwords: PasswordsConfig,

    pub matrix: MatrixConfig,

    #[serde(default)]
    pub policy: PolicyConfig,

    #[serde(default)]
    pub rate_limiting: RateLimitingConfig,

    #[serde(default)]
    pub branding: BrandingConfig,

    #[serde(default)]
    pub captcha: CaptchaConfig,

    #[serde(default)]
    pub account: AccountConfig,

    #[serde(default)]
    pub experimental: ExperimentalConfig,
}

impl ConfigurationSection for AppConfig {
    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.http.validate(figment)?;
        self.database.validate(figment)?;
        self.templates.validate(figment)?;
        self.email.validate(figment)?;
        self.passwords.validate(figment)?;
        self.secrets.validate(figment)?;
        self.matrix.validate(figment)?;
        self.policy.validate(figment)?;
        self.rate_limiting.validate(figment)?;
        self.branding.validate(figment)?;
        self.captcha.validate(figment)?;
        self.account.validate(figment)?;
        self.experimental.validate(figment)?;

        Ok(())
    }
}

/// Partial config used by the `mas-cli config sync` command
#[allow(missing_docs)]
#[derive(Debug, Deserialize)]
pub struct SyncConfig {
    #[serde(default)]
    pub database: DatabaseConfig,

    pub secrets: SecretsConfig,

    #[serde(default)]
    pub clients: ClientsConfig,

    #[serde(default)]
    pub upstream_oauth2: UpstreamOAuth2Config,
}

impl ConfigurationSection for SyncConfig {
    fn validate(
        &self,
        figment: &figment::Figment,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync + 'static>> {
        self.database.validate(figment)?;
        self.secrets.validate(figment)?;
        self.clients.validate(figment)?;
        self.upstream_oauth2.validate(figment)?;

        Ok(())
    }
}
