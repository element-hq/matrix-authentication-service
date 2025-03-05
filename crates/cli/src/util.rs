// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{sync::Arc, time::Duration};

use anyhow::Context;
use mas_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, DatabaseConfig, EmailConfig, EmailSmtpMode,
    EmailTransportKind, ExperimentalConfig, HomeserverKind, HttpConfig, MatrixConfig,
    PasswordsConfig, PolicyConfig, TemplatesConfig,
};
use mas_context::LogContext;
use mas_data_model::{SessionExpirationConfig, SiteConfig};
use mas_email::{MailTransport, Mailer};
use mas_handlers::{passwords::PasswordManager, webauthn::Webauthn};
use mas_matrix::{HomeserverConnection, ReadOnlyHomeserverConnection};
use mas_matrix_synapse::{LegacySynapseConnection, SynapseConnection};
use mas_policy::PolicyFactory;
use mas_router::UrlBuilder;
use mas_storage::{BoxRepositoryFactory, RepositoryAccess, RepositoryFactory};
use mas_templates::{SiteConfigExt, Templates};
use sqlx::{
    ConnectOptions, Executor, PgConnection, PgPool,
    postgres::{PgConnectOptions, PgPoolOptions},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
use tracing::{Instrument, log::LevelFilter};

pub async fn password_manager_from_config(
    config: &PasswordsConfig,
) -> Result<PasswordManager, anyhow::Error> {
    if !config.enabled() {
        return Ok(PasswordManager::disabled());
    }

    let schemes = config.load().await?.into_iter().map(
        |(version, algorithm, cost, secret, unicode_normalization)| {
            use mas_handlers::passwords::Hasher;
            let hasher = match algorithm {
                mas_config::PasswordAlgorithm::Pbkdf2 => {
                    Hasher::pbkdf2(secret, unicode_normalization)
                }
                mas_config::PasswordAlgorithm::Bcrypt => {
                    Hasher::bcrypt(cost, secret, unicode_normalization)
                }
                mas_config::PasswordAlgorithm::Argon2id => {
                    Hasher::argon2id(secret, unicode_normalization)
                }
            };

            (version, hasher)
        },
    );

    PasswordManager::new(config.minimum_complexity(), schemes)
}

pub fn mailer_from_config(
    config: &EmailConfig,
    templates: &Templates,
) -> Result<Mailer, anyhow::Error> {
    let from = config
        .from
        .parse()
        .context("invalid email configuration: invalid 'from' address")?;
    let reply_to = config
        .reply_to
        .parse()
        .context("invalid email configuration: invalid 'reply_to' address")?;
    let transport = match config.transport() {
        EmailTransportKind::Blackhole => MailTransport::blackhole(),
        EmailTransportKind::Smtp => {
            // This should have been set ahead of time
            let hostname = config
                .hostname()
                .context("invalid email configuration: missing hostname")?;

            let mode = config
                .mode()
                .context("invalid email configuration: missing mode")?;

            let credentials = match (config.username(), config.password()) {
                (Some(username), Some(password)) => Some(mas_email::SmtpCredentials::new(
                    username.to_owned(),
                    password.to_owned(),
                )),
                (None, None) => None,
                _ => {
                    anyhow::bail!("invalid email configuration: missing username or password");
                }
            };

            let mode = match mode {
                EmailSmtpMode::Plain => mas_email::SmtpMode::Plain,
                EmailSmtpMode::StartTls => mas_email::SmtpMode::StartTls,
                EmailSmtpMode::Tls => mas_email::SmtpMode::Tls,
            };

            MailTransport::smtp(mode, hostname, config.port(), credentials)
                .context("failed to build SMTP transport")?
        }
        EmailTransportKind::Sendmail => MailTransport::sendmail(config.command()),
    };

    Ok(Mailer::new(templates.clone(), transport, from, reply_to))
}

/// Test the connection to the mailer in a background task
pub fn test_mailer_in_background(mailer: &Mailer, timeout: Duration) {
    let mailer = mailer.clone();

    let span = tracing::info_span!("cli.test_mailer");
    tokio::spawn(
        LogContext::new("mailer-test").run(async move || {
            match tokio::time::timeout(timeout, mailer.test_connection()).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    tracing::warn!(
                        error = &err as &dyn std::error::Error,
                        "Could not connect to the mail backend, tasks sending mails may fail!"
                    );
                }
                Err(_) => {
                    tracing::warn!("Timed out while testing the mail backend connection, tasks sending mails may fail!");
                }
            }
        })
        .instrument(span)
    );
}

pub async fn policy_factory_from_config(
    config: &PolicyConfig,
    matrix_config: &MatrixConfig,
) -> Result<PolicyFactory, anyhow::Error> {
    let policy_file = tokio::fs::File::open(&config.wasm_module)
        .await
        .context("failed to open OPA WASM policy file")?;

    let entrypoints = mas_policy::Entrypoints {
        register: config.register_entrypoint.clone(),
        client_registration: config.client_registration_entrypoint.clone(),
        authorization_grant: config.authorization_grant_entrypoint.clone(),
        email: config.email_entrypoint.clone(),
    };

    let data =
        mas_policy::Data::new(matrix_config.homeserver.clone()).with_rest(config.data.clone());

    PolicyFactory::load(policy_file, data, entrypoints)
        .await
        .context("failed to load the policy")
}

pub fn captcha_config_from_config(
    captcha_config: &CaptchaConfig,
) -> Result<Option<mas_data_model::CaptchaConfig>, anyhow::Error> {
    let Some(service) = captcha_config.service else {
        return Ok(None);
    };

    let service = match service {
        mas_config::CaptchaServiceKind::RecaptchaV2 => mas_data_model::CaptchaService::RecaptchaV2,
        mas_config::CaptchaServiceKind::CloudflareTurnstile => {
            mas_data_model::CaptchaService::CloudflareTurnstile
        }
        mas_config::CaptchaServiceKind::HCaptcha => mas_data_model::CaptchaService::HCaptcha,
    };

    Ok(Some(mas_data_model::CaptchaConfig {
        service,
        site_key: captcha_config
            .site_key
            .clone()
            .context("missing site key")?,
        secret_key: captcha_config
            .secret_key
            .clone()
            .context("missing secret key")?,
    }))
}

pub fn site_config_from_config(
    branding_config: &BrandingConfig,
    matrix_config: &MatrixConfig,
    experimental_config: &ExperimentalConfig,
    password_config: &PasswordsConfig,
    account_config: &AccountConfig,
    captcha_config: &CaptchaConfig,
) -> Result<SiteConfig, anyhow::Error> {
    let captcha = captcha_config_from_config(captcha_config)?;
    let session_expiration = experimental_config
        .inactive_session_expiration
        .as_ref()
        .map(|c| SessionExpirationConfig {
            oauth_session_inactivity_ttl: c.expire_oauth_sessions.then_some(c.ttl),
            compat_session_inactivity_ttl: c.expire_compat_sessions.then_some(c.ttl),
            user_session_inactivity_ttl: c.expire_user_sessions.then_some(c.ttl),
        });

    Ok(SiteConfig {
        access_token_ttl: experimental_config.access_token_ttl,
        compat_token_ttl: experimental_config.compat_token_ttl,
        server_name: matrix_config.homeserver.clone(),
        policy_uri: branding_config.policy_uri.clone(),
        tos_uri: branding_config.tos_uri.clone(),
        imprint: branding_config.imprint.clone(),
        password_login_enabled: password_config.enabled(),
        password_registration_enabled: password_config.enabled()
            && account_config.password_registration_enabled,
        registration_token_required: account_config.registration_token_required,
        email_change_allowed: account_config.email_change_allowed,
        displayname_change_allowed: account_config.displayname_change_allowed,
        password_change_allowed: password_config.enabled()
            && account_config.password_change_allowed,
        account_recovery_allowed: password_config.enabled()
            && account_config.password_recovery_enabled,
        account_deactivation_allowed: account_config.account_deactivation_allowed,
        captcha,
        minimum_password_complexity: password_config.minimum_complexity(),
        session_expiration,
        login_with_email_allowed: account_config.login_with_email_allowed,
        plan_management_iframe_uri: experimental_config.plan_management_iframe_uri.clone(),
        passkeys_enabled: experimental_config
            .passkeys
            .as_ref()
            .is_some_and(|c| c.enabled),
    })
}

pub async fn templates_from_config(
    config: &TemplatesConfig,
    site_config: &SiteConfig,
    url_builder: &UrlBuilder,
) -> Result<Templates, anyhow::Error> {
    Templates::load(
        config.path.clone(),
        url_builder.clone(),
        config.assets_manifest.clone(),
        config.translations_path.clone(),
        site_config.templates_branding(),
        site_config.templates_features(),
    )
    .await
    .with_context(|| format!("Failed to load the templates at {}", config.path))
}

fn database_connect_options_from_config(
    config: &DatabaseConfig,
    opts: &DatabaseConnectOptions,
) -> Result<PgConnectOptions, anyhow::Error> {
    let options = if let Some(uri) = config.uri.as_deref() {
        uri.parse()
            .context("could not parse database connection string")?
    } else {
        let mut opts = PgConnectOptions::new().application_name("matrix-authentication-service");

        if let Some(host) = config.host.as_deref() {
            opts = opts.host(host);
        }

        if let Some(port) = config.port {
            opts = opts.port(port);
        }

        if let Some(socket) = config.socket.as_deref() {
            opts = opts.socket(socket);
        }

        if let Some(username) = config.username.as_deref() {
            opts = opts.username(username);
        }

        if let Some(password) = config.password.as_deref() {
            opts = opts.password(password);
        }

        if let Some(database) = config.database.as_deref() {
            opts = opts.database(database);
        }

        opts
    };

    let options = match (config.ssl_ca.as_deref(), config.ssl_ca_file.as_deref()) {
        (None, None) => options,
        (Some(pem), None) => options.ssl_root_cert_from_pem(pem.as_bytes().to_owned()),
        (None, Some(path)) => options.ssl_root_cert(path),
        (Some(_), Some(_)) => {
            anyhow::bail!("invalid database configuration: both `ssl_ca` and `ssl_ca_file` are set")
        }
    };

    let options = match (
        config.ssl_certificate.as_deref(),
        config.ssl_certificate_file.as_deref(),
    ) {
        (None, None) => options,
        (Some(pem), None) => options.ssl_client_cert_from_pem(pem.as_bytes()),
        (None, Some(path)) => options.ssl_client_cert(path),
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "invalid database configuration: both `ssl_certificate` and `ssl_certificate_file` are set"
            )
        }
    };

    let options = match (config.ssl_key.as_deref(), config.ssl_key_file.as_deref()) {
        (None, None) => options,
        (Some(pem), None) => options.ssl_client_key_from_pem(pem.as_bytes()),
        (None, Some(path)) => options.ssl_client_key(path),
        (Some(_), Some(_)) => {
            anyhow::bail!(
                "invalid database configuration: both `ssl_key` and `ssl_key_file` are set"
            )
        }
    };

    let options = match &config.ssl_mode {
        Some(ssl_mode) => {
            let ssl_mode = match ssl_mode {
                mas_config::PgSslMode::Disable => sqlx::postgres::PgSslMode::Disable,
                mas_config::PgSslMode::Allow => sqlx::postgres::PgSslMode::Allow,
                mas_config::PgSslMode::Prefer => sqlx::postgres::PgSslMode::Prefer,
                mas_config::PgSslMode::Require => sqlx::postgres::PgSslMode::Require,
                mas_config::PgSslMode::VerifyCa => sqlx::postgres::PgSslMode::VerifyCa,
                mas_config::PgSslMode::VerifyFull => sqlx::postgres::PgSslMode::VerifyFull,
            };

            options.ssl_mode(ssl_mode)
        }
        None => options,
    };

    let mut options = options.log_statements(LevelFilter::Debug);

    if opts.log_slow_statements {
        options = options.log_slow_statements(LevelFilter::Warn, Duration::from_millis(100));
    }

    Ok(options)
}

/// Create a database connection pool from the configuration
#[tracing::instrument(name = "db.connect", skip_all)]
pub async fn database_pool_from_config(config: &DatabaseConfig) -> Result<PgPool, anyhow::Error> {
    let options = database_connect_options_from_config(config, &DatabaseConnectOptions::default())?;
    PgPoolOptions::new()
        .max_connections(config.max_connections.into())
        .min_connections(config.min_connections)
        .acquire_timeout(config.connect_timeout)
        .idle_timeout(config.idle_timeout)
        .max_lifetime(config.max_lifetime)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                // Unlisten from all channels, as we might be connected via a connection pooler
                // that doesn't clean up LISTEN/NOTIFY state when reusing connections.
                conn.execute("UNLISTEN *;").await?;

                Ok(())
            })
        })
        .connect_with(options)
        .await
        .context("could not connect to the database")
}

pub struct DatabaseConnectOptions {
    pub log_slow_statements: bool,
}

impl Default for DatabaseConnectOptions {
    fn default() -> Self {
        Self {
            log_slow_statements: true,
        }
    }
}

/// Create a single database connection from the configuration
#[tracing::instrument(name = "db.connect", skip_all)]
pub async fn database_connection_from_config(
    config: &DatabaseConfig,
) -> Result<PgConnection, anyhow::Error> {
    database_connect_options_from_config(config, &DatabaseConnectOptions::default())?
        .connect()
        .await
        .context("could not connect to the database")
}

/// Create a single database connection from the configuration,
/// with specific options.
#[tracing::instrument(name = "db.connect", skip_all)]
pub async fn database_connection_from_config_with_options(
    config: &DatabaseConfig,
    options: &DatabaseConnectOptions,
) -> Result<PgConnection, anyhow::Error> {
    database_connect_options_from_config(config, options)?
        .connect()
        .await
        .context("could not connect to the database")
}

/// Update the policy factory dynamic data from the database and spawn a task to
/// periodically update it
// XXX: this could be put somewhere else?
pub async fn load_policy_factory_dynamic_data_continuously(
    policy_factory: &Arc<PolicyFactory>,
    repository_factory: BoxRepositoryFactory,
    cancellation_token: CancellationToken,
    task_tracker: &TaskTracker,
) -> Result<(), anyhow::Error> {
    let policy_factory = policy_factory.clone();

    load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await?;

    task_tracker.spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));

        loop {
            tokio::select! {
                () = cancellation_token.cancelled() => {
                    return;
                }
                _ = interval.tick() => {}
            }

            if let Err(err) =
                load_policy_factory_dynamic_data(&policy_factory, &*repository_factory).await
            {
                tracing::error!(
                    error = ?err,
                    "Failed to load policy factory dynamic data"
                );
                cancellation_token.cancel();
                return;
            }
        }
    });

    Ok(())
}

/// Update the policy factory dynamic data from the database
#[tracing::instrument(name = "policy.load_dynamic_data", skip_all)]
pub async fn load_policy_factory_dynamic_data(
    policy_factory: &PolicyFactory,
    repository_factory: &(dyn RepositoryFactory + Send + Sync),
) -> Result<(), anyhow::Error> {
    let mut repo = repository_factory
        .create()
        .await
        .context("Failed to acquire database connection")?;

    if let Some(data) = repo.policy_data().get().await? {
        let id = data.id;
        let updated = policy_factory.set_dynamic_data(data).await?;
        if updated {
            tracing::info!(policy_data.id = %id, "Loaded dynamic policy data from the database");
        }
    }

    Ok(())
}

/// Create a clonable, type-erased [`HomeserverConnection`] from the
/// configuration
pub async fn homeserver_connection_from_config(
    config: &MatrixConfig,
    http_client: reqwest::Client,
) -> anyhow::Result<Arc<dyn HomeserverConnection>> {
    Ok(match config.kind {
        HomeserverKind::Synapse | HomeserverKind::SynapseModern => {
            Arc::new(SynapseConnection::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            ))
        }
        HomeserverKind::SynapseLegacy => Arc::new(LegacySynapseConnection::new(
            config.homeserver.clone(),
            config.endpoint.clone(),
            config.secret().await?,
            http_client,
        )),
        HomeserverKind::SynapseReadOnly => {
            let connection = SynapseConnection::new(
                config.homeserver.clone(),
                config.endpoint.clone(),
                config.secret().await?,
                http_client,
            );
            let readonly = ReadOnlyHomeserverConnection::new(connection);
            Arc::new(readonly)
        }
    })
}

pub fn webauthn_from_config(
    http_config: &HttpConfig,
    experimental_config: &ExperimentalConfig,
) -> Result<Webauthn, anyhow::Error> {
    Webauthn::new(
        &http_config.public_base,
        experimental_config.passkeys.as_ref(),
    )
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use zeroize::Zeroizing;

    use super::*;

    #[tokio::test]
    async fn test_password_manager_from_config() {
        let mut rng = rand_chacha::ChaChaRng::seed_from_u64(42);
        let password = Zeroizing::new("hunter2".to_owned());

        // Test a valid, enabled config
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 10,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(manager.is_enabled());
        let hashed = manager.hash(&mut rng, password.clone()).await;
        assert!(hashed.is_ok());
        let (version, hashed) = hashed.unwrap();
        assert_eq!(version, 42);
        assert!(hashed.starts_with("$argon2id$"));

        // Test a valid, disabled config
        let config = serde_json::from_value(serde_json::json!({
            "enabled": false,
            "schemes": []
        }))
        .unwrap();

        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_ok());
        let manager = manager.unwrap();
        assert!(!manager.is_enabled());
        let res = manager.hash(&mut rng, password.clone()).await;
        assert!(res.is_err());

        // Test an invalid config
        // Repeat the same version twice
        let config = serde_json::from_value(serde_json::json!({
            "schemes": [{
                "version": 42,
                "algorithm": "argon2id"
            }, {
                "version": 42,
                "algorithm": "bcrypt"
            }]
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());

        // Empty schemes
        let config = serde_json::from_value(serde_json::json!({
            "schemes": []
        }))
        .unwrap();
        let manager = password_manager_from_config(&config).await;
        assert!(manager.is_err());
    }
}
