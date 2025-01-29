use std::{collections::HashMap, process::ExitCode};

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use mas_config::{
    ConfigurationSection, ConfigurationSectionExt, DatabaseConfig, MatrixConfig, SyncConfig,
    UpstreamOAuth2Config,
};
use mas_storage::SystemClock;
use mas_storage_pg::MIGRATOR;
use rand::thread_rng;
use sqlx::{postgres::PgConnectOptions, types::Uuid, Connection, Either, PgConnection};
use syn2mas::{synapse_config, LockedMasDatabase, MasWriter, SynapseReader};
use tracing::{error, info_span, warn, Instrument};

use crate::util::database_connection_from_config;

/// The exit code used by `syn2mas check` and `syn2mas migrate` when there are
/// errors preventing migration.
const EXIT_CODE_CHECK_ERRORS: u8 = 10;

/// The exit code used by `syn2mas check` when there are warnings which should
/// be considered prior to migration.
const EXIT_CODE_CHECK_WARNINGS: u8 = 11;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,

    /// This version of the syn2mas tool is EXPERIMENTAL and INCOMPLETE. It is
    /// only suitable for TESTING. If you want to use this tool anyway,
    /// please pass this argument.
    ///
    /// If you want to migrate from Synapse to MAS today, please use the
    /// Node.js-based tool in the MAS repository.
    #[clap(long = "i-swear-i-am-just-testing-in-a-staging-environment")]
    experimental_accepted: bool,

    /// Path to the Synapse configuration (in YAML format).
    /// May be specified multiple times if multiple Synapse configuration files
    /// are in use.
    #[clap(long = "synapse-config")]
    synapse_configuration_files: Vec<Utf8PathBuf>,

    /// Override the Synapse database URI.
    /// syn2mas normally loads the Synapse database connection details from the
    /// Synapse configuration. However, it may sometimes be necessary to
    /// override the database URI and in that case this flag can be used.
    ///
    /// Should be a connection URI of the following general form:
    /// ```text
    /// postgresql://[user[:password]@][host][:port][/dbname][?param1=value1&...]
    /// ```
    /// To use a UNIX socket at a custom path, the host should be a path to a
    /// socket, but in the URI string it must be URI-encoded by replacing
    /// `/` with `%2F`.
    ///
    /// Finally, any missing values will be loaded from the libpq-compatible
    /// environment variables `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`,
    /// `PGPASSWORD`, etc. It is valid to specify the URL `postgresql:` and
    /// configure all values through those environment variables.
    #[clap(long = "synapse-database-uri")]
    synapse_database_uri: Option<PgConnectOptions>,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check the setup for potential problems before running a migration.
    ///
    /// It is OK for Synapse to be online during these checks.
    Check,
    /// Perform a migration. Synapse must be offline during this process.
    Migrate,
}

/// The number of parallel writing transactions active against the MAS database.
const NUM_WRITER_CONNECTIONS: usize = 8;

impl Options {
    #[allow(clippy::too_many_lines)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        warn!("This version of the syn2mas tool is EXPERIMENTAL and INCOMPLETE. Do not use it, except for TESTING.");
        if !self.experimental_accepted {
            error!("Please agree that you can only use this tool for testing.");
            return Ok(ExitCode::FAILURE);
        }

        if self.synapse_configuration_files.is_empty() {
            error!("Please specify the path to the Synapse configuration file(s).");
            return Ok(ExitCode::FAILURE);
        }

        let synapse_config = synapse_config::Config::load(&self.synapse_configuration_files)
            .context("Failed to load Synapse configuration")?;

        // Establish a connection to Synapse's Postgres database
        let syn_connection_options = if let Some(db_override) = self.synapse_database_uri {
            db_override
        } else {
            synapse_config
                .database
                .to_sqlx_postgres()
                .context("Synapse configuration does not use Postgres, cannot migrate.")?
        };
        let mut syn_conn = PgConnection::connect_with(&syn_connection_options)
            .await
            .context("could not connect to Synapse Postgres database")?;

        let config = DatabaseConfig::extract_or_default(figment)?;

        let mut mas_connection = database_connection_from_config(&config).await?;

        MIGRATOR
            .run(&mut mas_connection)
            .instrument(info_span!("db.migrate"))
            .await
            .context("could not run migrations")?;

        if matches!(&self.subcommand, Subcommand::Migrate { .. }) {
            // First perform a config sync
            // This is crucial to ensure we register upstream OAuth providers
            // in the MAS database
            //
            let config = SyncConfig::extract(figment)?;
            let clock = SystemClock::default();
            let encrypter = config.secrets.encrypter();

            crate::sync::config_sync(
                config.upstream_oauth2,
                config.clients,
                &mut mas_connection,
                &encrypter,
                &clock,
                // Don't prune — we don't want to be unnecessarily destructive
                false,
                // Not a dry run — we do want to create the providers in the database
                false,
            )
            .await?;
        }

        let Either::Left(mut mas_connection) = LockedMasDatabase::try_new(&mut mas_connection)
            .await
            .context("failed to issue query to lock database")?
        else {
            error!("Failed to acquire syn2mas lock on the database.");
            error!("This likely means that another syn2mas instance is already running!");
            return Ok(ExitCode::FAILURE);
        };

        // Check configuration
        let (mut check_warnings, mut check_errors) = syn2mas::synapse_config_check(&synapse_config);
        {
            let (extra_warnings, extra_errors) =
                syn2mas::synapse_config_check_against_mas_config(&synapse_config, figment).await?;
            check_warnings.extend(extra_warnings);
            check_errors.extend(extra_errors);
        }

        // Check databases
        syn2mas::mas_pre_migration_checks(&mut mas_connection).await?;
        {
            let (extra_warnings, extra_errors) =
                syn2mas::synapse_database_check(&mut syn_conn, &synapse_config, figment).await?;
            check_warnings.extend(extra_warnings);
            check_errors.extend(extra_errors);
        }

        // Display errors and warnings
        if !check_errors.is_empty() {
            eprintln!("===== Errors =====");
            eprintln!("These issues prevent migrating from Synapse to MAS right now:\n");
            for error in &check_errors {
                eprintln!("• {error}\n");
            }
        }
        if !check_warnings.is_empty() {
            eprintln!("===== Warnings =====");
            eprintln!("These potential issues should be considered before migrating from Synapse to MAS right now:\n");
            for warning in &check_warnings {
                eprintln!("• {warning}\n");
            }
        }

        // Do not proceed if there are any errors
        if !check_errors.is_empty() {
            return Ok(ExitCode::from(EXIT_CODE_CHECK_ERRORS));
        }

        match self.subcommand {
            Subcommand::Check => {
                if !check_warnings.is_empty() {
                    return Ok(ExitCode::from(EXIT_CODE_CHECK_WARNINGS));
                }

                println!("Check completed successfully with no errors or warnings.");

                Ok(ExitCode::SUCCESS)
            }
            Subcommand::Migrate => {
                let provider_id_mappings: HashMap<String, Uuid> = {
                    let mas_oauth2 = UpstreamOAuth2Config::extract_or_default(figment)?;

                    mas_oauth2
                        .providers
                        .iter()
                        .filter_map(|provider| {
                            let synapse_idp_id = provider.synapse_idp_id.clone()?;
                            Some((synapse_idp_id, Uuid::from(provider.id)))
                        })
                        .collect()
                };

                // TODO how should we handle warnings at this stage?

                let mut reader = SynapseReader::new(&mut syn_conn, true).await?;
                let mut writer_mas_connections = Vec::with_capacity(NUM_WRITER_CONNECTIONS);
                for _ in 0..NUM_WRITER_CONNECTIONS {
                    writer_mas_connections.push(database_connection_from_config(&config).await?);
                }
                let mut writer = MasWriter::new(mas_connection, writer_mas_connections).await?;

                // TODO is this rng ok?
                #[allow(clippy::disallowed_methods)]
                let mut rng = thread_rng();

                // TODO progress reporting
                let mas_matrix = MatrixConfig::extract(figment)?;
                syn2mas::migrate(
                    &mut reader,
                    &mut writer,
                    &mas_matrix.homeserver,
                    &mut rng,
                    &provider_id_mappings,
                )
                .await?;

                reader.finish().await?;
                writer.finish().await?;

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
