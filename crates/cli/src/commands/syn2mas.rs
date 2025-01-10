use std::process::ExitCode;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSectionExt, DatabaseConfig};
use rand::thread_rng;
use sqlx::{Connection, Either, PgConnection};
use syn2mas::{synapse_config, LockedMasDatabase, MasWriter, SynapseReader};
use tracing::{error, warn};

use crate::util::database_connection_from_config;

/// The exit code used by `syn2mas check` and `syn2mas migrate` when there are errors preventing migration.
const EXIT_CODE_CHECK_ERRORS: u8 = 10;

/// The exit code used by `syn2mas check` when there are warnings which should be considered prior to migration.
const EXIT_CODE_CHECK_WARNINGS: u8 = 11;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,

    /// This version of the syn2mas tool is EXPERIMENTAL and INCOMPLETE. It is only suitable for TESTING.
    /// If you want to use this tool anyway, please pass this argument.
    ///
    /// If you want to migrate from Synapse to MAS today, please use the Node.js-based tool in the MAS repository.
    #[clap(long = "i-swear-i-am-just-testing-in-a-staging-environment")]
    experimental_accepted: bool,

    /// Path to the Synapse configuration (in YAML format).
    /// May be specified multiple times if multiple Synapse configuration files are in use.
    #[clap(long = "synapse-config")]
    synapse_configuration_files: Vec<Utf8PathBuf>,
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

        // TODO extract the synapse database location
        let mut syn_conn = PgConnection::connect("postgres:///fakesyn").await.unwrap();

        let config = DatabaseConfig::extract_or_default(figment)?;

        let mut mas_connection = database_connection_from_config(&config).await?;

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

                Ok(ExitCode::SUCCESS)
            }
            Subcommand::Migrate => {
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
                // TODO allow configuring the server name / extract from MAS config
                syn2mas::migrate(&mut reader, &mut writer, "matrix.org", &mut rng).await?;

                reader.finish().await?;
                writer.finish().await?;

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
