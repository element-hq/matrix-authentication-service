use std::process::ExitCode;

use anyhow::Context;
use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSectionExt, DatabaseConfig};
use rand::thread_rng;
use sqlx::{Connection, Either, PgConnection};
use syn2mas::{LockedMasDatabase, MasWriter, SynapseReader};
use tracing::{error, warn};

use crate::util::database_connection_from_config;

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
}

#[derive(Parser, Debug)]
enum Subcommand {
    Check,
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

        // TODO allow configuring the synapse database location
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

        syn2mas::mas_pre_migration_checks(&mut mas_connection).await?;
        syn2mas::synapse_pre_migration_checks(&mut syn_conn).await?;

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
        // TODO allow configuring the server name
        syn2mas::migrate(&mut reader, &mut writer, "matrix.org", &mut rng).await?;

        reader.finish().await?;
        writer.finish().await?;

        Ok(ExitCode::SUCCESS)
    }
}
