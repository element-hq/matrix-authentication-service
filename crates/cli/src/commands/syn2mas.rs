use std::{pin::pin, process::ExitCode};

use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSectionExt, DatabaseConfig};
use rand::thread_rng;
use sqlx::{Connection, PgConnection};
use syn2mas::{MasWriter, SynapseReader};
use tokio_stream::StreamExt;
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

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        warn!("This version of the syn2mas tool is EXPERIMENTAL and INCOMPLETE. Do not use it, except for TESTING.");
        if !self.experimental_accepted {
            error!("Please agree that you can only use this tool for testing.");
            return Ok(ExitCode::FAILURE);
        }

        let mut syn_conn = PgConnection::connect(
            "postgres:///fakesyn",
            // "postgres://matrix-synapse@%2Fhome%2Fele%2F.pg-lpnet/matrix-synapse",
        )
        .await
        .unwrap();

        let config = DatabaseConfig::extract_or_default(figment)?;
        let mut conn = database_connection_from_config(&config).await?;

        syn2mas::pre_migration_checks(&mut syn_conn, &mut conn).await?;

        let mut reader = SynapseReader::new(&mut syn_conn, true).await?;
        let mut writer = MasWriter::new(&mut conn).await?;

        let mut rng = thread_rng();
        // TODO progress reporting
        syn2mas::migrate(&mut reader, &mut writer, "matrix.org", &mut rng).await?;

        writer.finish().await?;

        Ok(ExitCode::SUCCESS)
    }
}
