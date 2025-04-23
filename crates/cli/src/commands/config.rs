// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::process::ExitCode;

use anyhow::Context;
use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSection, RootConfig, SyncConfig};
use mas_storage::{Clock as _, SystemClock};
use mas_storage_pg::MIGRATOR;
use rand::SeedableRng;
use tokio::io::AsyncWriteExt;
use tracing::{Instrument, info, info_span};

use crate::util::database_connection_from_config;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Dump the current config as YAML
    Dump {
        /// The path to the config file to dump
        ///
        /// If not specified, the config will be written to stdout
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,
    },

    /// Check a config file
    Check,

    /// Generate a new config file
    Generate {
        /// The path to the config file to generate
        ///
        /// If not specified, the config will be written to stdout
        #[clap(short, long)]
        output: Option<Utf8PathBuf>,

        /// Existing Synapse configuration used to generate the MAS config
        #[arg(short, long, action = clap::ArgAction::Append)]
        synapse_config: Vec<Utf8PathBuf>,
    },

    /// Sync the clients and providers from the config file to the database
    Sync {
        /// Prune elements that are in the database but not in the config file
        /// anymore
        #[clap(long)]
        prune: bool,

        /// Do not actually write to the database
        #[clap(long)]
        dry_run: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Dump { output } => {
                let _span = info_span!("cli.config.dump").entered();

                let config = RootConfig::extract(figment)?;
                let config = serde_yaml::to_string(&config)?;

                if let Some(output) = output {
                    info!("Writing configuration to {output:?}");
                    let mut file = tokio::fs::File::create(output).await?;
                    file.write_all(config.as_bytes()).await?;
                } else {
                    info!("Writing configuration to standard output");
                    tokio::io::stdout().write_all(config.as_bytes()).await?;
                }
            }

            SC::Check => {
                let _span = info_span!("cli.config.check").entered();

                let _config = RootConfig::extract(figment)?;
                info!("Configuration file looks good");
            }

            SC::Generate {
                output,
                synapse_config,
            } => {
                let _span = info_span!("cli.config.generate").entered();
                let clock = SystemClock::default();

                // XXX: we should disallow SeedableRng::from_entropy
                let mut rng = rand_chacha::ChaChaRng::from_entropy();
                let mut config = RootConfig::generate(&mut rng).await?;

                if !synapse_config.is_empty() {
                    info!("Adjusting MAS config to match Synapse config from {synapse_config:?}");
                    let synapse_config = syn2mas::synapse_config::Config::load(&synapse_config)?;
                    config = synapse_config.adjust_mas_config(config, &mut rng, clock.now());
                }

                let config = serde_yaml::to_string(&config)?;
                if let Some(output) = output {
                    info!("Writing configuration to {output:?}");
                    let mut file = tokio::fs::File::create(output).await?;
                    file.write_all(config.as_bytes()).await?;
                } else {
                    info!("Writing configuration to standard output");
                    tokio::io::stdout().write_all(config.as_bytes()).await?;
                }
            }

            SC::Sync { prune, dry_run } => {
                let config = SyncConfig::extract(figment)?;
                let clock = SystemClock::default();
                let encrypter = config.secrets.encrypter();

                // Grab a connection to the database
                let mut conn = database_connection_from_config(&config.database).await?;

                MIGRATOR
                    .run(&mut conn)
                    .instrument(info_span!("db.migrate"))
                    .await
                    .context("could not run migrations")?;

                crate::sync::config_sync(
                    config.upstream_oauth2,
                    config.clients,
                    &mut conn,
                    &encrypter,
                    &clock,
                    prune,
                    dry_run,
                )
                .await?;
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
