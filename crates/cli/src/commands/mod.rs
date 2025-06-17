// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::process::ExitCode;

use camino::Utf8PathBuf;
use clap::Parser;
use figment::{
    Figment,
    providers::{Env, Format, Yaml},
};

mod config;
mod database;
mod debug;
mod doctor;
mod manage;
mod server;
mod syn2mas;
mod templates;
mod worker;

#[derive(Parser, Debug)]
enum Subcommand {
    /// Configuration-related commands
    Config(self::config::Options),

    /// Manage the database
    Database(self::database::Options),

    /// Runs the web server
    Server(self::server::Options),

    /// Run the worker
    Worker(self::worker::Options),

    /// Manage the instance
    Manage(self::manage::Options),

    /// Templates-related commands
    Templates(self::templates::Options),

    /// Debug utilities
    #[clap(hide = true)]
    Debug(self::debug::Options),

    /// Run diagnostics on the deployment
    Doctor(self::doctor::Options),

    /// Migrate from Synapse's built-in auth system to MAS.
    #[clap(name = "syn2mas")]
    // Box<> is to work around a 'large size difference between variants' lint
    Syn2Mas(Box<self::syn2mas::Options>),
}

#[derive(Parser, Debug)]
#[command(version = crate::VERSION)]
pub struct Options {
    /// Path to the configuration file
    #[arg(short, long, global = true, action = clap::ArgAction::Append)]
    config: Vec<Utf8PathBuf>,

    #[command(subcommand)]
    subcommand: Option<Subcommand>,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as S;
        // We Box the futures for each subcommand so that we avoid this function being
        // big on the stack all the time
        match self.subcommand {
            Some(S::Config(c)) => Box::pin(c.run(figment)).await,
            Some(S::Database(c)) => Box::pin(c.run(figment)).await,
            Some(S::Server(c)) => Box::pin(c.run(figment)).await,
            Some(S::Worker(c)) => Box::pin(c.run(figment)).await,
            Some(S::Manage(c)) => Box::pin(c.run(figment)).await,
            Some(S::Templates(c)) => Box::pin(c.run(figment)).await,
            Some(S::Debug(c)) => Box::pin(c.run(figment)).await,
            Some(S::Doctor(c)) => Box::pin(c.run(figment)).await,
            Some(S::Syn2Mas(c)) => Box::pin(c.run(figment)).await,
            None => Box::pin(self::server::Options::default().run(figment)).await,
        }
    }

    /// Get a [`Figment`] instance with the configuration loaded
    pub fn figment(&self) -> Figment {
        let configs = if self.config.is_empty() {
            // Read the MAS_CONFIG environment variable
            std::env::var("MAS_CONFIG")
                // Default to "config.yaml"
                .unwrap_or_else(|_| "config.yaml".to_owned())
                // Split the file list on `:`
                .split(':')
                .map(Utf8PathBuf::from)
                .collect()
        } else {
            self.config.clone()
        };
        let base = Figment::new().merge(Env::prefixed("MAS_").split("_"));

        configs
            .into_iter()
            .fold(base, |f, path| f.admerge(Yaml::file(path)))
    }
}
