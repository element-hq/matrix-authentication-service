// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::process::ExitCode;

use clap::Parser;
use figment::Figment;
use mas_config::{
    ConfigurationSection, ConfigurationSectionExt, DatabaseConfig, MatrixConfig, PolicyConfig,
};
use tracing::{info, info_span};

use crate::util::{
    database_pool_from_config, load_policy_factory_dynamic_data, policy_factory_from_config,
};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check that the policies compile
    Policy {
        /// With dynamic data loaded
        #[arg(long)]
        with_dynamic_data: bool,
    },
}

impl Options {
    #[tracing::instrument(skip_all)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Policy { with_dynamic_data } => {
                let _span = info_span!("cli.debug.policy").entered();
                let config = PolicyConfig::extract_or_default(figment)?;
                let matrix_config = MatrixConfig::extract(figment)?;
                info!("Loading and compiling the policy module");
                let policy_factory = policy_factory_from_config(&config, &matrix_config).await?;

                if with_dynamic_data {
                    let database_config = DatabaseConfig::extract(figment)?;
                    let pool = database_pool_from_config(&database_config).await?;
                    load_policy_factory_dynamic_data(&policy_factory, &pool).await?;
                }

                let _instance = policy_factory.instantiate().await?;
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
