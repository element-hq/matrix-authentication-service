// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::process::ExitCode;

use clap::Parser;
use figment::Figment;
use mas_config::{ConfigurationSectionExt, PolicyConfig};
use tracing::{info, info_span};

use crate::util::policy_factory_from_config;

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check that the policies compile
    Policy,
}

impl Options {
    #[tracing::instrument(skip_all)]
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Policy => {
                let _span = info_span!("cli.debug.policy").entered();
                let config = PolicyConfig::extract_or_default(figment)?;
                info!("Loading and compiling the policy module");
                let policy_factory = policy_factory_from_config(&config).await?;

                let _instance = policy_factory.instantiate().await?;
            }
        }

        Ok(ExitCode::SUCCESS)
    }
}
