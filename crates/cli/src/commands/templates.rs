// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::process::ExitCode;

use clap::Parser;
use figment::Figment;
use mas_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, ConfigurationSection, ConfigurationSectionExt,
    ExperimentalConfig, MatrixConfig, PasswordsConfig, TemplatesConfig,
};
use mas_storage::{Clock, SystemClock};
use rand::SeedableRng;
use tracing::info_span;

use crate::util::{site_config_from_config, templates_from_config};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[clap(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Check that the templates specified in the config are valid
    Check,
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Check => {
                let _span = info_span!("cli.templates.check").entered();

                let template_config = TemplatesConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let branding_config = BrandingConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let matrix_config =
                    MatrixConfig::extract(figment).map_err(anyhow::Error::from_boxed)?;
                let experimental_config = ExperimentalConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let password_config = PasswordsConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let account_config = AccountConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;
                let captcha_config = CaptchaConfig::extract_or_default(figment)
                    .map_err(anyhow::Error::from_boxed)?;

                let clock = SystemClock::default();
                // XXX: we should disallow SeedableRng::from_entropy
                let mut rng = rand_chacha::ChaChaRng::from_entropy();
                let url_builder =
                    mas_router::UrlBuilder::new("https://example.com/".parse()?, None, None);
                let site_config = site_config_from_config(
                    &branding_config,
                    &matrix_config,
                    &experimental_config,
                    &password_config,
                    &account_config,
                    &captcha_config,
                )?;
                let templates =
                    templates_from_config(&template_config, &site_config, &url_builder).await?;
                templates.check_render(clock.now(), &mut rng)?;

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
