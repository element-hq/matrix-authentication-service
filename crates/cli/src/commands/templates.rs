// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{fmt::Write, process::ExitCode};

use anyhow::{Context as _, bail};
use camino::Utf8PathBuf;
use chrono::DateTime;
use clap::Parser;
use figment::Figment;
use mas_config::{
    AccountConfig, BrandingConfig, CaptchaConfig, ConfigurationSection, ConfigurationSectionExt,
    ExperimentalConfig, MatrixConfig, PasswordsConfig, TemplatesConfig,
};
use mas_data_model::{Clock, SystemClock};
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
    Check {
        /// If set, templates will be rendered to this directory.
        /// The directory must either not exist or be empty.
        #[arg(long = "out-dir")]
        out_dir: Option<Utf8PathBuf>,

        /// Attempt to remove 'unstable' template input data such as asset
        /// hashes, in order to make renders more reproducible between
        /// versions.
        #[arg(long = "stabilise")]
        stabilise: bool,
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Check { out_dir, stabilise } => {
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

                let now = if stabilise {
                    DateTime::from_timestamp_secs(0).unwrap()
                } else {
                    SystemClock::default().now()
                };
                let rng = if stabilise {
                    rand_chacha::ChaChaRng::from_seed([42; 32])
                } else {
                    // XXX: we should disallow SeedableRng::from_entropy
                    rand_chacha::ChaChaRng::from_entropy()
                };
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
                let templates = templates_from_config(
                    &template_config,
                    &site_config,
                    &url_builder, // Use strict mode in template checks
                    true,
                )
                .await?;
                let all_renders = templates.check_render(now, &rng)?;

                if let Some(out_dir) = out_dir {
                    // Save renders to disk.
                    if out_dir.exists() {
                        let mut read_dir =
                            tokio::fs::read_dir(&out_dir).await.with_context(|| {
                                format!("could not read {out_dir} to check it's empty")
                            })?;
                        if read_dir.next_entry().await?.is_some() {
                            bail!("Render directory {out_dir} is not empty, refusing to write.");
                        }
                    } else {
                        tokio::fs::create_dir(&out_dir)
                            .await
                            .with_context(|| format!("could not create {out_dir}"))?;
                    }

                    for ((template, sample_identifier), template_render) in &all_renders {
                        let (template_filename_base, template_ext) =
                            template.rsplit_once('.').unwrap_or((template, "txt"));
                        let template_filename_base = template_filename_base.replace('/', "_");

                        // Make a string like `-index=0-browser-session=0-locale=fr`
                        let sample_suffix = {
                            let mut s = String::new();
                            for (k, v) in &sample_identifier.components {
                                write!(s, "-{k}={v}")?;
                            }
                            s
                        };

                        let render_path = out_dir.join(format!(
                            "{template_filename_base}{sample_suffix}.{template_ext}"
                        ));

                        tokio::fs::write(&render_path, template_render.as_bytes())
                            .await
                            .with_context(|| format!("could not write render to {render_path}"))?;
                    }
                }

                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
