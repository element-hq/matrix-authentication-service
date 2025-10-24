// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::{collections::BTreeSet, fmt::Write, process::ExitCode};

use anyhow::{Context as _, bail};
use camino::Utf8PathBuf;
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
    },
}

impl Options {
    pub async fn run(self, figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Check { out_dir } => {
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
                let all_renders = templates.check_render(clock.now(), &mut rng)?;

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

                    let all_locales: BTreeSet<&str> = all_renders
                        .iter()
                        .filter_map(|((_, sample_identifier), _)| {
                            sample_identifier.locale.as_deref()
                        })
                        .collect();
                    for locale in all_locales {
                        let locale_dir = out_dir.join(locale);
                        tokio::fs::create_dir(&locale_dir)
                            .await
                            .with_context(|| format!("could not create {locale_dir}"))?;
                    }

                    for ((template, sample_identifier), template_render) in &all_renders {
                        let (template_filename_base, template_ext) =
                            template.rsplit_once('.').unwrap_or((template, "txt"));
                        let template_filename_base = template_filename_base.replace('/', "_");

                        // Make a string like:
                        // - `-sample1`
                        // - `-session2-sample1`
                        let sample_suffix = {
                            let mut s = String::new();
                            if let Some(session_index) = sample_identifier.session_index {
                                write!(s, "-session{session_index}")?;
                            }
                            write!(s, "-sample{}", sample_identifier.index)?;
                            s
                        };

                        let locale_dir = if let Some(locale) = &sample_identifier.locale {
                            out_dir.join(locale)
                        } else {
                            out_dir.clone()
                        };

                        let render_path = locale_dir.join(format!(
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
