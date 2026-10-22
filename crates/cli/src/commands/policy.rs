// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::process::ExitCode;

use anyhow::Context as _;
use camino::Utf8PathBuf;
use clap::Parser;
use figment::Figment;
use tracing::{info, info_span};

#[derive(Parser, Debug)]
pub(super) struct Options {
    #[command(subcommand)]
    subcommand: Subcommand,
}

#[derive(Parser, Debug)]
enum Subcommand {
    /// Compile a WASM policy ahead of time, so that loading it does not need
    /// to compile it on every startup
    ///
    /// The output only works with this exact version of MAS, on the same
    /// architecture and OS as this binary. It can be used as
    /// `policy.wasm_module`, or put as `policy.cwasm` next to the default
    /// `policy.wasm`. The SHA-256 digest of the input is written next to it,
    /// with a `.source.sha256` suffix.
    Precompile {
        /// Path to the WASM policy
        input: Utf8PathBuf,

        /// Where to write the precompiled policy
        output: Utf8PathBuf,
    },
}

impl Options {
    pub async fn run(self, _figment: &Figment) -> anyhow::Result<ExitCode> {
        use Subcommand as SC;
        match self.subcommand {
            SC::Precompile { input, output } => {
                let _span = info_span!("cli.policy.precompile").entered();

                let wasm = tokio::fs::read(&input)
                    .await
                    .with_context(|| format!("failed to read {input}"))?;

                if mas_policy::is_precompiled(&wasm) {
                    anyhow::bail!("{input} is already precompiled");
                }

                let digest = mas_policy::source_digest(&wasm);

                let precompiled =
                    tokio::task::spawn_blocking(move || mas_policy::precompile(&wasm))
                        .await?
                        .map_err(anyhow::Error::from)
                        .with_context(|| format!("failed to compile {input}"))?;

                tokio::fs::write(&output, &precompiled)
                    .await
                    .with_context(|| format!("failed to write {output}"))?;

                let digest_path = format!("{output}{}", mas_policy::SOURCE_DIGEST_SUFFIX);
                tokio::fs::write(&digest_path, format!("{digest}\n"))
                    .await
                    .with_context(|| format!("failed to write {digest_path}"))?;

                info!(%input, %output, size = precompiled.len(), "Policy precompiled");
                Ok(ExitCode::SUCCESS)
            }
        }
    }
}
