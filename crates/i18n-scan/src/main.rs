// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

// Without the custom_syntax feature, the `SyntaxConfig` is a unit struct
// which is annoying with this clippy lint
#![allow(clippy::default_constructed_unit_structs)]

use std::{fs::File, io::BufReader};

use ::minijinja::{machinery::WhitespaceConfig, syntax::SyntaxConfig};
use camino::Utf8PathBuf;
use clap::Parser;
use key::Context;
use mas_i18n::translations::TranslationTree;

mod key;
mod minijinja;

/// Scan a directory of templates for usage of the translation function and
/// output a translation tree.
#[derive(Parser)]
struct Options {
    /// The directory containing the templates
    templates: Utf8PathBuf,

    /// Path of the existing translation file
    existing: Option<Utf8PathBuf>,

    /// The extensions of the templates
    #[clap(long, default_value = "html,txt,subject")]
    extensions: String,

    /// The name of the translation function
    #[clap(long, default_value = "_")]
    function: String,

    /// Whether the existing translation file should be updated with missing
    /// keys in-place
    #[clap(long)]
    update: bool,
}

fn main() {
    tracing_subscriber::fmt::init();

    let options = Options::parse();

    // Open the existing translation file if one was provided
    let mut tree = if let Some(path) = &options.existing {
        let file = File::open(path).expect("Failed to open existing translation file");
        let mut reader = BufReader::new(file);
        serde_json::from_reader(&mut reader).expect("Failed to parse existing translation file")
    } else {
        TranslationTree::default()
    };

    let mut context = Context::new(options.function);

    for entry in walkdir::WalkDir::new(&options.templates) {
        let entry = entry.unwrap();
        if !entry.file_type().is_file() {
            continue;
        }

        let path: Utf8PathBuf = entry.into_path().try_into().expect("Non-UTF8 path");
        let relative = path.strip_prefix(&options.templates).expect("Invalid path");

        let Some(extension) = path.extension() else {
            continue;
        };

        if options.extensions.split(',').any(|e| e == extension) {
            tracing::debug!("Parsing {relative}");
            let template = std::fs::read_to_string(&path).expect("Failed to read template");
            match minijinja::parse(
                &template,
                relative.as_str(),
                SyntaxConfig::default(),
                WhitespaceConfig::default(),
            ) {
                Ok(ast) => {
                    context.set_current_file(relative.as_str());
                    minijinja::find_in_stmt(&mut context, &ast).unwrap();
                }
                Err(err) => {
                    tracing::error!("Failed to parse {relative}: {}", err);
                }
            }
        }
    }

    let count = context.add_missing(&mut tree);

    match count {
        0 => tracing::debug!("No missing keys"),
        1 => tracing::info!("Added 1 missing key"),
        count => tracing::info!("Added {} missing keys", count),
    }

    if options.update {
        let mut file = File::options()
            .write(true)
            .read(false)
            .truncate(true)
            .open(
                options
                    .existing
                    .expect("--update requires an existing translation file"),
            )
            .expect("Failed to open existing translation file");

        serde_json::to_writer_pretty(&mut file, &tree).expect("Failed to write translation tree");
    } else {
        serde_json::to_writer_pretty(std::io::stdout(), &tree)
            .expect("Failed to write translation tree");
    }

    // Just to make sure we don't end up with a trailing newline
    println!();
}
