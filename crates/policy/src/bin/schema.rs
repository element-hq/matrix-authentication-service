// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![expect(
    clippy::disallowed_types,
    reason = "We use Path/PathBuf instead of camino here for simplicity"
)]

use std::path::{Path, PathBuf};

use mas_policy::model::{
    AuthorizationGrantInput, ClientRegistrationInput, EmailInput, RegisterInput,
};
use schemars::{JsonSchema, generate::SchemaSettings};

fn write_schema<T: JsonSchema>(out_dir: Option<&Path>, file: &str) {
    let mut writer: Box<dyn std::io::Write> = if let Some(out_dir) = out_dir {
        let path = out_dir.join(file);
        eprintln!("Writing to {}", path.display());
        let file = std::fs::File::create(path).expect("Failed to create file");
        Box::new(std::io::BufWriter::new(file))
    } else {
        eprintln!("--- {file} ---");
        Box::new(std::io::stdout())
    };

    let generator = SchemaSettings::draft07().into_generator();
    let schema = generator.into_root_schema_for::<T>();
    serde_json::to_writer_pretty(&mut writer, &schema).expect("Failed to serialize schema");
    writer.flush().expect("Failed to flush writer");
}

/// Write the input schemas to the output directory.
/// They are then used in rego files to type check the input.
fn main() {
    let output_root = std::env::var("OUT_DIR").map(PathBuf::from).ok();
    let output_root = output_root.as_deref();

    write_schema::<RegisterInput>(output_root, "register_input.json");
    write_schema::<ClientRegistrationInput>(output_root, "client_registration_input.json");
    write_schema::<AuthorizationGrantInput>(output_root, "authorization_grant_input.json");
    write_schema::<EmailInput>(output_root, "email_input.json");
}
