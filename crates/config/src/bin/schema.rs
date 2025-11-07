// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use schemars::generate::SchemaSettings;

fn main() {
    let generator = SchemaSettings::draft07().into_generator();
    let schema = generator.into_root_schema_for::<mas_config::RootConfig>();

    serde_json::to_writer_pretty(std::io::stdout(), &schema).expect("Failed to serialize schema");
}
