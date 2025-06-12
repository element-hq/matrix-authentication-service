// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use schemars::{
    generate::SchemaSettings,
    transform::{AddNullable, RecursiveTransform},
};

fn main() {
    let generator = SchemaSettings::draft07()
        .with_transform(RecursiveTransform(AddNullable::default()))
        .into_generator();
    let schema = generator.into_root_schema_for::<mas_config::RootConfig>();

    serde_json::to_writer_pretty(std::io::stdout(), &schema).expect("Failed to serialize schema");
}
