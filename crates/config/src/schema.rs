// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Useful JSON Schema definitions

use schemars::{
    gen::SchemaGenerator,
    schema::{InstanceType, Schema, SchemaObject},
    JsonSchema,
};

/// A network hostname
pub struct Hostname;

impl JsonSchema for Hostname {
    fn schema_name() -> String {
        "Hostname".to_string()
    }

    fn json_schema(gen: &mut SchemaGenerator) -> Schema {
        hostname(gen)
    }
}

fn hostname(_gen: &mut SchemaGenerator) -> Schema {
    Schema::Object(SchemaObject {
        instance_type: Some(InstanceType::String.into()),
        format: Some("hostname".to_owned()),
        ..SchemaObject::default()
    })
}
