// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Common schema definitions

use schemars::{
    JsonSchema,
    r#gen::SchemaGenerator,
    schema::{InstanceType, Metadata, Schema, SchemaObject, StringValidation},
};

/// A type to use for schema definitions of ULIDs
///
/// Use with `#[schemars(with = "crate::admin::schema::Ulid")]`
pub struct Ulid;

impl JsonSchema for Ulid {
    fn schema_name() -> String {
        "ULID".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),

            metadata: Some(Box::new(Metadata {
                title: Some("ULID".into()),
                description: Some("A ULID as per https://github.com/ulid/spec".into()),
                examples: vec![
                    "01ARZ3NDEKTSV4RRFFQ69G5FAV".into(),
                    "01J41912SC8VGAQDD50F6APK91".into(),
                ],
                ..Metadata::default()
            })),

            string: Some(Box::new(StringValidation {
                pattern: Some(r"^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$".into()),
                ..StringValidation::default()
            })),

            ..SchemaObject::default()
        }
        .into()
    }
}

/// A type to use for schema definitions of device IDs
///
/// Use with `#[schemars(with = "crate::admin::schema::Device")]`
pub struct Device;

impl JsonSchema for Device {
    fn schema_name() -> String {
        "DeviceID".to_owned()
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        SchemaObject {
            instance_type: Some(InstanceType::String.into()),

            metadata: Some(Box::new(Metadata {
                title: Some("Device ID".into()),
                examples: vec!["AABBCCDDEE".into(), "FFGGHHIIJJ".into()],
                ..Metadata::default()
            })),

            string: Some(Box::new(StringValidation {
                pattern: Some(r"^[A-Za-z0-9._~!$&'()*+,;=:&/-]+$".into()),
                ..StringValidation::default()
            })),

            ..SchemaObject::default()
        }
        .into()
    }
}
