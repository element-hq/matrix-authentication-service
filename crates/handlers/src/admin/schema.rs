// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Common schema definitions

use std::borrow::Cow;

use schemars::{JsonSchema, Schema, SchemaGenerator, json_schema};

/// A type to use for schema definitions of ULIDs
///
/// Use with `#[schemars(with = "crate::admin::schema::Ulid")]`
pub struct Ulid;

impl JsonSchema for Ulid {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("ULID")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "title": "ULID",
            "description": "A ULID as per https://github.com/ulid/spec",
            "examples": [
                "01ARZ3NDEKTSV4RRFFQ69G5FAV",
                "01J41912SC8VGAQDD50F6APK91",
            ],
            "pattern": "^[0123456789ABCDEFGHJKMNPQRSTVWXYZ]{26}$",
        })
    }
}

/// A type to use for schema definitions of device IDs
///
/// Use with `#[schemars(with = "crate::admin::schema::Device")]`
pub struct Device;

impl JsonSchema for Device {
    fn schema_name() -> Cow<'static, str> {
        Cow::Borrowed("DeviceID")
    }

    fn json_schema(_gen: &mut SchemaGenerator) -> Schema {
        json_schema!({
            "type": "string",
            "title": "Device ID",
            "description": "A device ID as per https://matrix.org/docs/spec/client_server/r0.6.0#device-ids",
            "examples": [
                "AABBCCDDEE",
                "FFGGHHIIJJ",
            ],
            "pattern": "^[A-Za-z0-9._~!$&'()*+,;=:&/-]+$",
        })
    }
}
