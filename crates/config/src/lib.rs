// Copyright 2024 New Vector Ltd.
// Copyright 2021-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![deny(missing_docs, rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]
// derive(JSONSchema) uses &str.to_string()
#![allow(clippy::str_to_string)]

//! Application configuration logic

#[cfg(all(feature = "docker", feature = "dist"))]
compile_error!("Only one of the `docker` and `dist` features can be enabled at once");

pub(crate) mod schema;
mod sections;
pub(crate) mod util;

pub use self::{
    sections::*,
    util::{ConfigurationSection, ConfigurationSectionExt},
};
