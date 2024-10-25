// Copyright 2024 New Vector Ltd.
// Copyright 2022-2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! Utilities to do HTTP requests

#![deny(rustdoc::missing_crate_level_docs)]
#![allow(clippy::module_name_repetitions)]

use std::sync::LazyLock;

mod ext;
mod reqwest;

pub use self::{
    ext::{set_propagator, CorsLayerExt},
    reqwest::{client as reqwest_client, RequestBuilderExt},
};

static METER: LazyLock<opentelemetry::metrics::Meter> = LazyLock::new(|| {
    opentelemetry::global::meter_with_version(
        env!("CARGO_PKG_NAME"),
        Some(env!("CARGO_PKG_VERSION")),
        Some(opentelemetry_semantic_conventions::SCHEMA_URL),
        None,
    )
});
