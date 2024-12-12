// Copyright 2024 New Vector Ltd.
// Copyright 2023, 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

#![allow(clippy::module_name_repetitions)]

mod metrics;
mod trace_context;
mod tracing;
mod utils;

pub use self::{metrics::*, trace_context::*, tracing::*, utils::*};

fn meter() -> opentelemetry::metrics::Meter {
    let scope = opentelemetry::InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(opentelemetry_semantic_conventions::SCHEMA_URL)
        .build();

    opentelemetry::global::meter_with_scope(scope)
}
