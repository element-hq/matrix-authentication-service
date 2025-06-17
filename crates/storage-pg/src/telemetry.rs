// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::LazyLock;

use opentelemetry::{
    InstrumentationScope,
    metrics::{Histogram, Meter},
};
use opentelemetry_semantic_conventions as semcov;

static SCOPE: LazyLock<InstrumentationScope> = LazyLock::new(|| {
    InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(semcov::SCHEMA_URL)
        .build()
});

static METER: LazyLock<Meter> =
    LazyLock::new(|| opentelemetry::global::meter_with_scope(SCOPE.clone()));

pub(crate) static DB_CLIENT_CONNECTIONS_CREATE_TIME_HISTOGRAM: LazyLock<Histogram<u64>> =
    LazyLock::new(|| {
        METER
            .u64_histogram("db.client.connections.create_time")
            .with_description("The time it took to create a new connection.")
            .with_unit("ms")
            .build()
    });
