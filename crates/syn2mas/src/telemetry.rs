use std::sync::LazyLock;

use opentelemetry::{
    InstrumentationScope,
    metrics::{Counter, Gauge, Histogram, Meter},
};
use opentelemetry_semantic_conventions as semcov;

static SCOPE: LazyLock<InstrumentationScope> = LazyLock::new(|| {
    InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(semcov::SCHEMA_URL)
        .build()
});

pub static METER: LazyLock<Meter> =
    LazyLock::new(|| opentelemetry::global::meter_with_scope(SCOPE.clone()));

pub static APPROX_TOTAL_COUNTER: LazyLock<Gauge<u64>> = LazyLock::new(|| {
    METER
        .u64_gauge("syn2mas.entity.approx_total")
        .with_description("Approximate number of entities of this type to be migrated")
        .build()
});

pub static MIGRATED_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("syn2mas.entity.migrated")
        .with_description("Number of entities of this type that have been migrated so far")
        .build()
});

pub static SKIPPED_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("syn2mas.entity.skipped")
        .with_description("Number of entities of this type that have been skipped so far")
        .build()
});

pub static WRITER_FLUSH_TIME: LazyLock<Histogram<u64>> = LazyLock::new(|| {
    METER
        .u64_histogram("syn2mas.writer.flush_time")
        .with_description("Time spent flushing the writer")
        .with_unit("ms")
        .build()
});

/// Attribute key for syn2mas.entity metrics representing what entity.
pub const K_ENTITY: &str = "entity";

/// Attribute value for syn2mas.entity metrics representing users.
pub const V_ENTITY_USERS: &str = "users";
/// Attribute value for syn2mas.entity metrics representing devices.
pub const V_ENTITY_DEVICES: &str = "devices";
/// Attribute value for syn2mas.entity metrics representing threepids.
pub const V_ENTITY_THREEPIDS: &str = "threepids";
/// Attribute value for syn2mas.entity metrics representing external IDs.
pub const V_ENTITY_EXTERNAL_IDS: &str = "external_ids";
/// Attribute value for syn2mas.entity metrics representing non-refreshable
/// access token entities.
pub const V_ENTITY_NONREFRESHABLE_ACCESS_TOKENS: &str = "nonrefreshable_access_tokens";
/// Attribute value for syn2mas.entity metrics representing refreshable
/// access/refresh token pairs.
pub const V_ENTITY_REFRESHABLE_TOKEN_PAIRS: &str = "refreshable_token_pairs";
