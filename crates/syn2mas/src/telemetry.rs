use std::sync::LazyLock;

use opentelemetry::{InstrumentationScope, metrics::Meter};
use opentelemetry_semantic_conventions as semcov;

static SCOPE: LazyLock<InstrumentationScope> = LazyLock::new(|| {
    InstrumentationScope::builder(env!("CARGO_PKG_NAME"))
        .with_version(env!("CARGO_PKG_VERSION"))
        .with_schema_url(semcov::SCHEMA_URL)
        .build()
});

pub static METER: LazyLock<Meter> =
    LazyLock::new(|| opentelemetry::global::meter_with_scope(SCOPE.clone()));

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
