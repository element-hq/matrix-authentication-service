// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::sync::{Arc, LazyLock, atomic::AtomicU32};

use arc_swap::ArcSwap;
use opentelemetry::{
    KeyValue,
    metrics::{Counter, Gauge},
};

use crate::telemetry::METER;

/// A gauge that tracks the approximate number of entities of a given type
/// that will be migrated.
pub static APPROX_TOTAL_GAUGE: LazyLock<Gauge<u64>> = LazyLock::new(|| {
    METER
        .u64_gauge("syn2mas.entity.approx_total")
        .with_description("Approximate number of entities of this type to be migrated")
        .build()
});

/// A counter that tracks the number of entities of a given type that have
/// been migrated so far.
pub static MIGRATED_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("syn2mas.entity.migrated")
        .with_description("Number of entities of this type that have been migrated so far")
        .build()
});

/// A counter that tracks the number of entities of a given type that have
/// been skipped so far.
pub static SKIPPED_COUNTER: LazyLock<Counter<u64>> = LazyLock::new(|| {
    METER
        .u64_counter("syn2mas.entity.skipped")
        .with_description("Number of entities of this type that have been skipped so far")
        .build()
});

/// Enum representing the different types of entities that syn2mas can migrate.
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
    /// Represents users
    Users,

    /// Represents devices
    Devices,

    /// Represents third-party IDs
    ThreePids,

    /// Represents external IDs
    ExternalIds,

    /// Represents non-refreshable access tokens
    NonRefreshableAccessTokens,

    /// Represents refreshable access tokens
    RefreshableTokens,
}

impl std::fmt::Display for EntityType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.name())
    }
}

impl EntityType {
    pub const fn name(self) -> &'static str {
        match self {
            Self::Users => "users",
            Self::Devices => "devices",
            Self::ThreePids => "threepids",
            Self::ExternalIds => "external_ids",
            Self::NonRefreshableAccessTokens => "nonrefreshable_access_tokens",
            Self::RefreshableTokens => "refreshable_tokens",
        }
    }

    pub fn as_kv(self) -> KeyValue {
        KeyValue::new("entity", self.name())
    }
}

/// Tracker for the progress of the migration
///
/// Cloning this struct intuitively gives a 'handle' to the same counters,
/// which means it can be shared between tasks/threads.
#[derive(Clone)]
pub struct Progress {
    current_stage: Arc<ArcSwap<ProgressStage>>,
}

#[derive(Clone)]
pub struct ProgressCounter {
    inner: Arc<ProgressCounterInner>,
}

struct ProgressCounterInner {
    kv: [KeyValue; 1],
    migrated: AtomicU32,
    skipped: AtomicU32,
}

impl ProgressCounter {
    fn new(entity: EntityType) -> Self {
        Self {
            inner: Arc::new(ProgressCounterInner {
                kv: [entity.as_kv()],
                migrated: AtomicU32::new(0),
                skipped: AtomicU32::new(0),
            }),
        }
    }

    pub fn increment_migrated(&self) {
        MIGRATED_COUNTER.add(1, &self.inner.kv);
        self.inner
            .migrated
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_skipped(&self) {
        SKIPPED_COUNTER.add(1, &self.inner.kv);
        self.inner
            .skipped
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    #[must_use]
    pub fn migrated(&self) -> u32 {
        self.inner
            .migrated
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[must_use]
    pub fn skipped(&self) -> u32 {
        self.inner
            .skipped
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

impl Progress {
    #[must_use]
    pub fn migrating_data(&self, entity: EntityType, approx_count: usize) -> ProgressCounter {
        let counter = ProgressCounter::new(entity);
        APPROX_TOTAL_GAUGE.record(approx_count as u64, &[entity.as_kv()]);
        self.set_current_stage(ProgressStage::MigratingData {
            entity,
            counter: counter.clone(),
            approx_count: approx_count as u64,
        });
        counter
    }

    pub fn rebuild_index(&self, index_name: String) {
        self.set_current_stage(ProgressStage::RebuildIndex { index_name });
    }

    pub fn rebuild_constraint(&self, constraint_name: String) {
        self.set_current_stage(ProgressStage::RebuildConstraint { constraint_name });
    }

    /// Sets the current stage of progress.
    ///
    /// This is probably not cheap enough to use for every individual row,
    /// so use of atomic integers for the fields that will be updated is
    /// recommended.
    #[inline]
    fn set_current_stage(&self, stage: ProgressStage) {
        self.current_stage.store(Arc::new(stage));
    }

    /// Returns the current stage of progress.
    #[inline]
    #[must_use]
    pub fn get_current_stage(&self) -> arc_swap::Guard<Arc<ProgressStage>> {
        self.current_stage.load()
    }
}

impl Default for Progress {
    fn default() -> Self {
        Self {
            current_stage: Arc::new(ArcSwap::new(Arc::new(ProgressStage::SettingUp))),
        }
    }
}

pub enum ProgressStage {
    SettingUp,
    MigratingData {
        entity: EntityType,
        counter: ProgressCounter,
        approx_count: u64,
    },
    RebuildIndex {
        index_name: String,
    },
    RebuildConstraint {
        constraint_name: String,
    },
}
