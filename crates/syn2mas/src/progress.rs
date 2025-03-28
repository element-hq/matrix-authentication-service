use std::sync::{Arc, atomic::AtomicU32};

use arc_swap::ArcSwap;

/// Tracker for the progress of the migration
///
/// Cloning this struct intuitively gives a 'handle' to the same counters,
/// which means it can be shared between tasks/threads.
#[derive(Clone)]
pub struct Progress {
    current_stage: Arc<ArcSwap<ProgressStage>>,
}

#[derive(Clone, Default)]
pub struct ProgressCounter {
    inner: Arc<ProgressCounterInner>,
}

#[derive(Default)]
struct ProgressCounterInner {
    migrated: AtomicU32,
    skipped: AtomicU32,
}

impl ProgressCounter {
    pub fn increment_migrated(&self) {
        self.inner
            .migrated
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn increment_skipped(&self) {
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
    pub fn migrating_data(&self, entity: &'static str, approx_count: usize) -> ProgressCounter {
        let counter = ProgressCounter::default();
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
        entity: &'static str,
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
