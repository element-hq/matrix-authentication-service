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

impl Progress {
    /// Sets the current stage of progress.
    ///
    /// This is probably not cheap enough to use for every individual row,
    /// so use of atomic integers for the fields that will be updated is
    /// recommended.
    #[inline]
    pub fn set_current_stage(&self, stage: ProgressStage) {
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
        migrated: Arc<AtomicU32>,
        approx_count: u64,
    },
    RebuildIndex {
        index_name: String,
    },
    RebuildConstraint {
        constraint_name: String,
    },
}
