// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::num::NonZeroUsize;

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::ConfigurationSection;

/// Configuration related to the asynchronous runtime
#[derive(Clone, Debug, Default, Serialize, Deserialize, JsonSchema)]
pub struct RuntimeConfig {
    /// Number of worker threads running asynchronous tasks
    ///
    /// Defaults to the number of CPU cores available. With `1`, all tasks run
    /// on the main thread.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker_threads: Option<NonZeroUsize>,

    /// Maximum number of threads used for blocking operations, like password
    /// hashing and template rendering
    ///
    /// Threads are spawned on demand up to this limit. Defaults to 512.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_blocking_threads: Option<NonZeroUsize>,
}

impl RuntimeConfig {
    /// Returns true if all fields are at their default values
    pub(crate) fn is_default(&self) -> bool {
        self.worker_threads.is_none() && self.max_blocking_threads.is_none()
    }
}

impl ConfigurationSection for RuntimeConfig {
    const PATH: Option<&'static str> = Some("runtime");
}
