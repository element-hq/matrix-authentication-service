// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! Shared with `build.rs`: a precompiled module only loads into an engine
//! whose settings match the ones it was compiled with.

use wasmtime::{Config, OptLevel};

pub fn config() -> Config {
    let mut config = Config::default();
    config.cranelift_opt_level(OptLevel::SpeedAndSize);
    config
}
