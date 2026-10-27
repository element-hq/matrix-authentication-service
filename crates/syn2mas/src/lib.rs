// Copyright 2025, 2026 Element Creations Ltd.
// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

#![expect(
    clippy::redundant_field_names,
    reason = "`thiserror_ext::ContextInto` generates `source: source` in its constructors"
)]

mod mas_writer;
mod synapse_reader;

mod migration;
mod progress;
mod telemetry;

type RandomState = rustc_hash::FxBuildHasher;
type HashMap<K, V> = rustc_hash::FxHashMap<K, V>;

pub use self::{
    mas_writer::{MasWriter, checks::mas_pre_migration_checks, locking::LockedMasDatabase},
    migration::migrate,
    progress::{Progress, ProgressCounter, ProgressStage},
    synapse_reader::{
        SynapseReader,
        checks::{
            synapse_config_check, synapse_config_check_against_mas_config, synapse_database_check,
        },
        config as synapse_config,
    },
};
