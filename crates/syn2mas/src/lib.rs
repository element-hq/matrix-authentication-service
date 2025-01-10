// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod mas_writer;
mod synapse_reader;

mod migration;

pub use self::mas_writer::locking::LockedMasDatabase;
pub use self::mas_writer::{checks::mas_pre_migration_checks, MasWriter};
pub use self::migration::migrate;
pub use self::synapse_reader::checks::{
    synapse_config_check, synapse_config_check_against_mas_config, synapse_database_check,
};
pub use self::synapse_reader::config as synapse_config;
pub use self::synapse_reader::SynapseReader;
