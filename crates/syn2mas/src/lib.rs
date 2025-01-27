// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod mas_writer;
mod synapse_reader;

mod migration;

pub use self::{
    mas_writer::{checks::mas_pre_migration_checks, locking::LockedMasDatabase, MasWriter},
    migration::migrate,
    synapse_reader::{
        checks::{
            synapse_config_check, synapse_config_check_against_mas_config, synapse_database_check,
        },
        config as synapse_config, SynapseReader,
    },
};
