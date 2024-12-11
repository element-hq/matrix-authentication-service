// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

mod mas_writer;
mod synapse_reader;

mod checks;
mod migration;

pub use self::checks::synapse_pre_migration_checks;
pub use self::mas_writer::locking::LockedMasDatabase;
pub use self::mas_writer::{checks::mas_pre_migration_checks, MasWriter};
pub use self::migration::migrate;
pub use self::synapse_reader::SynapseReader;
