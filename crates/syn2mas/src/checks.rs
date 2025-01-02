// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Checks
//!
//! This module provides safety checks to run against a Synapse database before running the Synapse-to-MAS migration.

use sqlx::PgConnection;
use thiserror::Error;

use crate::mas_writer;

#[derive(Debug, Error)]
pub enum Error {
    #[error("problem with MAS database: {0}")]
    MasDatabase(#[source] mas_writer::checks::Error),

    #[error("query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
}

#[tracing::instrument(skip_all)]
pub async fn synapse_pre_migration_checks(
    synapse_connection: &mut PgConnection,
) -> Result<(), Error> {
    // TODO check that the database looks like a Synapse database and is sane for migration
    Ok(())
}
