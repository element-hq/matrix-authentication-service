//! # Checks
//!
//! This module provides safety checks to run against a Synapse database before running the Synapse-to-MAS migration.

use sqlx::PgConnection;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("the MAS database is not empty")]
    MasDatabaseNotEmpty,

    #[error("query failed: {0}")]
    Sqlx(#[from] sqlx::Error),
}

pub async fn pre_migration_checks(
    synapse_connection: &mut PgConnection,
    mas_connection: &mut PgConnection,
) -> Result<(), Error> {
    mas_pre_migration_checks(mas_connection).await?;
    synapse_pre_migration_checks(synapse_connection).await?;
    Ok(())
}

pub async fn synapse_pre_migration_checks(
    synapse_connection: &mut PgConnection,
) -> Result<(), Error> {
    // TODO check that the database looks like a Synapse database
    Ok(())
}

pub async fn mas_pre_migration_checks(mas_connection: &mut PgConnection) -> Result<(), Error> {
    // TODO check that the database looks like a MAS database

    // Check that there are no users in the database.
    if sqlx::query!("SELECT 1 AS \"dummy\" FROM users LIMIT 1")
        .fetch_optional(&mut *mas_connection)
        .await?
        .is_some()
    {
        return Err(Error::MasDatabaseNotEmpty);
    }

    Ok(())
}
