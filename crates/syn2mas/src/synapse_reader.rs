// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # Synapse Database Reader
//!
//! This module provides facilities for streaming relevant types of database records from a Synapse database.

use chrono::{DateTime, Utc};
use futures_util::{Stream, TryStreamExt};
use sqlx::{query, Acquire, FromRow, PgConnection, Postgres, Row, Transaction, Type};
use thiserror::Error;
use thiserror_ext::ContextInto;

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}")]
    Database {
        #[source]
        source: sqlx::Error,
        context: String,
    },
}

#[derive(Clone, Debug, sqlx::Decode)]
pub struct FullUserId(pub String);

impl Type<Postgres> for FullUserId {
    fn type_info() -> <sqlx::Postgres as sqlx::Database>::TypeInfo {
        <String as Type<Postgres>>::type_info()
    }
}

#[derive(Debug, Error)]
pub enum ExtractLocalpartError {
    #[error("user ID does not start with `@` sigil")]
    NoAtSigil,
    #[error("user ID does not have a `:` separator")]
    NoSeparator,
    #[error("wrong server name: expected {expected:?}, got {found:?}")]
    WrongServerName { expected: String, found: String },
}

impl FullUserId {
    /// Extract the localpart from the User ID, asserting that the User ID has the correct
    /// server name.
    ///
    /// # Errors
    ///
    /// A handful of basic validity checks are performed and an error may be returned
    /// if the User ID is not valid.
    /// However, the User ID grammar is not checked fully.
    ///
    /// If the wrong server name is asserted, returns an error.
    pub fn extract_localpart(
        &self,
        expected_server_name: &str,
    ) -> Result<&str, ExtractLocalpartError> {
        let Some(without_sigil) = self.0.strip_prefix('@') else {
            return Err(ExtractLocalpartError::NoAtSigil);
        };

        let Some((localpart, server_name)) = without_sigil.split_once(':') else {
            return Err(ExtractLocalpartError::NoSeparator);
        };

        if server_name != expected_server_name {
            return Err(ExtractLocalpartError::WrongServerName {
                expected: expected_server_name.to_owned(),
                found: server_name.to_owned(),
            });
        };

        Ok(localpart)
    }
}

/// A Synapse boolean.
/// Synapse stores booleans as 0 or 1, due to compatibility with old SQLite versions
/// that did not have native boolean support.
#[derive(Copy, Clone, Debug)]
pub struct SynapseBool(bool);

impl<'r> sqlx::Decode<'r, Postgres> for SynapseBool {
    fn decode(
        value: <Postgres as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        <i16 as sqlx::Decode<Postgres>>::decode(value)
            .map(|boolean_int| SynapseBool(boolean_int != 0))
    }
}

impl sqlx::Type<Postgres> for SynapseBool {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <i16 as sqlx::Type<Postgres>>::type_info()
    }
}

impl From<SynapseBool> for bool {
    fn from(SynapseBool(value): SynapseBool) -> Self {
        value
    }
}

/// A timestamp stored as the number of seconds since the Unix epoch.
/// Note that Synapse stores MOST timestamps as numbers of **milliseconds** since the Unix epoch.
/// But some timestamps are still stored in seconds.
#[derive(Copy, Clone, Debug)]
pub struct SecondsTimestamp(DateTime<Utc>);

impl From<SecondsTimestamp> for DateTime<Utc> {
    fn from(SecondsTimestamp(value): SecondsTimestamp) -> Self {
        value
    }
}

impl<'r> sqlx::Decode<'r, Postgres> for SecondsTimestamp {
    fn decode(
        value: <Postgres as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        <i64 as sqlx::Decode<Postgres>>::decode(value).map(|milliseconds_since_epoch| {
            SecondsTimestamp(DateTime::from_timestamp_nanos(
                milliseconds_since_epoch * 1_000_000_000,
            ))
        })
    }
}

impl sqlx::Type<Postgres> for SecondsTimestamp {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<Postgres>>::type_info()
    }
}

#[derive(Clone, Debug, FromRow)]
pub struct SynapseUser {
    /// Full User ID of the user
    pub name: FullUserId,
    /// Password hash string for the user. Optional (null if no password is set).
    pub password_hash: Option<String>,
    /// Whether the user is a Synapse Admin
    pub admin: SynapseBool,
    /// Whether the user is deactivated
    pub deactivated: SynapseBool,
    /// When the user was created
    pub creation_ts: SecondsTimestamp,
    // TODO ...
    // TODO is_guest
    // TODO do we care about upgrade_ts (users who upgraded from guest accounts to real accounts)
}

/// List of Synapse tables that we should acquire an `EXCLUSIVE` lock on.
///
/// This is a safety measure against other processes changing the data underneath our feet.
/// It's still not a good idea to run Synapse at the same time as the migration.
// TODO not complete!
const TABLES_TO_LOCK: &[&str] = &["users"];

/// Number of migratable rows in various Synapse tables.
/// Used to estimate progress.
#[derive(Clone, Debug)]
pub struct SynapseRowCounts {
    pub users: i64,
}

pub struct SynapseReader<'c> {
    txn: Transaction<'c, Postgres>,
}

impl<'conn> SynapseReader<'conn> {
    /// Create a new Synapse reader, which entails creating a transaction and locking Synapse tables.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    /// - If we can't lock the Synapse tables (pointing to the fact that Synapse may still be running)
    pub async fn new(
        synapse_connection: &'conn mut PgConnection,
        dry_run: bool,
    ) -> Result<Self, Error> {
        let mut txn = synapse_connection
            .begin()
            .await
            .into_database("begin transaction")?;

        query("SET TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE;")
            .execute(&mut *txn)
            .await
            .into_database("set transaction")?;

        let lock_type = if dry_run {
            // We expect dry runs to be done alongside Synapse running, so we don't want to
            // interfere with Synapse's database access in that case.
            "ACCESS SHARE"
        } else {
            "EXCLUSIVE"
        };
        for table in TABLES_TO_LOCK {
            query(&format!("LOCK TABLE {table} IN {lock_type} MODE NOWAIT;"))
                .execute(&mut *txn)
                .await
                .into_database_with(|| format!("locking Synapse table `{table}`"))?;
        }

        Ok(Self { txn })
    }

    /// Finishes the Synapse reader, committing the transaction.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error whilst committing the transaction.
    pub async fn finish(self) -> Result<(), Error> {
        // TODO enforce that this is called somehow.
        self.txn.commit().await.into_database("end transaction")?;
        Ok(())
    }

    /// Counts the rows in the Synapse database to get an estimate of how large the migration is going to be.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    pub async fn count_rows(&mut self) -> Result<SynapseRowCounts, Error> {
        let users = sqlx::query(
            "
            SELECT COUNT(1) FROM users
            WHERE appservice_id IS NULL AND is_guest = 0
            ",
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("counting Synapse users")?
        .try_get::<i64, _>(0)
        .into_database("couldn't decode count of Synapse users table")?;

        Ok(SynapseRowCounts { users })
    }

    /// Reads Synapse users, excluding application service users (which do not need to be migrated), from the database.
    pub fn read_users(&mut self) -> impl Stream<Item = Result<SynapseUser, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              name, password_hash, admin, deactivated, creation_ts
            FROM users
            WHERE appservice_id IS NULL AND is_guest = 0
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse users"))
    }
}

#[cfg(test)]
mod test {
    // TODO test me
}
