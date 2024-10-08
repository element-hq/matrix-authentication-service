//! # Synapse Database Reader
//!
//! This module provides facilities for streaming relevant types of database records from a Synapse database.

use async_stream::stream;
use chrono::{DateTime, Utc};
use futures_util::Stream;
use sea_query::{enum_def, Expr, Iden, PostgresQueryBuilder, Query};
use sea_query_binder::SqlxBinder;
use sqlx::{query, query_with, FromRow, PgConnection, Postgres, Row, Type};
use thiserror::Error;
use thiserror_ext::ContextInto;

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}: {source}")]
    Database {
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
#[derive(Clone, Debug)]
pub struct SynapseBool(pub bool);

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

/// A timestamp stored as the number of seconds since the Unix epoch.
/// Note that Synapse stores MOST timestamps as numbers of **milliseconds** since the Unix epoch.
/// But some timestamps are still stored in seconds.
#[derive(Clone, Debug)]
pub struct SecondsTimestamp(pub DateTime<Utc>);

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
#[enum_def(table_name = "users")]
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

#[derive(Iden)]
pub enum ExtraSynapseUserIden {
    AppserviceId,
    IsGuest,
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
    conn: &'c mut PgConnection,
}

impl<'conn> SynapseReader<'conn> {
    pub async fn new(
        synapse_connection: &'conn mut PgConnection,
        dry_run: bool,
    ) -> Result<Self, Error> {
        query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE READ ONLY DEFERRABLE;")
            .execute(&mut *synapse_connection)
            .await
            .into_database("begin transaction")?;

        let lock_type = if dry_run {
            // We expect dry runs to be done alongside Synapse running, so we don't want to
            // interfere with Synapse's database access in that case.
            "ACCESS SHARE"
        } else {
            "EXCLUSIVE"
        };
        for table in TABLES_TO_LOCK {
            query(&format!("LOCK TABLE {table} IN {lock_type} MODE NOWAIT;"))
                .execute(&mut *synapse_connection)
                .await
                .into_database_with(|| format!("locking Synapse table `{table}`"))?;
        }

        Ok(Self {
            conn: synapse_connection,
        })
    }

    pub async fn finish(self) -> Result<(), Error> {
        // TODO enforce that this is called somehow.

        query("COMMIT;")
            .execute(self.conn)
            .await
            .into_database("end transaction")?;
        Ok(())
    }

    pub async fn count_rows(&mut self) -> Result<SynapseRowCounts, Error> {
        // TODO no need for query builder here
        let (sql, args) = Query::select()
            .expr(Expr::val(1).count())
            .and_where(Expr::col(ExtraSynapseUserIden::AppserviceId).is_null())
            .and_where(Expr::col(ExtraSynapseUserIden::IsGuest).eq(0))
            .from(SynapseUserIden::Table)
            .build_sqlx(PostgresQueryBuilder);
        let users = query_with(&sql, args)
            .fetch_one(&mut *self.conn)
            .await
            .into_database("counting Synapse users")?
            .try_get::<i64, _>(0)
            .into_database("couldn't decode count of Synapse users table")?;

        Ok(SynapseRowCounts { users })
    }

    /// Reads Synapse users, excluding application service users (which do not need to be migrated), from the database.
    pub fn read_users<'a, 'ret>(
        &'a mut self,
    ) -> impl Stream<Item = Result<SynapseUser, Error>> + 'ret
    where
        'conn: 'a,
        'a: 'ret,
    {
        // TODO no need for query builder here
        let (sql, args) = Query::select()
            .columns([
                SynapseUserIden::Name,
                SynapseUserIden::PasswordHash,
                SynapseUserIden::Admin,
                SynapseUserIden::Deactivated,
                SynapseUserIden::CreationTs,
            ])
            .and_where(Expr::col(ExtraSynapseUserIden::AppserviceId).is_null())
            .and_where(Expr::col(ExtraSynapseUserIden::IsGuest).eq(0))
            .from(SynapseUserIden::Table)
            .build_sqlx(PostgresQueryBuilder);

        let conn = &mut *self.conn;

        // The async stream macro works around an issue where the QueryAs output stream borrows the SQL.
        // See: https://github.com/launchbadge/sqlx/issues/1594#issuecomment-1493146479
        stream! {
            for await row in sqlx::query_as_with::<_, SynapseUser, _>(&sql, args).fetch(conn) {
                yield row.into_database("reading Synapse users");
            }
        }
    }
}

#[cfg(test)]
mod test {
    // TODO test me
}
