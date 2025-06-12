// Copyright 2024, 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! # Synapse Database Reader
//!
//! This module provides facilities for streaming relevant types of database
//! records from a Synapse database.

use std::fmt::Display;

use chrono::{DateTime, Utc};
use futures_util::{Stream, TryStreamExt};
use sqlx::{Acquire, FromRow, PgConnection, Postgres, Transaction, Type, query};
use thiserror::Error;
use thiserror_ext::ContextInto;

pub mod checks;
pub mod config;

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}")]
    Database {
        #[source]
        source: sqlx::Error,
        context: String,
    },
}

#[derive(Clone, Debug, sqlx::Decode, PartialEq, Eq, PartialOrd, Ord)]
pub struct FullUserId(pub String);

impl Display for FullUserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

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
    /// Extract the localpart from the User ID, asserting that the User ID has
    /// the correct server name.
    ///
    /// # Errors
    ///
    /// A handful of basic validity checks are performed and an error may be
    /// returned if the User ID is not valid.
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
        }

        Ok(localpart)
    }
}

/// A Synapse boolean.
/// Synapse stores booleans as 0 or 1, due to compatibility with old SQLite
/// versions that did not have native boolean support.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
/// Note that Synapse stores MOST timestamps as numbers of **milliseconds**
/// since the Unix epoch. But some timestamps are still stored in seconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
        <i64 as sqlx::Decode<Postgres>>::decode(value).map(|seconds_since_epoch| {
            SecondsTimestamp(DateTime::from_timestamp_nanos(
                seconds_since_epoch * 1_000_000_000,
            ))
        })
    }
}

impl sqlx::Type<Postgres> for SecondsTimestamp {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<Postgres>>::type_info()
    }
}

/// A timestamp stored as the number of milliseconds since the Unix epoch.
/// Note that Synapse stores some timestamps in seconds.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MillisecondsTimestamp(DateTime<Utc>);

impl From<MillisecondsTimestamp> for DateTime<Utc> {
    fn from(MillisecondsTimestamp(value): MillisecondsTimestamp) -> Self {
        value
    }
}

impl<'r> sqlx::Decode<'r, Postgres> for MillisecondsTimestamp {
    fn decode(
        value: <Postgres as sqlx::Database>::ValueRef<'r>,
    ) -> Result<Self, sqlx::error::BoxDynError> {
        <i64 as sqlx::Decode<Postgres>>::decode(value).map(|milliseconds_since_epoch| {
            MillisecondsTimestamp(DateTime::from_timestamp_nanos(
                milliseconds_since_epoch * 1_000_000,
            ))
        })
    }
}

impl sqlx::Type<Postgres> for MillisecondsTimestamp {
    fn type_info() -> <Postgres as sqlx::Database>::TypeInfo {
        <i64 as sqlx::Type<Postgres>>::type_info()
    }
}

#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseUser {
    /// Full User ID of the user
    pub name: FullUserId,
    /// Password hash string for the user. Optional (null if no password is
    /// set).
    pub password_hash: Option<String>,
    /// Whether the user is a Synapse Admin
    pub admin: SynapseBool,
    /// Whether the user is deactivated
    pub deactivated: SynapseBool,
    /// Whether the user is locked
    pub locked: bool,
    /// When the user was created
    pub creation_ts: SecondsTimestamp,
    /// Whether the user is a guest.
    /// Note that not all numeric user IDs are guests; guests can upgrade their
    /// account!
    pub is_guest: SynapseBool,
    /// The ID of the appservice that created this user, if any.
    pub appservice_id: Option<String>,
}

/// Row of the `user_threepids` table in Synapse.
#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseThreepid {
    pub user_id: FullUserId,
    pub medium: String,
    pub address: String,
    pub added_at: MillisecondsTimestamp,
}

/// Row of the `user_external_ids` table in Synapse.
#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseExternalId {
    pub user_id: FullUserId,
    pub auth_provider: String,
    pub external_id: String,
}

/// Row of the `devices` table in Synapse.
#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseDevice {
    pub user_id: FullUserId,
    pub device_id: String,
    pub display_name: Option<String>,
    pub last_seen: Option<MillisecondsTimestamp>,
    pub ip: Option<String>,
    pub user_agent: Option<String>,
}

/// Row of the `access_tokens` table in Synapse.
#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseAccessToken {
    pub user_id: FullUserId,
    pub device_id: Option<String>,
    pub token: String,
    pub valid_until_ms: Option<MillisecondsTimestamp>,
    pub last_validated: Option<MillisecondsTimestamp>,
}

/// Row of the `refresh_tokens` table in Synapse.
#[derive(Clone, Debug, FromRow, PartialEq, Eq, PartialOrd, Ord)]
pub struct SynapseRefreshableTokenPair {
    pub user_id: FullUserId,
    pub device_id: String,
    pub access_token: String,
    pub refresh_token: String,
    pub valid_until_ms: Option<MillisecondsTimestamp>,
    pub last_validated: Option<MillisecondsTimestamp>,
}

/// List of Synapse tables that we should acquire an `EXCLUSIVE` lock on.
///
/// This is a safety measure against other processes changing the data
/// underneath our feet. It's still not a good idea to run Synapse at the same
/// time as the migration.
const TABLES_TO_LOCK: &[&str] = &[
    "users",
    "user_threepids",
    "user_external_ids",
    "devices",
    "access_tokens",
    "refresh_tokens",
];

/// Number of migratable rows in various Synapse tables.
/// Used to estimate progress.
#[derive(Clone, Debug)]
pub struct SynapseRowCounts {
    pub users: usize,
    pub devices: usize,
    pub threepids: usize,
    pub external_ids: usize,
    pub access_tokens: usize,
    pub refresh_tokens: usize,
}

pub struct SynapseReader<'c> {
    txn: Transaction<'c, Postgres>,
}

impl<'conn> SynapseReader<'conn> {
    /// Create a new Synapse reader, which entails creating a transaction and
    /// locking Synapse tables.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    /// - If we can't lock the Synapse tables (pointing to the fact that Synapse
    ///   may still be running)
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
        self.txn.commit().await.into_database("end transaction")?;
        Ok(())
    }

    /// Counts the rows in the Synapse database to get an estimate of how large
    /// the migration is going to be.
    ///
    /// # Errors
    ///
    /// Errors are returned under the following circumstances:
    ///
    /// - An underlying database error
    pub async fn count_rows(&mut self) -> Result<SynapseRowCounts, Error> {
        // We don't get to filter out application service users by using this estimate,
        // which is a shame, but on a large database this is way faster.
        // On matrix.org, counting users and devices properly takes around 1m10s,
        // which is unnecessary extra downtime during the migration, just to
        // show a more accurate progress bar and size a hash map accurately.
        let users = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'users'::regclass;
            ",
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of users")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        let devices = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'devices'::regclass;
            ",
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of devices")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        let threepids = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'user_threepids'::regclass;
            "
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of threepids")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        let access_tokens = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'access_tokens'::regclass;
            "
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of access tokens")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        let refresh_tokens = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'refresh_tokens'::regclass;
            "
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of refresh tokens")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        let external_ids = sqlx::query_scalar::<_, i64>(
            "
            SELECT reltuples::bigint AS estimate FROM pg_class WHERE oid = 'user_external_ids'::regclass;
            "
        )
        .fetch_one(&mut *self.txn)
        .await
        .into_database("estimating count of external IDs")?
        .max(0)
        .try_into()
        .unwrap_or(usize::MAX);

        Ok(SynapseRowCounts {
            users,
            devices,
            threepids,
            external_ids,
            access_tokens,
            refresh_tokens,
        })
    }

    /// Reads Synapse users, excluding application service users (which do not
    /// need to be migrated), from the database.
    pub fn read_users(&mut self) -> impl Stream<Item = Result<SynapseUser, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              name, password_hash, admin, deactivated, locked, creation_ts, is_guest, appservice_id
            FROM users
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse users"))
    }

    /// Reads threepids (such as e-mail and phone number associations) from
    /// Synapse.
    pub fn read_threepids(&mut self) -> impl Stream<Item = Result<SynapseThreepid, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              user_id, medium, address, added_at
            FROM user_threepids
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse threepids"))
    }

    /// Read associations between Synapse users and external identity providers
    pub fn read_user_external_ids(
        &mut self,
    ) -> impl Stream<Item = Result<SynapseExternalId, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              user_id, auth_provider, external_id
            FROM user_external_ids
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse user external IDs"))
    }

    /// Reads devices from the Synapse database.
    /// Does not include so-called 'hidden' devices, which are just a mechanism
    /// for storing various signing keys shared between the real devices.
    pub fn read_devices(&mut self) -> impl Stream<Item = Result<SynapseDevice, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              user_id, device_id, display_name, last_seen, ip, user_agent
            FROM devices
            WHERE NOT hidden AND device_id != 'guest_device'
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse devices"))
    }

    /// Reads unrefreshable access tokens from the Synapse database.
    /// This does not include access tokens used for puppetting users, as those
    /// are not supported by MAS.
    ///
    /// This also excludes access tokens whose referenced device ID does not
    /// exist, except for deviceless access tokens.
    /// (It's unclear what mechanism led to these, but since Synapse has no
    /// foreign key constraints and is not consistently atomic about this,
    /// it should be no surprise really)
    pub fn read_unrefreshable_access_tokens(
        &mut self,
    ) -> impl Stream<Item = Result<SynapseAccessToken, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              at0.user_id, at0.device_id, at0.token, at0.valid_until_ms, at0.last_validated
            FROM access_tokens at0
            INNER JOIN devices USING (user_id, device_id)
            WHERE at0.puppets_user_id IS NULL AND at0.refresh_token_id IS NULL

            UNION ALL

            SELECT
              at0.user_id, at0.device_id, at0.token, at0.valid_until_ms, at0.last_validated
            FROM access_tokens at0
            WHERE at0.puppets_user_id IS NULL AND at0.refresh_token_id IS NULL AND at0.device_id IS NULL
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse access tokens"))
    }

    /// Reads (access token, refresh token) pairs from the Synapse database.
    /// This does not include token pairs which have been made obsolete
    /// by using the refresh token and then acknowledging the
    /// successor access token by using it to authenticate a request.
    ///
    /// The `expiry_ts` and `ultimate_session_expiry_ts` columns are ignored as
    /// they are not implemented in MAS.
    /// Further, they are unused by any real-world deployment to the best of
    /// our knowledge.
    pub fn read_refreshable_token_pairs(
        &mut self,
    ) -> impl Stream<Item = Result<SynapseRefreshableTokenPair, Error>> + '_ {
        sqlx::query_as(
            "
            SELECT
              rt0.user_id, rt0.device_id, at0.token AS access_token, rt0.token AS refresh_token, at0.valid_until_ms, at0.last_validated
            FROM refresh_tokens rt0
            INNER JOIN devices USING (user_id, device_id)
            INNER JOIN access_tokens at0 ON at0.refresh_token_id = rt0.id AND at0.user_id = rt0.user_id AND at0.device_id = rt0.device_id
            LEFT JOIN access_tokens at1 ON at1.refresh_token_id = rt0.next_token_id
            WHERE NOT at1.used OR at1.used IS NULL
            ",
        )
        .fetch(&mut *self.txn)
        .map_err(|err| err.into_database("reading Synapse refresh tokens"))
    }
}

#[cfg(test)]
mod test {
    use std::collections::BTreeSet;

    use futures_util::TryStreamExt;
    use insta::assert_debug_snapshot;
    use sqlx::{PgPool, migrate::Migrator};

    use crate::{
        SynapseReader,
        synapse_reader::{
            SynapseAccessToken, SynapseDevice, SynapseExternalId, SynapseRefreshableTokenPair,
            SynapseThreepid, SynapseUser,
        },
    };

    static MIGRATOR: Migrator = sqlx::migrate!("./test_synapse_migrations");

    #[sqlx::test(migrator = "MIGRATOR", fixtures("user_alice"))]
    async fn test_read_users(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let users: BTreeSet<SynapseUser> = reader
            .read_users()
            .try_collect()
            .await
            .expect("failed to read Synapse users");

        assert_debug_snapshot!(users);
    }

    #[sqlx::test(migrator = "MIGRATOR", fixtures("user_alice", "threepids_alice"))]
    async fn test_read_threepids(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let threepids: BTreeSet<SynapseThreepid> = reader
            .read_threepids()
            .try_collect()
            .await
            .expect("failed to read Synapse threepids");

        assert_debug_snapshot!(threepids);
    }

    #[sqlx::test(migrator = "MIGRATOR", fixtures("user_alice", "external_ids_alice"))]
    async fn test_read_external_ids(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let external_ids: BTreeSet<SynapseExternalId> = reader
            .read_user_external_ids()
            .try_collect()
            .await
            .expect("failed to read Synapse external user IDs");

        assert_debug_snapshot!(external_ids);
    }

    #[sqlx::test(migrator = "MIGRATOR", fixtures("user_alice", "devices_alice"))]
    async fn test_read_devices(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let devices: BTreeSet<SynapseDevice> = reader
            .read_devices()
            .try_collect()
            .await
            .expect("failed to read Synapse devices");

        assert_debug_snapshot!(devices);
    }

    #[sqlx::test(
        migrator = "MIGRATOR",
        fixtures("user_alice", "devices_alice", "access_token_alice")
    )]
    async fn test_read_access_token(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let access_tokens: BTreeSet<SynapseAccessToken> = reader
            .read_unrefreshable_access_tokens()
            .try_collect()
            .await
            .expect("failed to read Synapse access tokens");

        assert_debug_snapshot!(access_tokens);
    }

    /// Tests that puppetting access tokens are ignored.
    #[sqlx::test(
        migrator = "MIGRATOR",
        fixtures("user_alice", "devices_alice", "access_token_alice_with_puppet")
    )]
    async fn test_read_access_token_puppet(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let access_tokens: BTreeSet<SynapseAccessToken> = reader
            .read_unrefreshable_access_tokens()
            .try_collect()
            .await
            .expect("failed to read Synapse access tokens");

        assert!(access_tokens.is_empty());
    }

    #[sqlx::test(
        migrator = "MIGRATOR",
        fixtures("user_alice", "devices_alice", "access_token_alice_with_refresh_token")
    )]
    async fn test_read_access_and_refresh_tokens(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let access_tokens: BTreeSet<SynapseAccessToken> = reader
            .read_unrefreshable_access_tokens()
            .try_collect()
            .await
            .expect("failed to read Synapse access tokens");

        let refresh_tokens: BTreeSet<SynapseRefreshableTokenPair> = reader
            .read_refreshable_token_pairs()
            .try_collect()
            .await
            .expect("failed to read Synapse refresh tokens");

        assert!(
            access_tokens.is_empty(),
            "there are no unrefreshable access tokens"
        );
        assert_debug_snapshot!(refresh_tokens);
    }

    #[sqlx::test(
        migrator = "MIGRATOR",
        fixtures(
            "user_alice",
            "devices_alice",
            "access_token_alice_with_unused_refresh_token"
        )
    )]
    async fn test_read_access_and_unused_refresh_tokens(pool: PgPool) {
        let mut conn = pool.acquire().await.expect("failed to get connection");
        let mut reader = SynapseReader::new(&mut conn, false)
            .await
            .expect("failed to make SynapseReader");

        let access_tokens: BTreeSet<SynapseAccessToken> = reader
            .read_unrefreshable_access_tokens()
            .try_collect()
            .await
            .expect("failed to read Synapse access tokens");

        let refresh_tokens: BTreeSet<SynapseRefreshableTokenPair> = reader
            .read_refreshable_token_pairs()
            .try_collect()
            .await
            .expect("failed to read Synapse refresh tokens");

        assert!(
            access_tokens.is_empty(),
            "there are no unrefreshable access tokens"
        );
        assert_debug_snapshot!(refresh_tokens);
    }
}
