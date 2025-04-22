// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # MAS Writer
//!
//! This module is responsible for writing new records to MAS' database.

use std::{
    fmt::Display,
    net::IpAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
};

use chrono::{DateTime, Utc};
use futures_util::{FutureExt, TryStreamExt, future::BoxFuture};
use sqlx::{Executor, PgConnection, query, query_as};
use thiserror::Error;
use thiserror_ext::{Construct, ContextInto};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{Instrument, Level, error, info, warn};
use uuid::{NonNilUuid, Uuid};

use self::{
    constraint_pausing::{ConstraintDescription, IndexDescription},
    locking::LockedMasDatabase,
};
use crate::Progress;

pub mod checks;
pub mod locking;

mod constraint_pausing;

#[derive(Debug, Error, Construct, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}")]
    Database {
        #[source]
        source: sqlx::Error,
        context: String,
    },

    #[error("writer connection pool shut down due to error")]
    #[expect(clippy::enum_variant_names)]
    WriterConnectionPoolError,

    #[error("inconsistent database: {0}")]
    Inconsistent(String),

    #[error("bug in syn2mas: write buffers not finished")]
    WriteBuffersNotFinished,

    #[error("{0}")]
    Multiple(MultipleErrors),
}

#[derive(Debug)]
pub struct MultipleErrors {
    errors: Vec<Error>,
}

impl Display for MultipleErrors {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "multiple errors")?;
        for error in &self.errors {
            write!(f, "\n- {error}")?;
        }
        Ok(())
    }
}

impl From<Vec<Error>> for MultipleErrors {
    fn from(value: Vec<Error>) -> Self {
        MultipleErrors { errors: value }
    }
}

struct WriterConnectionPool {
    /// How many connections are in circulation
    num_connections: usize,

    /// A receiver handle to get a writer connection
    /// The writer connection will be mid-transaction!
    connection_rx: Receiver<Result<PgConnection, Error>>,

    /// A sender handle to return a writer connection to the pool
    /// The connection should still be mid-transaction!
    connection_tx: Sender<Result<PgConnection, Error>>,
}

impl WriterConnectionPool {
    pub fn new(connections: Vec<PgConnection>) -> Self {
        let num_connections = connections.len();
        let (connection_tx, connection_rx) = mpsc::channel(num_connections);
        for connection in connections {
            connection_tx
                .try_send(Ok(connection))
                .expect("there should be room for this connection");
        }

        WriterConnectionPool {
            num_connections,
            connection_rx,
            connection_tx,
        }
    }

    pub async fn spawn_with_connection<F>(&mut self, task: F) -> Result<(), Error>
    where
        F: for<'conn> FnOnce(&'conn mut PgConnection) -> BoxFuture<'conn, Result<(), Error>>
            + Send
            + Sync
            + 'static,
    {
        match self.connection_rx.recv().await {
            Some(Ok(mut connection)) => {
                let connection_tx = self.connection_tx.clone();
                tokio::task::spawn(
                    async move {
                        let to_return = match task(&mut connection).await {
                            Ok(()) => Ok(connection),
                            Err(error) => {
                                error!("error in writer: {error}");
                                Err(error)
                            }
                        };
                        // This should always succeed in sending unless we're already shutting
                        // down for some other reason.
                        let _: Result<_, _> = connection_tx.send(to_return).await;
                    }
                    .instrument(tracing::debug_span!("spawn_with_connection")),
                );

                Ok(())
            }
            Some(Err(error)) => {
                // This should always succeed in sending unless we're already shutting
                // down for some other reason.
                let _: Result<_, _> = self.connection_tx.send(Err(error)).await;

                Err(Error::WriterConnectionPoolError)
            }
            None => {
                unreachable!("we still hold a reference to the sender, so this shouldn't happen")
            }
        }
    }

    /// Finishes writing to the database, committing all changes.
    ///
    /// # Errors
    ///
    /// - If any errors were returned to the pool.
    /// - If committing the changes failed.
    ///
    /// # Panics
    ///
    /// - If connections were not returned to the pool. (This indicates a
    ///   serious bug.)
    pub async fn finish(self) -> Result<(), Vec<Error>> {
        let mut errors = Vec::new();

        let Self {
            num_connections,
            mut connection_rx,
            connection_tx,
        } = self;
        // Drop the sender handle so we gracefully allow the receiver to close
        drop(connection_tx);

        let mut finished_connections = 0;

        while let Some(connection_or_error) = connection_rx.recv().await {
            finished_connections += 1;

            match connection_or_error {
                Ok(mut connection) => {
                    if let Err(err) = query("COMMIT;").execute(&mut connection).await {
                        errors.push(err.into_database("commit writer transaction"));
                    }
                }
                Err(error) => {
                    errors.push(error);
                }
            }
        }
        assert_eq!(
            finished_connections, num_connections,
            "syn2mas had a bug: connections went missing {finished_connections} != {num_connections}"
        );

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

/// Small utility to make sure `finish()` is called on all write buffers
/// before committing to the database.
#[derive(Default)]
struct FinishChecker {
    counter: Arc<AtomicU32>,
}

struct FinishCheckerHandle {
    counter: Arc<AtomicU32>,
}

impl FinishChecker {
    /// Acquire a new handle, for a task that should declare when it has
    /// finished.
    pub fn handle(&self) -> FinishCheckerHandle {
        self.counter.fetch_add(1, Ordering::SeqCst);
        FinishCheckerHandle {
            counter: Arc::clone(&self.counter),
        }
    }

    /// Check that all handles have been declared as finished.
    pub fn check_all_finished(self) -> Result<(), Error> {
        if self.counter.load(Ordering::SeqCst) == 0 {
            Ok(())
        } else {
            Err(Error::WriteBuffersNotFinished)
        }
    }
}

impl FinishCheckerHandle {
    /// Declare that the task this handle represents has been finished.
    pub fn declare_finished(self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct MasWriter {
    conn: LockedMasDatabase,
    writer_pool: WriterConnectionPool,

    indices_to_restore: Vec<IndexDescription>,
    constraints_to_restore: Vec<ConstraintDescription>,

    write_buffer_finish_checker: FinishChecker,
}

trait WriteBatch: Sized {
    fn write_batch(
        conn: &mut PgConnection,
        batch: Vec<Self>,
    ) -> impl Future<Output = Result<(), Error>>;
}

pub struct MasNewUser {
    pub user_id: NonNilUuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub deactivated_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
    /// Whether the user was a Synapse guest.
    /// Although MAS doesn't support guest access, it's still useful to track
    /// for the future.
    pub is_guest: bool,
}

impl WriteBatch for MasNewUser {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        // `UNNEST` is a fast way to do bulk inserts, as it lets us send multiple rows
        // in one statement without having to change the statement
        // SQL thus altering the query plan. See <https://github.com/launchbadge/sqlx/blob/main/FAQ.md#how-can-i-bind-an-array-to-a-values-clause-how-can-i-do-bulk-inserts>.
        // In the future we could consider using sqlx's support for `PgCopyIn` / the
        // `COPY FROM STDIN` statement, which is allegedly the best
        // for insert performance, but is less simple to encode.
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut usernames: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut locked_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut deactivated_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut can_request_admins: Vec<bool> = Vec::with_capacity(batch.len());
        let mut is_guests: Vec<bool> = Vec::with_capacity(batch.len());
        for MasNewUser {
            user_id,
            username,
            created_at,
            locked_at,
            deactivated_at,
            can_request_admin,
            is_guest,
        } in batch
        {
            user_ids.push(user_id.get());
            usernames.push(username);
            created_ats.push(created_at);
            locked_ats.push(locked_at);
            deactivated_ats.push(deactivated_at);
            can_request_admins.push(can_request_admin);
            is_guests.push(is_guest);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__users (
              user_id, username,
              created_at, locked_at,
              deactivated_at,
              can_request_admin, is_guest)
            SELECT * FROM UNNEST(
              $1::UUID[], $2::TEXT[],
              $3::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[],
              $5::TIMESTAMP WITH TIME ZONE[],
              $6::BOOL[], $7::BOOL[])
            "#,
            &user_ids[..],
            &usernames[..],
            &created_ats[..],
            // We need to override the typing for arrays of optionals (sqlx limitation)
            &locked_ats[..] as &[Option<DateTime<Utc>>],
            &deactivated_ats[..] as &[Option<DateTime<Utc>>],
            &can_request_admins[..],
            &is_guests[..],
        )
        .execute(&mut *conn)
        .await
        .into_database("writing users to MAS")?;

        Ok(())
    }
}

pub struct MasNewUserPassword {
    pub user_password_id: Uuid,
    pub user_id: NonNilUuid,
    pub hashed_password: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUserPassword {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_password_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut hashed_passwords: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut versions: Vec<i32> = Vec::with_capacity(batch.len());
        for MasNewUserPassword {
            user_password_id,
            user_id,
            hashed_password,
            created_at,
        } in batch
        {
            user_password_ids.push(user_password_id);
            user_ids.push(user_id.get());
            hashed_passwords.push(hashed_password);
            created_ats.push(created_at);
            versions.push(MIGRATED_PASSWORD_VERSION.into());
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__user_passwords
            (user_password_id, user_id, hashed_password, created_at, version)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[], $5::INTEGER[])
            "#,
            &user_password_ids[..],
            &user_ids[..],
            &hashed_passwords[..],
            &created_ats[..],
            &versions[..],
        ).execute(&mut *conn).await.into_database("writing users to MAS")?;

        Ok(())
    }
}

pub struct MasNewEmailThreepid {
    pub user_email_id: Uuid,
    pub user_id: NonNilUuid,
    pub email: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewEmailThreepid {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_email_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut emails: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewEmailThreepid {
            user_email_id,
            user_id,
            email,
            created_at,
        } in batch
        {
            user_email_ids.push(user_email_id);
            user_ids.push(user_id.get());
            emails.push(email);
            created_ats.push(created_at);
        }

        // `confirmed_at` is going to get removed in a future MAS release,
        // so just populate with `created_at`
        sqlx::query!(
            r#"
            INSERT INTO syn2mas__user_emails
            (user_email_id, user_id, email, created_at, confirmed_at)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[])
            "#,
            &user_email_ids[..],
            &user_ids[..],
            &emails[..],
            &created_ats[..],
        ).execute(&mut *conn).await.into_database("writing emails to MAS")?;

        Ok(())
    }
}

pub struct MasNewUnsupportedThreepid {
    pub user_id: NonNilUuid,
    pub medium: String,
    pub address: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUnsupportedThreepid {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut mediums: Vec<String> = Vec::with_capacity(batch.len());
        let mut addresses: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewUnsupportedThreepid {
            user_id,
            medium,
            address,
            created_at,
        } in batch
        {
            user_ids.push(user_id.get());
            mediums.push(medium);
            addresses.push(address);
            created_ats.push(created_at);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__user_unsupported_third_party_ids
            (user_id, medium, address, created_at)
            SELECT * FROM UNNEST($1::UUID[], $2::TEXT[], $3::TEXT[], $4::TIMESTAMP WITH TIME ZONE[])
            "#,
            &user_ids[..],
            &mediums[..],
            &addresses[..],
            &created_ats[..],
        )
        .execute(&mut *conn)
        .await
        .into_database("writing unsupported threepids to MAS")?;

        Ok(())
    }
}

pub struct MasNewUpstreamOauthLink {
    pub link_id: Uuid,
    pub user_id: NonNilUuid,
    pub upstream_provider_id: Uuid,
    pub subject: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewUpstreamOauthLink {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut link_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut upstream_provider_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut subjects: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewUpstreamOauthLink {
            link_id,
            user_id,
            upstream_provider_id,
            subject,
            created_at,
        } in batch
        {
            link_ids.push(link_id);
            user_ids.push(user_id.get());
            upstream_provider_ids.push(upstream_provider_id);
            subjects.push(subject);
            created_ats.push(created_at);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__upstream_oauth_links
            (upstream_oauth_link_id, user_id, upstream_oauth_provider_id, subject, created_at)
            SELECT * FROM UNNEST($1::UUID[], $2::UUID[], $3::UUID[], $4::TEXT[], $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &link_ids[..],
            &user_ids[..],
            &upstream_provider_ids[..],
            &subjects[..],
            &created_ats[..],
        ).execute(&mut *conn).await.into_database("writing unsupported threepids to MAS")?;

        Ok(())
    }
}

pub struct MasNewCompatSession {
    pub session_id: Uuid,
    pub user_id: NonNilUuid,
    pub device_id: Option<String>,
    pub human_name: Option<String>,
    pub created_at: DateTime<Utc>,
    pub is_synapse_admin: bool,
    pub last_active_at: Option<DateTime<Utc>>,
    pub last_active_ip: Option<IpAddr>,
    pub user_agent: Option<String>,
}

impl WriteBatch for MasNewCompatSession {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut user_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut device_ids: Vec<Option<String>> = Vec::with_capacity(batch.len());
        let mut human_names: Vec<Option<String>> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut is_synapse_admins: Vec<bool> = Vec::with_capacity(batch.len());
        let mut last_active_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());
        let mut last_active_ips: Vec<Option<IpAddr>> = Vec::with_capacity(batch.len());
        let mut user_agents: Vec<Option<String>> = Vec::with_capacity(batch.len());

        for MasNewCompatSession {
            session_id,
            user_id,
            device_id,
            human_name,
            created_at,
            is_synapse_admin,
            last_active_at,
            last_active_ip,
            user_agent,
        } in batch
        {
            session_ids.push(session_id);
            user_ids.push(user_id.get());
            device_ids.push(device_id);
            human_names.push(human_name);
            created_ats.push(created_at);
            is_synapse_admins.push(is_synapse_admin);
            last_active_ats.push(last_active_at);
            last_active_ips.push(last_active_ip);
            user_agents.push(user_agent);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__compat_sessions (
              compat_session_id, user_id,
              device_id, human_name,
              created_at, is_synapse_admin,
              last_active_at, last_active_ip,
              user_agent)
            SELECT * FROM UNNEST(
              $1::UUID[], $2::UUID[],
              $3::TEXT[], $4::TEXT[],
              $5::TIMESTAMP WITH TIME ZONE[], $6::BOOLEAN[],
              $7::TIMESTAMP WITH TIME ZONE[], $8::INET[],
              $9::TEXT[])
            "#,
            &session_ids[..],
            &user_ids[..],
            &device_ids[..] as &[Option<String>],
            &human_names[..] as &[Option<String>],
            &created_ats[..],
            &is_synapse_admins[..],
            // We need to override the typing for arrays of optionals (sqlx limitation)
            &last_active_ats[..] as &[Option<DateTime<Utc>>],
            &last_active_ips[..] as &[Option<IpAddr>],
            &user_agents[..] as &[Option<String>],
        )
        .execute(&mut *conn)
        .await
        .into_database("writing compat sessions to MAS")?;

        Ok(())
    }
}

pub struct MasNewCompatAccessToken {
    pub token_id: Uuid,
    pub session_id: Uuid,
    pub access_token: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
}

impl WriteBatch for MasNewCompatAccessToken {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut access_tokens: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());
        let mut expires_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(batch.len());

        for MasNewCompatAccessToken {
            token_id,
            session_id,
            access_token,
            created_at,
            expires_at,
        } in batch
        {
            token_ids.push(token_id);
            session_ids.push(session_id);
            access_tokens.push(access_token);
            created_ats.push(created_at);
            expires_ats.push(expires_at);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__compat_access_tokens (
              compat_access_token_id,
              compat_session_id,
              access_token,
              created_at,
              expires_at)
            SELECT * FROM UNNEST(
              $1::UUID[],
              $2::UUID[],
              $3::TEXT[],
              $4::TIMESTAMP WITH TIME ZONE[],
              $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &token_ids[..],
            &session_ids[..],
            &access_tokens[..],
            &created_ats[..],
            // We need to override the typing for arrays of optionals (sqlx limitation)
            &expires_ats[..] as &[Option<DateTime<Utc>>],
        )
        .execute(&mut *conn)
        .await
        .into_database("writing compat access tokens to MAS")?;

        Ok(())
    }
}

pub struct MasNewCompatRefreshToken {
    pub refresh_token_id: Uuid,
    pub session_id: Uuid,
    pub access_token_id: Uuid,
    pub refresh_token: String,
    pub created_at: DateTime<Utc>,
}

impl WriteBatch for MasNewCompatRefreshToken {
    async fn write_batch(conn: &mut PgConnection, batch: Vec<Self>) -> Result<(), Error> {
        let mut refresh_token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut session_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut access_token_ids: Vec<Uuid> = Vec::with_capacity(batch.len());
        let mut refresh_tokens: Vec<String> = Vec::with_capacity(batch.len());
        let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(batch.len());

        for MasNewCompatRefreshToken {
            refresh_token_id,
            session_id,
            access_token_id,
            refresh_token,
            created_at,
        } in batch
        {
            refresh_token_ids.push(refresh_token_id);
            session_ids.push(session_id);
            access_token_ids.push(access_token_id);
            refresh_tokens.push(refresh_token);
            created_ats.push(created_at);
        }

        sqlx::query!(
            r#"
            INSERT INTO syn2mas__compat_refresh_tokens (
              compat_refresh_token_id,
              compat_session_id,
              compat_access_token_id,
              refresh_token,
              created_at)
            SELECT * FROM UNNEST(
              $1::UUID[],
              $2::UUID[],
              $3::UUID[],
              $4::TEXT[],
              $5::TIMESTAMP WITH TIME ZONE[])
            "#,
            &refresh_token_ids[..],
            &session_ids[..],
            &access_token_ids[..],
            &refresh_tokens[..],
            &created_ats[..],
        )
        .execute(&mut *conn)
        .await
        .into_database("writing compat refresh tokens to MAS")?;

        Ok(())
    }
}

/// The 'version' of the password hashing scheme used for passwords when they
/// are migrated from Synapse to MAS.
/// This is version 1, as in the previous syn2mas script.
// TODO hardcoding version to `1` may not be correct long-term?
pub const MIGRATED_PASSWORD_VERSION: u16 = 1;

/// List of all MAS tables that are written to by syn2mas.
pub const MAS_TABLES_AFFECTED_BY_MIGRATION: &[&str] = &[
    "users",
    "user_passwords",
    "user_emails",
    "user_unsupported_third_party_ids",
    "upstream_oauth_links",
    "compat_sessions",
    "compat_access_tokens",
    "compat_refresh_tokens",
];

/// Detect whether a syn2mas migration has started on the given database.
///
/// Concretly, this checks for the presence of syn2mas restoration tables.
///
/// Returns `true` if syn2mas has started, or `false` if it hasn't.
///
/// # Errors
///
/// Errors are returned under the following circumstances:
///
/// - If any database error occurs whilst querying the database.
/// - If some, but not all, syn2mas restoration tables are present. (This
///   shouldn't be possible without syn2mas having been sabotaged!)
pub async fn is_syn2mas_in_progress(conn: &mut PgConnection) -> Result<bool, Error> {
    // Names of tables used for syn2mas resumption
    // Must be `String`s, not just `&str`, for the query.
    let restore_table_names = vec![
        "syn2mas_restore_constraints".to_owned(),
        "syn2mas_restore_indices".to_owned(),
    ];

    let num_resumption_tables = query!(
        r#"
        SELECT 1 AS _dummy FROM pg_tables WHERE schemaname = current_schema
        AND tablename = ANY($1)
        "#,
        &restore_table_names,
    )
    .fetch_all(conn.as_mut())
    .await
    .into_database("failed to query count of resumption tables")?
    .len();

    if num_resumption_tables == 0 {
        Ok(false)
    } else if num_resumption_tables == restore_table_names.len() {
        Ok(true)
    } else {
        Err(Error::inconsistent(
            "some, but not all, syn2mas resumption tables were found",
        ))
    }
}

impl MasWriter {
    /// Creates a new MAS writer.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[tracing::instrument(name = "syn2mas.mas_writer.new", skip_all)]
    pub async fn new(
        mut conn: LockedMasDatabase,
        mut writer_connections: Vec<PgConnection>,
    ) -> Result<Self, Error> {
        // Given that we don't have any concurrent transactions here,
        // the READ COMMITTED isolation level is sufficient.
        query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;")
            .execute(conn.as_mut())
            .await
            .into_database("begin MAS transaction")?;

        let syn2mas_started = is_syn2mas_in_progress(conn.as_mut()).await?;

        let indices_to_restore;
        let constraints_to_restore;

        if syn2mas_started {
            // We are resuming from a partially-done syn2mas migration
            // We should reset the database so that we're starting from scratch.
            warn!("Partial syn2mas migration has already been done; resetting.");
            for table in MAS_TABLES_AFFECTED_BY_MIGRATION {
                query(&format!("TRUNCATE syn2mas__{table};"))
                    .execute(conn.as_mut())
                    .await
                    .into_database_with(|| format!("failed to truncate table syn2mas__{table}"))?;
            }

            indices_to_restore = query_as!(
                IndexDescription,
                "SELECT table_name, name, definition FROM syn2mas_restore_indices ORDER BY order_key"
            )
                .fetch_all(conn.as_mut())
                .await
                .into_database("failed to get syn2mas restore data (index descriptions)")?;
            constraints_to_restore = query_as!(
                ConstraintDescription,
                "SELECT table_name, name, definition FROM syn2mas_restore_constraints ORDER BY order_key"
            )
                .fetch_all(conn.as_mut())
                .await
                .into_database("failed to get syn2mas restore data (constraint descriptions)")?;
        } else {
            info!("Starting new syn2mas migration");

            conn.as_mut()
                .execute_many(include_str!("syn2mas_temporary_tables.sql"))
                // We don't care about any query results
                .try_collect::<Vec<_>>()
                .await
                .into_database("could not create temporary tables")?;

            // Pause (temporarily drop) indices and constraints in order to improve
            // performance of bulk data loading.
            (indices_to_restore, constraints_to_restore) =
                Self::pause_indices(conn.as_mut()).await?;

            // Persist these index and constraint definitions.
            for IndexDescription {
                name,
                table_name,
                definition,
            } in &indices_to_restore
            {
                query!(
                    r#"
                    INSERT INTO syn2mas_restore_indices (name, table_name, definition)
                    VALUES ($1, $2, $3)
                    "#,
                    name,
                    table_name,
                    definition
                )
                .execute(conn.as_mut())
                .await
                .into_database("failed to save restore data (index)")?;
            }
            for ConstraintDescription {
                name,
                table_name,
                definition,
            } in &constraints_to_restore
            {
                query!(
                    r#"
                    INSERT INTO syn2mas_restore_constraints (name, table_name, definition)
                    VALUES ($1, $2, $3)
                    "#,
                    name,
                    table_name,
                    definition
                )
                .execute(conn.as_mut())
                .await
                .into_database("failed to save restore data (index)")?;
            }
        }

        query("COMMIT;")
            .execute(conn.as_mut())
            .await
            .into_database("begin MAS transaction")?;

        // Now after all the schema changes have been done, begin writer transactions
        for writer_connection in &mut writer_connections {
            query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;")
                .execute(&mut *writer_connection)
                .await
                .into_database("begin MAS writer transaction")?;
        }

        Ok(Self {
            conn,

            writer_pool: WriterConnectionPool::new(writer_connections),
            indices_to_restore,
            constraints_to_restore,
            write_buffer_finish_checker: FinishChecker::default(),
        })
    }

    #[tracing::instrument(skip_all)]
    async fn pause_indices(
        conn: &mut PgConnection,
    ) -> Result<(Vec<IndexDescription>, Vec<ConstraintDescription>), Error> {
        let mut indices_to_restore = Vec::new();
        let mut constraints_to_restore = Vec::new();

        for &unprefixed_table in MAS_TABLES_AFFECTED_BY_MIGRATION {
            let table = format!("syn2mas__{unprefixed_table}");
            // First drop incoming foreign key constraints
            for constraint in
                constraint_pausing::describe_foreign_key_constraints_to_table(&mut *conn, &table)
                    .await?
            {
                constraint_pausing::drop_constraint(&mut *conn, &constraint).await?;
                constraints_to_restore.push(constraint);
            }
            // After all incoming foreign key constraints have been removed,
            // we can now drop internal constraints.
            for constraint in
                constraint_pausing::describe_constraints_on_table(&mut *conn, &table).await?
            {
                constraint_pausing::drop_constraint(&mut *conn, &constraint).await?;
                constraints_to_restore.push(constraint);
            }
            // After all constraints have been removed, we can drop indices.
            for index in constraint_pausing::describe_indices_on_table(&mut *conn, &table).await? {
                constraint_pausing::drop_index(&mut *conn, &index).await?;
                indices_to_restore.push(index);
            }
        }

        Ok((indices_to_restore, constraints_to_restore))
    }

    async fn restore_indices(
        conn: &mut LockedMasDatabase,
        indices_to_restore: &[IndexDescription],
        constraints_to_restore: &[ConstraintDescription],
        progress: &Progress,
    ) -> Result<(), Error> {
        // First restore all indices. The order is not important as far as I know.
        // However the indices are needed before constraints.
        for index in indices_to_restore.iter().rev() {
            progress.rebuild_index(index.name.clone());
            constraint_pausing::restore_index(conn.as_mut(), index).await?;
        }
        // Then restore all constraints.
        // The order here is the reverse of drop order, since some constraints may rely
        // on other constraints to work.
        for constraint in constraints_to_restore.iter().rev() {
            progress.rebuild_constraint(constraint.name.clone());
            constraint_pausing::restore_constraint(conn.as_mut(), constraint).await?;
        }
        Ok(())
    }

    /// Finish writing to the MAS database, flushing and committing all changes.
    /// It returns the unlocked underlying connection.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[tracing::instrument(skip_all)]
    pub async fn finish(mut self, progress: &Progress) -> Result<PgConnection, Error> {
        self.write_buffer_finish_checker.check_all_finished()?;

        // Commit all writer transactions to the database.
        self.writer_pool
            .finish()
            .await
            .map_err(|errors| Error::Multiple(MultipleErrors::from(errors)))?;

        // Now all the data has been migrated, finish off by restoring indices and
        // constraints!

        query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;")
            .execute(self.conn.as_mut())
            .await
            .into_database("begin MAS transaction")?;

        Self::restore_indices(
            &mut self.conn,
            &self.indices_to_restore,
            &self.constraints_to_restore,
            progress,
        )
        .await?;

        self.conn
            .as_mut()
            .execute_many(include_str!("syn2mas_revert_temporary_tables.sql"))
            // We don't care about any query results
            .try_collect::<Vec<_>>()
            .await
            .into_database("could not revert temporary tables")?;

        query("COMMIT;")
            .execute(self.conn.as_mut())
            .await
            .into_database("ending MAS transaction")?;

        let conn = self
            .conn
            .unlock()
            .await
            .into_database("could not unlock MAS database")?;

        Ok(conn)
    }

    /// Write a batch of users to the database.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database writer connection pool had an error.
    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_users(&mut self, users: Vec<MasNewUser>) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewUser::write_batch(conn, users).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    /// Write a batch of user passwords to the database.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database writer connection pool had an error.
    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_passwords(
        &mut self,
        passwords: Vec<MasNewUserPassword>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewUserPassword::write_batch(conn, passwords).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_email_threepids(
        &mut self,
        threepids: Vec<MasNewEmailThreepid>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewEmailThreepid::write_batch(conn, threepids).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_unsupported_threepids(
        &mut self,
        threepids: Vec<MasNewUnsupportedThreepid>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewUnsupportedThreepid::write_batch(conn, threepids).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_upstream_oauth_links(
        &mut self,
        links: Vec<MasNewUpstreamOauthLink>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewUpstreamOauthLink::write_batch(conn, links).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_compat_sessions(
        &mut self,
        sessions: Vec<MasNewCompatSession>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewCompatSession::write_batch(conn, sessions).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_compat_access_tokens(
        &mut self,
        tokens: Vec<MasNewCompatAccessToken>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewCompatAccessToken::write_batch(conn, tokens).await?;

                    Ok(())
                })
            })
            .boxed()
    }

    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub fn write_compat_refresh_tokens(
        &mut self,
        tokens: Vec<MasNewCompatRefreshToken>,
    ) -> BoxFuture<'_, Result<(), Error>> {
        self.writer_pool
            .spawn_with_connection(move |conn| {
                Box::pin(async move {
                    MasNewCompatRefreshToken::write_batch(conn, tokens).await?;
                    Ok(())
                })
            })
            .boxed()
    }
}

// How many entries to buffer at once, before writing a batch of rows to the
// database.
const WRITE_BUFFER_BATCH_SIZE: usize = 4096;

/// A function that can accept and flush buffers from a `MasWriteBuffer`.
/// Intended uses are the methods on `MasWriter` such as `write_users`.
type WriteBufferFlusher<T> =
    for<'a> fn(&'a mut MasWriter, Vec<T>) -> BoxFuture<'a, Result<(), Error>>;

/// A buffer for writing rows to the MAS database.
/// Generic over the type of rows.
pub struct MasWriteBuffer<T> {
    rows: Vec<T>,
    flusher: WriteBufferFlusher<T>,
    finish_checker_handle: FinishCheckerHandle,
}

impl<T> MasWriteBuffer<T> {
    pub fn new(writer: &MasWriter, flusher: WriteBufferFlusher<T>) -> Self {
        MasWriteBuffer {
            rows: Vec::with_capacity(WRITE_BUFFER_BATCH_SIZE),
            flusher,
            finish_checker_handle: writer.write_buffer_finish_checker.handle(),
        }
    }

    pub async fn finish(mut self, writer: &mut MasWriter) -> Result<(), Error> {
        self.flush(writer).await?;
        self.finish_checker_handle.declare_finished();
        Ok(())
    }

    pub async fn flush(&mut self, writer: &mut MasWriter) -> Result<(), Error> {
        if self.rows.is_empty() {
            return Ok(());
        }
        let rows = std::mem::take(&mut self.rows);
        self.rows.reserve_exact(WRITE_BUFFER_BATCH_SIZE);
        (self.flusher)(writer, rows).await?;
        Ok(())
    }

    pub async fn write(&mut self, writer: &mut MasWriter, row: T) -> Result<(), Error> {
        self.rows.push(row);
        if self.rows.len() >= WRITE_BUFFER_BATCH_SIZE {
            self.flush(writer).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::collections::{BTreeMap, BTreeSet};

    use chrono::DateTime;
    use futures_util::TryStreamExt;
    use serde::Serialize;
    use sqlx::{Column, PgConnection, PgPool, Row};
    use uuid::{NonNilUuid, Uuid};

    use crate::{
        LockedMasDatabase, MasWriter, Progress,
        mas_writer::{
            MasNewCompatAccessToken, MasNewCompatRefreshToken, MasNewCompatSession,
            MasNewEmailThreepid, MasNewUnsupportedThreepid, MasNewUpstreamOauthLink, MasNewUser,
            MasNewUserPassword,
        },
    };

    /// A snapshot of a whole database
    #[derive(Default, Serialize)]
    #[serde(transparent)]
    struct DatabaseSnapshot {
        tables: BTreeMap<String, TableSnapshot>,
    }

    #[derive(Serialize)]
    #[serde(transparent)]
    struct TableSnapshot {
        rows: BTreeSet<RowSnapshot>,
    }

    #[derive(PartialEq, Eq, PartialOrd, Ord, Serialize)]
    #[serde(transparent)]
    struct RowSnapshot {
        columns_to_values: BTreeMap<String, Option<String>>,
    }

    const SKIPPED_TABLES: &[&str] = &["_sqlx_migrations"];

    /// Produces a serialisable snapshot of a database, usable for snapshot
    /// testing
    ///
    /// For brevity, empty tables, as well as [`SKIPPED_TABLES`], will not be
    /// included in the snapshot.
    async fn snapshot_database(conn: &mut PgConnection) -> DatabaseSnapshot {
        let mut out = DatabaseSnapshot::default();
        let table_names: Vec<String> = sqlx::query_scalar(
            "SELECT table_name FROM information_schema.tables WHERE table_schema = current_schema();",
        )
        .fetch_all(&mut *conn)
        .await
        .unwrap();

        for table_name in table_names {
            if SKIPPED_TABLES.contains(&table_name.as_str()) {
                continue;
            }

            let column_names: Vec<String> = sqlx::query_scalar(
                "SELECT column_name FROM information_schema.columns WHERE table_name = $1 AND table_schema = current_schema();"
            ).bind(&table_name).fetch_all(&mut *conn).await.expect("failed to get column names for table for snapshotting");

            let column_name_list = column_names
                .iter()
                // stringify all the values for simplicity
                .map(|column_name| format!("{column_name}::TEXT AS \"{column_name}\""))
                .collect::<Vec<_>>()
                .join(", ");

            let table_rows = sqlx::query(&format!("SELECT {column_name_list} FROM {table_name};"))
                .fetch(&mut *conn)
                .map_ok(|row| {
                    let mut columns_to_values = BTreeMap::new();
                    for (idx, column) in row.columns().iter().enumerate() {
                        columns_to_values.insert(column.name().to_owned(), row.get(idx));
                    }
                    RowSnapshot { columns_to_values }
                })
                .try_collect::<BTreeSet<RowSnapshot>>()
                .await
                .expect("failed to fetch rows from table for snapshotting");

            if !table_rows.is_empty() {
                out.tables
                    .insert(table_name, TableSnapshot { rows: table_rows });
            }
        }

        out
    }

    /// Make a snapshot assertion against the database.
    macro_rules! assert_db_snapshot {
        ($db: expr) => {
            let db_snapshot = snapshot_database($db).await;
            ::insta::assert_yaml_snapshot!(db_snapshot);
        };
    }

    /// Runs some code with a `MasWriter`.
    ///
    /// The callback is responsible for `finish`ing the `MasWriter`.
    async fn make_mas_writer(pool: &PgPool) -> MasWriter {
        let main_conn = pool.acquire().await.unwrap().detach();
        let mut writer_conns = Vec::new();
        for _ in 0..2 {
            writer_conns.push(
                pool.acquire()
                    .await
                    .expect("failed to acquire MasWriter writer connection")
                    .detach(),
            );
        }
        let locked_main_conn = LockedMasDatabase::try_new(main_conn)
            .await
            .expect("failed to lock MAS database")
            .expect_left("MAS database is already locked");
        MasWriter::new(locked_main_conn, writer_conns)
            .await
            .expect("failed to construct MasWriter")
    }

    /// Tests writing a single user, without a password.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a password.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_password(pool: PgPool) {
        const USER_ID: NonNilUuid = NonNilUuid::new(Uuid::from_u128(1u128)).unwrap();

        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: USER_ID,
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");
        writer
            .write_passwords(vec![MasNewUserPassword {
                user_password_id: Uuid::from_u128(42u128),
                user_id: USER_ID,
                hashed_password: "$bcrypt$aaaaaaaaaaa".to_owned(),
                created_at: DateTime::default(),
            }])
            .await
            .expect("failed to write password");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with an e-mail address associated.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_email(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_email_threepids(vec![MasNewEmailThreepid {
                user_email_id: Uuid::from_u128(2u128),
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                email: "alice@example.org".to_owned(),
                created_at: DateTime::default(),
            }])
            .await
            .expect("failed to write e-mail");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a unsupported third-party ID
    /// associated.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_unsupported_threepid(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_unsupported_threepids(vec![MasNewUnsupportedThreepid {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                medium: "msisdn".to_owned(),
                address: "441189998819991197253".to_owned(),
                created_at: DateTime::default(),
            }])
            .await
            .expect("failed to write phone number (unsupported threepid)");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a link to an upstream provider.
    /// There needs to be an upstream provider in the database already — in the
    /// real migration, this is done by running a provider sync first.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR", fixtures("upstream_provider"))]
    async fn test_write_user_with_upstream_provider_link(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_upstream_oauth_links(vec![MasNewUpstreamOauthLink {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                link_id: Uuid::from_u128(3u128),
                upstream_provider_id: Uuid::from_u128(4u128),
                subject: "12345.67890".to_owned(),
                created_at: DateTime::default(),
            }])
            .await
            .expect("failed to write link");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a device (compat session).
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_device(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_compat_sessions(vec![MasNewCompatSession {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                session_id: Uuid::from_u128(5u128),
                created_at: DateTime::default(),
                device_id: Some("ADEVICE".to_owned()),
                human_name: Some("alice's pinephone".to_owned()),
                is_synapse_admin: true,
                last_active_at: Some(DateTime::default()),
                last_active_ip: Some("203.0.113.1".parse().unwrap()),
                user_agent: Some("Browser/5.0".to_owned()),
            }])
            .await
            .expect("failed to write compat session");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a device and an access token.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_access_token(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_compat_sessions(vec![MasNewCompatSession {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                session_id: Uuid::from_u128(5u128),
                created_at: DateTime::default(),
                device_id: Some("ADEVICE".to_owned()),
                human_name: None,
                is_synapse_admin: false,
                last_active_at: None,
                last_active_ip: None,
                user_agent: None,
            }])
            .await
            .expect("failed to write compat session");

        writer
            .write_compat_access_tokens(vec![MasNewCompatAccessToken {
                token_id: Uuid::from_u128(6u128),
                session_id: Uuid::from_u128(5u128),
                access_token: "syt_zxcvzxcvzxcvzxcv_zxcv".to_owned(),
                created_at: DateTime::default(),
                expires_at: None,
            }])
            .await
            .expect("failed to write access token");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }

    /// Tests writing a single user, with a device, an access token and a
    /// refresh token.
    #[sqlx::test(migrator = "mas_storage_pg::MIGRATOR")]
    async fn test_write_user_with_refresh_token(pool: PgPool) {
        let mut writer = make_mas_writer(&pool).await;

        writer
            .write_users(vec![MasNewUser {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                username: "alice".to_owned(),
                created_at: DateTime::default(),
                locked_at: None,
                deactivated_at: None,
                can_request_admin: false,
                is_guest: false,
            }])
            .await
            .expect("failed to write user");

        writer
            .write_compat_sessions(vec![MasNewCompatSession {
                user_id: NonNilUuid::new(Uuid::from_u128(1u128)).unwrap(),
                session_id: Uuid::from_u128(5u128),
                created_at: DateTime::default(),
                device_id: Some("ADEVICE".to_owned()),
                human_name: None,
                is_synapse_admin: false,
                last_active_at: None,
                last_active_ip: None,
                user_agent: None,
            }])
            .await
            .expect("failed to write compat session");

        writer
            .write_compat_access_tokens(vec![MasNewCompatAccessToken {
                token_id: Uuid::from_u128(6u128),
                session_id: Uuid::from_u128(5u128),
                access_token: "syt_zxcvzxcvzxcvzxcv_zxcv".to_owned(),
                created_at: DateTime::default(),
                expires_at: None,
            }])
            .await
            .expect("failed to write access token");

        writer
            .write_compat_refresh_tokens(vec![MasNewCompatRefreshToken {
                refresh_token_id: Uuid::from_u128(7u128),
                session_id: Uuid::from_u128(5u128),
                access_token_id: Uuid::from_u128(6u128),
                refresh_token: "syr_zxcvzxcvzxcvzxcv_zxcv".to_owned(),
                created_at: DateTime::default(),
            }])
            .await
            .expect("failed to write refresh token");

        let mut conn = writer
            .finish(&Progress::default())
            .await
            .expect("failed to finish MasWriter");

        assert_db_snapshot!(&mut conn);
    }
}
