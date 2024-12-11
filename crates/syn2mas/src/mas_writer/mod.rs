// Copyright 2024 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! # MAS Writer
//!
//! This module is responsible for writing new records to MAS' database.

use std::fmt::Display;

use chrono::{DateTime, Utc};
use futures_util::{future::BoxFuture, TryStreamExt};
use sqlx::{query, query_as, Executor, PgConnection};
use thiserror::Error;
use thiserror_ext::{Construct, ContextInto};
use tokio::sync::mpsc::{self, Receiver, Sender};
use tracing::{error, info, warn, Level};
use uuid::Uuid;

use self::{
    constraint_pausing::{ConstraintDescription, IndexDescription},
    locking::LockedMasDatabase,
};

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
    #[allow(clippy::enum_variant_names)]
    WriterConnectionPoolError,

    #[error("inconsistent database: {0}")]
    Inconsistent(String),

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
                tokio::task::spawn(async move {
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
                });

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
    /// - If connections were not returned to the pool. (This indicates a serious bug.)
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
        assert_eq!(finished_connections, num_connections, "syn2mas had a bug: connections went missing {finished_connections} != {num_connections}");

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub struct MasWriter<'c> {
    conn: LockedMasDatabase<'c>,
    writer_pool: WriterConnectionPool,

    indices_to_restore: Vec<IndexDescription>,
    constraints_to_restore: Vec<ConstraintDescription>,
}

pub struct MasNewUser {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
}

pub struct MasNewUserPassword {
    pub user_password_id: Uuid,
    pub user_id: Uuid,
    pub hashed_password: String,
    pub created_at: DateTime<Utc>,
}

/// List of all MAS tables that are written to by syn2mas.
pub const MAS_TABLES_AFFECTED_BY_MIGRATION: &[&str] = &["users", "user_passwords"];

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
/// - If some, but not all, syn2mas restoration tables are present.
///   (This shouldn't be possible without syn2mas having been sabotaged!)
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

impl<'conn> MasWriter<'conn> {
    /// Creates a new MAS writer.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[allow(clippy::missing_panics_doc)] // not real
    #[tracing::instrument(skip_all)]
    pub async fn new(
        mut conn: LockedMasDatabase<'conn>,
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

    async fn restore_indices<'a>(
        conn: &mut LockedMasDatabase<'a>,
        indices_to_restore: &[IndexDescription],
        constraints_to_restore: &[ConstraintDescription],
    ) -> Result<(), Error> {
        // First restore all indices. The order is not important as far as I know.
        // However the indices are needed before constraints.
        for index in indices_to_restore.iter().rev() {
            constraint_pausing::restore_index(conn.as_mut(), index).await?;
        }
        // Then restore all constraints.
        // The order here is the reverse of drop order, since some constraints may rely
        // on other constraints to work.
        for constraint in constraints_to_restore.iter().rev() {
            constraint_pausing::restore_constraint(conn.as_mut(), constraint).await?;
        }
        Ok(())
    }

    /// Finish writing to the MAS database, flushing and committing all changes.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database connection experiences an error.
    #[tracing::instrument(skip_all)]
    pub async fn finish(mut self) -> Result<(), Error> {
        // Commit all writer transactions to the database.
        self.writer_pool
            .finish()
            .await
            .map_err(|errors| Error::Multiple(MultipleErrors::from(errors)))?;

        // Now all the data has been migrated, finish off by restoring indices and constraints!

        query("BEGIN TRANSACTION ISOLATION LEVEL READ COMMITTED;")
            .execute(self.conn.as_mut())
            .await
            .into_database("begin MAS transaction")?;

        Self::restore_indices(
            &mut self.conn,
            &self.indices_to_restore,
            &self.constraints_to_restore,
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

        self.conn
            .unlock()
            .await
            .into_database("could not unlock MAS database")?;

        Ok(())
    }

    /// Write a batch of users to the database.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database writer connection pool had an error.
    #[allow(clippy::missing_panics_doc)] // not a real panic
    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub async fn write_users(&mut self, users: Vec<MasNewUser>) -> Result<(), Error> {
        self.writer_pool.spawn_with_connection(move |conn| Box::pin(async move {
            // `UNNEST` is a fast way to do bulk inserts, as it lets us send multiple rows in one statement
            // without having to change the statement SQL thus altering the query plan.
            // See <https://github.com/launchbadge/sqlx/blob/main/FAQ.md#how-can-i-bind-an-array-to-a-values-clause-how-can-i-do-bulk-inserts>.
            // In the future we could consider using sqlx's support for `PgCopyIn` / the `COPY FROM STDIN` statement,
            // which is allegedly the best for insert performance, but is less simple to encode.
            if users.is_empty() {
                return Ok(());
            }

            let mut user_ids: Vec<Uuid> = Vec::with_capacity(users.len());
            let mut usernames: Vec<String> = Vec::with_capacity(users.len());
            let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(users.len());
            let mut locked_ats: Vec<Option<DateTime<Utc>>> = Vec::with_capacity(users.len());
            let mut can_request_admins: Vec<bool> = Vec::with_capacity(users.len());
            for MasNewUser {
                user_id,
                username,
                created_at,
                locked_at,
                can_request_admin,
            } in users
            {
                user_ids.push(user_id);
                usernames.push(username);
                created_ats.push(created_at);
                locked_ats.push(locked_at);
                can_request_admins.push(can_request_admin);
            }

            sqlx::query!(
                r#"
                INSERT INTO syn2mas__users
                (user_id, username, created_at, locked_at, can_request_admin)
                SELECT * FROM UNNEST($1::UUID[], $2::TEXT[], $3::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[], $5::BOOL[])
                "#,
                &user_ids[..],
                &usernames[..],
                &created_ats[..],
                // We need to override the typing for arrays of optionals (sqlx limitation)
                &locked_ats[..] as &[Option<DateTime<Utc>>],
                &can_request_admins[..],
            ).execute(&mut *conn).await.into_database("writing users to MAS")?;

            Ok(())
        })).await
    }

    /// Write a batch of user passwords to the database.
    ///
    /// # Errors
    ///
    /// Errors are returned in the following conditions:
    ///
    /// - If the database writer connection pool had an error.
    #[allow(clippy::missing_panics_doc)] // not a real panic
    #[tracing::instrument(skip_all, level = Level::DEBUG)]
    pub async fn write_passwords(
        &mut self,
        passwords: Vec<MasNewUserPassword>,
    ) -> Result<(), Error> {
        self.writer_pool.spawn_with_connection(move |conn| Box::pin(async move {
            if passwords.is_empty() {
                return Ok(());
            }

            let mut user_password_ids: Vec<Uuid> = Vec::with_capacity(passwords.len());
            let mut user_ids: Vec<Uuid> = Vec::with_capacity(passwords.len());
            let mut hashed_passwords: Vec<String> = Vec::with_capacity(passwords.len());
            let mut created_ats: Vec<DateTime<Utc>> = Vec::with_capacity(passwords.len());
            let mut versions: Vec<i32> = Vec::with_capacity(passwords.len());
            for MasNewUserPassword {
                user_password_id,
                user_id,
                hashed_password,
                created_at,
            } in passwords
            {
                user_password_ids.push(user_password_id);
                user_ids.push(user_id);
                hashed_passwords.push(hashed_password);
                created_ats.push(created_at);
            // TODO hardcoding version to `1` may not be correct long-term?
                versions.push(1);
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
        })).await
    }
}

// How many entries to buffer at once, before writing a batch of rows to the database.
// TODO tune: didn't see that much difference between 4k and 64k
// (4k: 13.5~14, 64k: 12.5~13s — streaming the whole way would be better, especially for DB latency, but probably fiiine
// and also we won't be able to stream to two tables at once...)
const WRITE_BUFFER_BATCH_SIZE: usize = 4096;

pub struct MasUserWriteBuffer<'writer, 'conn> {
    users: Vec<MasNewUser>,
    passwords: Vec<MasNewUserPassword>,
    writer: &'writer mut MasWriter<'conn>,
}

impl<'writer, 'conn> MasUserWriteBuffer<'writer, 'conn> {
    pub fn new(writer: &'writer mut MasWriter<'conn>) -> Self {
        MasUserWriteBuffer {
            users: Vec::with_capacity(WRITE_BUFFER_BATCH_SIZE),
            passwords: Vec::with_capacity(WRITE_BUFFER_BATCH_SIZE),
            writer,
        }
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        self.flush_users().await?;
        self.flush_passwords().await?;
        Ok(())
    }

    pub async fn flush_users(&mut self) -> Result<(), Error> {
        // via copy: 13s
        // not via copy: 14s
        // difference probably gets worse with latency
        self.writer
            .write_users(std::mem::take(&mut self.users))
            .await?;

        self.users.reserve_exact(WRITE_BUFFER_BATCH_SIZE);
        Ok(())
    }

    pub async fn flush_passwords(&mut self) -> Result<(), Error> {
        self.writer
            .write_passwords(std::mem::take(&mut self.passwords))
            .await?;
        self.passwords.reserve_exact(WRITE_BUFFER_BATCH_SIZE);

        Ok(())
    }

    pub async fn write_user(&mut self, user: MasNewUser) -> Result<(), Error> {
        self.users.push(user);
        if self.users.len() >= WRITE_BUFFER_BATCH_SIZE {
            self.flush_users().await?;
        }
        Ok(())
    }

    pub async fn write_password(&mut self, password: MasNewUserPassword) -> Result<(), Error> {
        self.passwords.push(password);
        if self.passwords.len() >= WRITE_BUFFER_BATCH_SIZE {
            self.flush_passwords().await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // TODO test me
}
