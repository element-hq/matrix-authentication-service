//! # MAS Writer
//!
//! This module is responsible for writing new records to MAS' database.

use chrono::{DateTime, Utc};
use sqlx::{prelude::FromRow, query, PgConnection};
use thiserror::Error;
use thiserror_ext::ContextInto;
use tracing::info;
use uuid::Uuid;

#[derive(Debug, Error, ContextInto)]
pub enum Error {
    #[error("database error whilst {context}: {source}")]
    Database {
        source: sqlx::Error,
        context: String,
    },
}

/// List of MAS tables that we should acquire an `ACCESS EXCLUSIVE` lock on.
///
/// This is a safety measure against other processes changing the data underneath our feet.
// TODO not complete!
const TABLES_TO_LOCK: &[&str] = &["users"];

/// List of MAS tables to pause indices on whilst doing the bulk load.
const TABLES_TO_PAUSE_INDICES_ON: &[(&str, &[&str])] =
    &[("users", &["users_pkey", "users_username_unique"])];

struct IndexToRestore {
    name: String,
    table_name: String,
    definition: String,
}

pub struct MasWriter<'c> {
    conn: &'c mut PgConnection,

    indices_to_restore: Vec<IndexToRestore>,
}

pub struct MasNewUser {
    pub user_id: Uuid,
    pub username: String,
    pub created_at: DateTime<Utc>,
    pub locked_at: Option<DateTime<Utc>>,
    pub can_request_admin: bool,
}

pub const INDEX_AND_CONSTRAINT_DROPS: &[&str] = &[
    // TODO this is not maintainable and we also don't recreate the cascaded constraints here.
    "ALTER TABLE users DROP CONSTRAINT users_pkey CASCADE, DROP CONSTRAINT users_username_unique;",
    "COMMIT;",
    "BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;",
    "LOCK TABLE users IN ACCESS EXCLUSIVE MODE NOWAIT;",
];

pub const INDEX_AND_CONSTRAINT_RESTORES: &[&str] =
    &["ALTER TABLE users ADD CONSTRAINT users_pkey PRIMARY KEY (user_id), ADD CONSTRAINT users_username_unique UNIQUE (username);"];

impl<'conn> MasWriter<'conn> {
    pub async fn new(mas_connection: &'conn mut PgConnection) -> Result<Self, Error> {
        // TODO we can probably reduce the level given that we take a full lock?
        query("BEGIN TRANSACTION ISOLATION LEVEL SERIALIZABLE;")
            .execute(&mut *mas_connection)
            .await
            .into_database("begin MAS transaction")?;

        for table in TABLES_TO_LOCK {
            query(&format!(
                "LOCK TABLE {table} IN ACCESS EXCLUSIVE MODE NOWAIT;"
            ))
            .execute(&mut *mas_connection)
            .await
            .into_database_with(|| format!("locking MAS table `{table}`"))?;
        }

        // TODO temporarily drop and backup indices
        let indices_to_restore = Self::pause_indices(mas_connection).await?;

        Ok(Self {
            conn: mas_connection,
            indices_to_restore,
        })
    }

    async fn pause_indices(conn: &mut PgConnection) -> Result<Vec<IndexToRestore>, Error> {
        #[derive(FromRow)]
        struct Index {
            indexname: String,
            indexdef: String,
        }

        let mut indices_to_restore = Vec::new();

        for stmt in INDEX_AND_CONSTRAINT_DROPS {
            info!("{stmt} ...");
            sqlx::query(stmt)
                .execute(&mut *conn)
                .await
                .into_database("failed to apply pre-migration constraint drop")?;
            info!("ok");
        }

        // TODO good approach but need to adapt to constraints, see https://dba.stackexchange.com/questions/206562/postgres-read-constraints-definition
        // for (table_name, expected_indices) in TABLES_TO_PAUSE_INDICES_ON {
        //     let table_indices = sqlx::query_as!(
        //         Index,
        //         "SELECT indexname AS \"indexname!\", indexdef AS \"indexdef!\" FROM pg_indexes WHERE schemaname = current_schema AND tablename = $1 AND indexname IS NOT NULL AND indexdef IS NOT NULL",
        //         table_name
        //     ).fetch_all(&mut *conn).await.into_database("cannot search for indices")?;

        //     for table_index in table_indices {
        //         let index_name = &table_index.indexname;
        //         indices_to_restore.push(IndexToRestore {
        //             name: table_index.indexname.clone(),
        //             table_name: (*table_name).to_owned(),
        //             definition: table_index.indexdef,
        //         });

        //         sqlx::query(&format!("DROP INDEX {index_name};"))
        //             .execute(&mut *conn)
        //             .await
        //             .into_database_with(|| format!("failed to temporarily drop {index_name}"))?;
        //         info!("dropped {index_name}");
        //     }
        // }

        Ok(indices_to_restore)
    }

    async fn restore_indices(&mut self) -> Result<(), Error> {
        for stmt in INDEX_AND_CONSTRAINT_RESTORES {
            info!("{stmt} ...");
            sqlx::query(stmt)
                .execute(&mut *self.conn)
                .await
                .into_database("failed to apply pre-migration constraint drop")?;
            info!("ok");
        }

        for index_to_restore in std::mem::take(&mut self.indices_to_restore) {
            sqlx::query(&format!("{};", index_to_restore.definition))
                .execute(&mut *self.conn)
                .await
                .into_database_with(|| {
                    format!("failed to recreate index {}", index_to_restore.name)
                })?;
        }
        Ok(())
    }

    pub async fn finish(mut self) -> Result<(), Error> {
        // TODO restore dropped indices
        self.restore_indices().await?;

        // TODO we might be able to use normal transaction management from sqlx here...
        query("COMMIT;")
            .execute(&mut *self.conn)
            .await
            .into_database("ending MAS transaction")?;
        Ok(())
    }

    /// Write a batch of users to the database.
    pub async fn write_users(&mut self, users: Vec<MasNewUser>) -> Result<(), Error> {
        // `UNNEST` is a fast way to do bulk inserts.
        // See <https://github.com/launchbadge/sqlx/blob/main/FAQ.md#how-can-i-bind-an-array-to-a-values-clause-how-can-i-do-bulk-inserts>.
        // TODO in the future we could consider using sqlx's support for `PgCopyIn`, which is allegedly the best
        // for insert performance, but is a bit less simple to encode.

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
            INSERT INTO users
            (user_id, username, created_at, locked_at, can_request_admin)
            SELECT * FROM UNNEST($1::UUID[], $2::TEXT[], $3::TIMESTAMP WITH TIME ZONE[], $4::TIMESTAMP WITH TIME ZONE[], $5::BOOL[])
            "#,
            &user_ids[..],
            &usernames[..],
            &created_ats[..],
            // We need to override the typing for arrays of optionals (sqlx limitation)
            &locked_ats[..] as &[Option<DateTime<Utc>>],
            &can_request_admins[..],
        ).execute(&mut *self.conn).await.into_database("writing users to MAS")?;

        Ok(())
    }

    pub async fn write_users_via_copy(&mut self, users: Vec<MasNewUser>) -> Result<(), Error> {
        // TODO THIS IS NOT SUITABLE FOR PRODUCTION; DOES NOT IMPLEMENT ESCAPING RULES

        let mut copy = self.conn.copy_in_raw("COPY users (user_id, username, created_at, locked_at, can_request_admin) FROM STDIN;").await.into_database("failed to start COPY users")?;
        let mut buf = Vec::with_capacity(32768);
        for MasNewUser {
            user_id,
            username,
            created_at,
            locked_at,
            can_request_admin,
        } in users
        {
            let locked_at = locked_at
                .map(|dt| dt.to_rfc3339())
                .unwrap_or_else(|| "\\N".to_owned());
            buf.extend_from_slice(
                format!("{user_id}\t{username}\t{created_at}\t{locked_at}\t{can_request_admin}\n")
                    .as_bytes(),
            );

            if buf.len() > 16384 {
                copy.send(buf.as_slice())
                    .await
                    .into_database("failed to send COPY data")?;
                buf.clear();
            }
        }

        buf.extend_from_slice(b"\\.\n");

        copy.send(buf.as_slice())
            .await
            .into_database("failed to send last COPY data")?;

        copy.finish()
            .await
            .into_database("failed to COPY users into table")?;

        Ok(())
    }
}

// How many entries to buffer at once, before writing a batch of rows to the database.
// TODO tune: didn't see that much difference between 4k and 64k
// (4k: 13.5~14, 64k: 12.5~13s — streaming the whole way would be better, especially for DB latency, but probably fiiine
// and also we won't be able to stream to two tables at once...)
const WRITE_BUFFER_BATCH_SIZE: usize = 4096;

// TODO should split this out into the different stages
pub struct MasWriteBuffer {
    users: Vec<MasNewUser>,
}

impl Default for MasWriteBuffer {
    fn default() -> Self {
        Self {
            users: Vec::with_capacity(WRITE_BUFFER_BATCH_SIZE),
        }
    }
}

impl MasWriteBuffer {
    pub async fn finish(mut self, writer: &mut MasWriter<'_>) -> Result<(), Error> {
        self.flush_users(writer).await?;
        Ok(())
    }

    pub async fn flush_users(&mut self, writer: &mut MasWriter<'_>) -> Result<(), Error> {
        // via copy: 13s
        // not via copy: 14s
        // difference probably gets worse with latency
        writer
            .write_users_via_copy(std::mem::take(&mut self.users))
            .await?;
        // std::mem::take(&mut self.users); // TODO testing only

        self.users.reserve_exact(WRITE_BUFFER_BATCH_SIZE);
        Ok(())
    }

    pub async fn write_user(
        &mut self,
        writer: &mut MasWriter<'_>,
        user: MasNewUser,
    ) -> Result<(), Error> {
        self.users.push(user);
        if self.users.len() >= WRITE_BUFFER_BATCH_SIZE {
            self.flush_users(writer).await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod test {
    // TODO test me
}
