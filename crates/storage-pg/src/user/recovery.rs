// Copyright 2024 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::{UserEmail, UserRecoverySession, UserRecoveryTicket};
use mas_storage::{Clock, user::UserRecoveryRepository};
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`UserRecoveryRepository`] for a PostgreSQL connection
pub struct PgUserRecoveryRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRecoveryRepository<'c> {
    /// Create a new [`PgUserRecoveryRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct UserRecoverySessionRow {
    user_recovery_session_id: Uuid,
    email: String,
    user_agent: String,
    ip_address: Option<IpAddr>,
    locale: String,
    created_at: DateTime<Utc>,
    consumed_at: Option<DateTime<Utc>>,
}

impl From<UserRecoverySessionRow> for UserRecoverySession {
    fn from(row: UserRecoverySessionRow) -> Self {
        UserRecoverySession {
            id: row.user_recovery_session_id.into(),
            email: row.email,
            user_agent: row.user_agent,
            ip_address: row.ip_address,
            locale: row.locale,
            created_at: row.created_at,
            consumed_at: row.consumed_at,
        }
    }
}

struct UserRecoveryTicketRow {
    user_recovery_ticket_id: Uuid,
    user_recovery_session_id: Uuid,
    user_email_id: Uuid,
    ticket: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
}

impl From<UserRecoveryTicketRow> for UserRecoveryTicket {
    fn from(row: UserRecoveryTicketRow) -> Self {
        Self {
            id: row.user_recovery_ticket_id.into(),
            user_recovery_session_id: row.user_recovery_session_id.into(),
            user_email_id: row.user_email_id.into(),
            ticket: row.ticket,
            created_at: row.created_at,
            expires_at: row.expires_at,
        }
    }
}

#[async_trait]
impl UserRecoveryRepository for PgUserRecoveryRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_recovery.lookup_session",
        skip_all,
        fields(
            db.query.text,
            user_recovery_session.id = %id,
        ),
        err,
    )]
    async fn lookup_session(
        &mut self,
        id: Ulid,
    ) -> Result<Option<UserRecoverySession>, Self::Error> {
        let row = sqlx::query_as!(
            UserRecoverySessionRow,
            r#"
                SELECT
                      user_recovery_session_id
                    , email
                    , user_agent
                    , ip_address as "ip_address: IpAddr"
                    , locale
                    , created_at
                    , consumed_at
                FROM user_recovery_sessions
                WHERE user_recovery_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(row.into()))
    }

    #[tracing::instrument(
        name = "db.user_recovery.add_session",
        skip_all,
        fields(
            db.query.text,
            user_recovery_session.id,
            user_recovery_session.email = email,
            user_recovery_session.user_agent = user_agent,
            user_recovery_session.ip_address = ip_address.map(|ip| ip.to_string()),
        )
    )]
    async fn add_session(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        email: String,
        user_agent: String,
        ip_address: Option<IpAddr>,
        locale: String,
    ) -> Result<UserRecoverySession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_recovery_session.id", tracing::field::display(id));
        sqlx::query!(
            r#"
                INSERT INTO user_recovery_sessions (
                      user_recovery_session_id
                    , email
                    , user_agent
                    , ip_address
                    , locale
                    , created_at
                )
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            &email,
            &*user_agent,
            ip_address as Option<IpAddr>,
            &locale,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let user_recovery_session = UserRecoverySession {
            id,
            email,
            user_agent,
            ip_address,
            locale,
            created_at,
            consumed_at: None,
        };

        Ok(user_recovery_session)
    }

    #[tracing::instrument(
        name = "db.user_recovery.find_ticket",
        skip_all,
        fields(
            db.query.text,
            user_recovery_ticket.id = ticket,
        ),
        err,
    )]
    async fn find_ticket(
        &mut self,
        ticket: &str,
    ) -> Result<Option<UserRecoveryTicket>, Self::Error> {
        let row = sqlx::query_as!(
            UserRecoveryTicketRow,
            r#"
                SELECT
                      user_recovery_ticket_id
                    , user_recovery_session_id
                    , user_email_id
                    , ticket
                    , created_at
                    , expires_at
                FROM user_recovery_tickets
                WHERE ticket = $1
            "#,
            ticket,
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(row) = row else {
            return Ok(None);
        };

        Ok(Some(row.into()))
    }

    #[tracing::instrument(
        name = "db.user_recovery.add_ticket",
        skip_all,
        fields(
            db.query.text,
            user_recovery_ticket.id,
            user_recovery_ticket.id = ticket,
            %user_recovery_session.id,
            %user_email.id,
        )
    )]
    async fn add_ticket(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user_recovery_session: &UserRecoverySession,
        user_email: &UserEmail,
        ticket: String,
    ) -> Result<UserRecoveryTicket, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_recovery_ticket.id", tracing::field::display(id));

        // TODO: move that to a parameter
        let expires_at = created_at + Duration::minutes(10);

        sqlx::query!(
            r#"
                INSERT INTO user_recovery_tickets (
                      user_recovery_ticket_id
                    , user_recovery_session_id
                    , user_email_id
                    , ticket
                    , created_at
                    , expires_at
                )
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            Uuid::from(user_recovery_session.id),
            Uuid::from(user_email.id),
            &ticket,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        let ticket = UserRecoveryTicket {
            id,
            user_recovery_session_id: user_recovery_session.id,
            user_email_id: user_email.id,
            ticket,
            created_at,
            expires_at,
        };

        Ok(ticket)
    }

    #[tracing::instrument(
        name = "db.user_recovery.consume_ticket",
        skip_all,
        fields(
            db.query.text,
            %user_recovery_ticket.id,
            user_email.id = %user_recovery_ticket.user_email_id,
            %user_recovery_session.id,
            %user_recovery_session.email,
        ),
        err,
    )]
    async fn consume_ticket(
        &mut self,
        clock: &dyn Clock,
        user_recovery_ticket: UserRecoveryTicket,
        mut user_recovery_session: UserRecoverySession,
    ) -> Result<UserRecoverySession, Self::Error> {
        // We don't really use the ticket, we just want to make sure we drop it
        let _ = user_recovery_ticket;

        // This should have been checked by the caller
        if user_recovery_session.consumed_at.is_some() {
            return Err(DatabaseError::invalid_operation());
        }

        let consumed_at = clock.now();

        let res = sqlx::query!(
            r#"
                UPDATE user_recovery_sessions
                SET consumed_at = $1
                WHERE user_recovery_session_id = $2
            "#,
            consumed_at,
            Uuid::from(user_recovery_session.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        user_recovery_session.consumed_at = Some(consumed_at);

        DatabaseError::ensure_affected_rows(&res, 1)?;

        Ok(user_recovery_session)
    }
}
