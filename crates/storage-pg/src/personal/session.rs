// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use std::net::IpAddr;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::{
    Clock, User,
    personal::session::{PersonalSession, SessionState},
};
use mas_storage::personal::PersonalSessionRepository;
use oauth2_types::scope::Scope;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, errors::DatabaseInconsistencyError, tracing::ExecuteExt as _};

/// An implementation of [`PersonalSessionRepository`] for a PostgreSQL
/// connection
pub struct PgPersonalSessionRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgPersonalSessionRepository<'c> {
    /// Create a new [`PgOAuth2SessionRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct PersonalSessionLookup {
    personal_session_id: Uuid,
    owner_user_id: Uuid,
    actor_user_id: Uuid,
    human_name: String,
    scope_list: Vec<String>,
    created_at: DateTime<Utc>,
    revoked_at: Option<DateTime<Utc>>,
    last_active_at: Option<DateTime<Utc>>,
    last_active_ip: Option<IpAddr>,
}

impl TryFrom<PersonalSessionLookup> for PersonalSession {
    type Error = DatabaseInconsistencyError;

    fn try_from(value: PersonalSessionLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(value.personal_session_id);
        let scope: Result<Scope, _> = value.scope_list.iter().map(|s| s.parse()).collect();
        let scope = scope.map_err(|e| {
            DatabaseInconsistencyError::on("personal_sessions")
                .column("scope")
                .row(id)
                .source(e)
        })?;

        let state = match value.revoked_at {
            None => SessionState::Valid,
            Some(revoked_at) => SessionState::Revoked { revoked_at },
        };

        Ok(PersonalSession {
            id,
            state,
            owner_user_id: Ulid::from(value.owner_user_id),
            actor_user_id: Ulid::from(value.actor_user_id),
            human_name: value.human_name,
            scope,
            created_at: value.created_at,
            last_active_at: value.last_active_at,
            last_active_ip: value.last_active_ip,
        })
    }
}

#[async_trait]
impl PersonalSessionRepository for PgPersonalSessionRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.personal_session.lookup",
        skip_all,
        fields(
            db.query.text,
            session.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<PersonalSession>, Self::Error> {
        let res = sqlx::query_as!(
            PersonalSessionLookup,
            r#"
                SELECT personal_session_id
                     , owner_user_id
                     , actor_user_id
                     , scope_list
                     , created_at
                     , revoked_at
                     , human_name
                     , last_active_at
                     , last_active_ip as "last_active_ip: IpAddr"
                FROM personal_sessions

                WHERE personal_session_id = $1
            "#,
            Uuid::from(id),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(session) = res else { return Ok(None) };

        Ok(Some(session.try_into()?))
    }

    #[tracing::instrument(
        name = "db.personal_session.add",
        skip_all,
        fields(
            db.query.text,
            session.id,
            session.scope = %scope,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        owner_user: &User,
        actor_user: &User,
        human_name: String,
        scope: Scope,
    ) -> Result<PersonalSession, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("session.id", tracing::field::display(id));

        let scope_list: Vec<String> = scope.iter().map(|s| s.as_str().to_owned()).collect();

        sqlx::query!(
            r#"
                INSERT INTO personal_sessions
                    ( personal_session_id
                    , owner_user_id
                    , actor_user_id
                    , human_name
                    , scope_list
                    , created_at
                    )
                VALUES ($1, $2, $3, $4, $5, $6)
            "#,
            Uuid::from(id),
            Uuid::from(owner_user.id),
            Uuid::from(actor_user.id),
            &human_name,
            &scope_list,
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(PersonalSession {
            id,
            state: SessionState::Valid,
            owner_user_id: owner_user.id,
            actor_user_id: actor_user.id,
            human_name,
            scope,
            created_at,
            last_active_at: None,
            last_active_ip: None,
        })
    }

    #[tracing::instrument(
        name = "db.personal_session.revoke",
        skip_all,
        fields(
            db.query.text,
            %session.id,
            %session.scope,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        session: PersonalSession,
    ) -> Result<PersonalSession, Self::Error> {
        let finished_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE personal_sessions
                SET revoked_at = $2
                WHERE personal_session_id = $1
            "#,
            Uuid::from(session.id),
            finished_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        session
            .finish(finished_at)
            .map_err(DatabaseError::to_invalid_operation)
    }
}
