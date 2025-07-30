// Copyright 2024, 2025 New Vector Ltd.
// Copyright 2024 The Matrix.org Foundation C.I.C.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

use async_trait::async_trait;
use mas_data_model::{Clock, User};
use mas_storage::user::UserTermsRepository;
use rand::RngCore;
use sqlx::PgConnection;
use ulid::Ulid;
use url::Url;
use uuid::Uuid;

use crate::{DatabaseError, tracing::ExecuteExt};

/// An implementation of [`UserTermsRepository`] for a PostgreSQL connection
pub struct PgUserTermsRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserTermsRepository<'c> {
    /// Create a new [`PgUserTermsRepository`] from an active PostgreSQL
    /// connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[async_trait]
impl UserTermsRepository for PgUserTermsRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_terms.accept_terms",
        skip_all,
        fields(
            db.query.text,
            %user.id,
            user_terms.id,
            %user_terms.url = terms_url.as_str(),
        ),
        err,
    )]
    async fn accept_terms(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        user: &User,
        terms_url: Url,
    ) -> Result<(), Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);
        tracing::Span::current().record("user_terms.id", tracing::field::display(id));

        sqlx::query!(
            r#"
            INSERT INTO user_terms (user_terms_id, user_id, terms_url, created_at)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (user_id, terms_url) DO NOTHING
            "#,
            Uuid::from(id),
            Uuid::from(user.id),
            terms_url.as_str(),
            created_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }
}
