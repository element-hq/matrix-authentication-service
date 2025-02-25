// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

//! A module containing the PostgreSQL implementation of the policy data
//! storage.

use async_trait::async_trait;
use mas_data_model::PolicyData;
use mas_storage::{Clock, policy_data::PolicyDataRepository};
use rand::RngCore;
use serde_json::Value;
use sqlx::{PgConnection, types::Json};
use ulid::Ulid;
use uuid::Uuid;

use crate::{DatabaseError, ExecuteExt};

/// An implementation of [`PolicyDataRepository`] for a PostgreSQL connection.
pub struct PgPolicyDataRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgPolicyDataRepository<'c> {
    /// Create a new [`PgPolicyDataRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct PolicyDataLookup {
    policy_data_id: Uuid,
    created_at: chrono::DateTime<chrono::Utc>,
    data: Json<Value>,
}

impl From<PolicyDataLookup> for PolicyData {
    fn from(value: PolicyDataLookup) -> Self {
        PolicyData {
            id: value.policy_data_id.into(),
            created_at: value.created_at,
            data: value.data.0,
        }
    }
}

#[async_trait]
impl PolicyDataRepository for PgPolicyDataRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.policy_data.get",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn get(&mut self) -> Result<Option<PolicyData>, Self::Error> {
        let row = sqlx::query_as!(
            PolicyDataLookup,
            r#"
            SELECT policy_data_id, created_at, data
            FROM policy_data
            ORDER BY policy_data_id DESC
            LIMIT 1
            "#
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
        name = "db.policy_data.set",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn set(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn Clock,
        data: Value,
    ) -> Result<PolicyData, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);

        sqlx::query!(
            r#"
            INSERT INTO policy_data (policy_data_id, created_at, data)
            VALUES ($1, $2, $3)
            "#,
            Uuid::from(id),
            created_at,
            data,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(PolicyData {
            id,
            created_at,
            data,
        })
    }

    #[tracing::instrument(
        name = "db.policy_data.prune",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn prune(&mut self, keep: usize) -> Result<usize, Self::Error> {
        let res = sqlx::query!(
            r#"
            DELETE FROM policy_data
            WHERE policy_data_id IN (
                SELECT policy_data_id
                FROM policy_data
                ORDER BY policy_data_id DESC
                OFFSET $1
            )
            "#,
            i64::try_from(keep).map_err(DatabaseError::to_invalid_operation)?
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(res
            .rows_affected()
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)?)
    }
}

#[cfg(test)]
mod tests {
    use mas_storage::{clock::MockClock, policy_data::PolicyDataRepository};
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use serde_json::json;
    use sqlx::PgPool;

    use crate::policy_data::PgPolicyDataRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_policy_data(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();
        let mut conn = pool.acquire().await.unwrap();
        let mut repo = PgPolicyDataRepository::new(&mut conn);

        // Get an empty state at first
        let data = repo.get().await.unwrap();
        assert_eq!(data, None);

        // Set some data
        let value1 = json!({"hello": "world"});
        let policy_data1 = repo.set(&mut rng, &clock, value1.clone()).await.unwrap();
        assert_eq!(policy_data1.data, value1);

        let data_fetched1 = repo.get().await.unwrap().unwrap();
        assert_eq!(policy_data1, data_fetched1);

        // Set some new data
        clock.advance(chrono::Duration::seconds(1));
        let value2 = json!({"foo": "bar"});
        let policy_data2 = repo.set(&mut rng, &clock, value2.clone()).await.unwrap();
        assert_eq!(policy_data2.data, value2);

        // Check the new data is fetched
        let data_fetched2 = repo.get().await.unwrap().unwrap();
        assert_eq!(data_fetched2, policy_data2);

        // Prune until the first entry
        let affected = repo.prune(1).await.unwrap();
        let data_fetched3 = repo.get().await.unwrap().unwrap();
        assert_eq!(data_fetched3, policy_data2);
        assert_eq!(affected, 1);

        // Do a raw query to check the other rows were pruned
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM policy_data")
            .fetch_one(&mut *conn)
            .await
            .unwrap();
        assert_eq!(count, 1);
    }
}
