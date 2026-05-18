// Copyright 2026 Element Creations Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
// Please see LICENSE files in the repository root for full details.

//! PostgreSQL implementation of [`JwksCacheRepository`].

use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use mas_data_model::JwksCacheEntry;
use mas_jose::jwk::PublicJsonWebKeySet;
use mas_storage::jwks_cache::{JwksCacheRepository, JwksCacheUpsert};
use sqlx::{PgConnection, types::Json};
use url::Url;

use crate::{DatabaseError, DatabaseInconsistencyError, ExecuteExt};

/// An implementation of [`JwksCacheRepository`] for a PostgreSQL connection.
pub struct PgJwksCacheRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgJwksCacheRepository<'c> {
    /// Create a new [`PgJwksCacheRepository`] from an active PostgreSQL
    /// connection.
    #[must_use]
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

struct JwksCacheLookup {
    jwks_uri: String,
    jwks: Json<serde_json::Value>,
    fetched_at: DateTime<Utc>,
    fresh_until: DateTime<Utc>,
    stale_until: Option<DateTime<Utc>>,
    etag: Option<String>,
    last_modified: Option<String>,
    forced_refresh_at: Option<DateTime<Utc>>,
    last_used_at: DateTime<Utc>,
}

impl TryFrom<JwksCacheLookup> for JwksCacheEntry {
    type Error = DatabaseError;

    fn try_from(value: JwksCacheLookup) -> Result<Self, Self::Error> {
        let jwks_uri = value.jwks_uri.parse().map_err(|e| {
            DatabaseInconsistencyError::on("jwks_cache")
                .column("jwks_uri")
                .source(e)
        })?;

        let jwks: PublicJsonWebKeySet = serde_json::from_value(value.jwks.0).map_err(|e| {
            DatabaseInconsistencyError::on("jwks_cache")
                .column("jwks")
                .source(e)
        })?;

        Ok(JwksCacheEntry {
            jwks_uri,
            jwks,
            fetched_at: value.fetched_at,
            fresh_until: value.fresh_until,
            stale_until: value.stale_until,
            etag: value.etag,
            last_modified: value.last_modified,
            forced_refresh_at: value.forced_refresh_at,
            last_used_at: value.last_used_at,
        })
    }
}

#[async_trait]
impl JwksCacheRepository for PgJwksCacheRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.jwks_cache.get",
        skip_all,
        fields(
            db.query.text,
            jwks_cache.jwks_uri = %jwks_uri,
        ),
        err,
    )]
    async fn get(&mut self, jwks_uri: &Url) -> Result<Option<JwksCacheEntry>, Self::Error> {
        let row = sqlx::query_as!(
            JwksCacheLookup,
            r#"
            SELECT
                jwks_uri,
                jwks AS "jwks: Json<serde_json::Value>",
                fetched_at,
                fresh_until,
                stale_until,
                etag,
                last_modified,
                forced_refresh_at,
                last_used_at
            FROM jwks_cache
            WHERE jwks_uri = $1
            "#,
            jwks_uri.as_str(),
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        row.map(JwksCacheEntry::try_from).transpose()
    }

    #[tracing::instrument(
        name = "db.jwks_cache.upsert",
        skip_all,
        fields(
            db.query.text,
            jwks_cache.jwks_uri = %jwks_uri,
        ),
        err,
    )]
    async fn upsert(
        &mut self,
        jwks_uri: &Url,
        values: JwksCacheUpsert<'_>,
    ) -> Result<(), Self::Error> {
        let jwks_value = serde_json::to_value(values.jwks).map_err(|e| {
            DatabaseError::InvalidOperation {
                source: Some(Box::new(e)),
            }
        })?;

        sqlx::query!(
            r#"
            INSERT INTO jwks_cache
                (jwks_uri, jwks, fetched_at, fresh_until, stale_until,
                 etag, last_modified, last_used_at)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $3)
            ON CONFLICT (jwks_uri) DO UPDATE SET
                jwks          = EXCLUDED.jwks,
                fetched_at    = EXCLUDED.fetched_at,
                fresh_until   = EXCLUDED.fresh_until,
                stale_until   = EXCLUDED.stale_until,
                etag          = EXCLUDED.etag,
                last_modified = EXCLUDED.last_modified
            "#,
            jwks_uri.as_str(),
            jwks_value,
            values.fetched_at,
            values.fresh_until,
            values.stale_until,
            values.etag,
            values.last_modified,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.jwks_cache.try_claim_forced_refresh",
        skip_all,
        fields(
            db.query.text,
            jwks_cache.jwks_uri = %jwks_uri,
        ),
        err,
    )]
    async fn try_claim_forced_refresh(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        cooldown: Duration,
    ) -> Result<bool, Self::Error> {
        let cutoff = now - cooldown;

        // A row may not exist yet for this URI (e.g. first-ever kid miss for a
        // newly-configured upstream). In that case the conditional UPDATE would
        // affect zero rows even though the caller *should* proceed. Treat
        // "no row" as the caller winning the claim — there's no contender to
        // race with, and the subsequent fetch will INSERT the row anyway.
        let exists = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT 1 FROM jwks_cache WHERE jwks_uri = $1) AS "exists!""#,
            jwks_uri.as_str(),
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        if !exists {
            return Ok(true);
        }

        let result = sqlx::query!(
            r#"
            UPDATE jwks_cache
               SET forced_refresh_at = $2
             WHERE jwks_uri = $1
               AND (forced_refresh_at IS NULL OR forced_refresh_at < $3)
            "#,
            jwks_uri.as_str(),
            now,
            cutoff,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[tracing::instrument(
        name = "db.jwks_cache.touch",
        skip_all,
        fields(
            db.query.text,
            jwks_cache.jwks_uri = %jwks_uri,
        ),
        err,
    )]
    async fn touch(
        &mut self,
        jwks_uri: &Url,
        now: DateTime<Utc>,
        threshold: DateTime<Utc>,
    ) -> Result<(), Self::Error> {
        sqlx::query!(
            r#"
            UPDATE jwks_cache
               SET last_used_at = $2
             WHERE jwks_uri = $1
               AND last_used_at < $3
            "#,
            jwks_uri.as_str(),
            now,
            threshold,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(())
    }

    #[tracing::instrument(
        name = "db.jwks_cache.delete",
        skip_all,
        fields(
            db.query.text,
            jwks_cache.jwks_uri = %jwks_uri,
        ),
        err,
    )]
    async fn delete(&mut self, jwks_uri: &Url) -> Result<bool, Self::Error> {
        let result = sqlx::query!(
            r#"DELETE FROM jwks_cache WHERE jwks_uri = $1"#,
            jwks_uri.as_str(),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(result.rows_affected() > 0)
    }

    #[tracing::instrument(
        name = "db.jwks_cache.delete_unused_since",
        skip_all,
        fields(db.query.text),
        err,
    )]
    async fn delete_unused_since(
        &mut self,
        before: DateTime<Utc>,
    ) -> Result<u64, Self::Error> {
        let result = sqlx::query!(
            r#"DELETE FROM jwks_cache WHERE last_used_at < $1"#,
            before,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(result.rows_affected())
    }

    #[tracing::instrument(
        name = "db.jwks_cache.list",
        skip_all,
        fields(db.query.text),
        err,
    )]
    async fn list(&mut self) -> Result<Vec<JwksCacheEntry>, Self::Error> {
        let rows = sqlx::query_as!(
            JwksCacheLookup,
            r#"
            SELECT
                jwks_uri,
                jwks AS "jwks: Json<serde_json::Value>",
                fetched_at,
                fresh_until,
                stale_until,
                etag,
                last_modified,
                forced_refresh_at,
                last_used_at
            FROM jwks_cache
            ORDER BY jwks_uri
            "#,
        )
        .traced()
        .fetch_all(&mut *self.conn)
        .await?;

        rows.into_iter().map(JwksCacheEntry::try_from).collect()
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_data_model::{Clock, clock::MockClock};
    use mas_jose::jwk::PublicJsonWebKeySet;
    use mas_storage::jwks_cache::{JwksCacheRepository, JwksCacheUpsert};
    use sqlx::PgPool;
    use url::Url;

    use crate::jwks_cache::PgJwksCacheRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_get_upsert_roundtrip(pool: PgPool) {
        let clock = MockClock::default();
        let mut conn = pool.acquire().await.unwrap();
        let mut repo = PgJwksCacheRepository::new(&mut conn);
        let uri: Url = "https://example.com/jwks".parse().unwrap();
        let jwks = PublicJsonWebKeySet::default();

        // No entry yet.
        assert!(repo.get(&uri).await.unwrap().is_none());

        let now = clock.now();
        let fresh_until = now + Duration::minutes(15);
        repo.upsert(
            &uri,
            JwksCacheUpsert {
                jwks: &jwks,
                fetched_at: now,
                fresh_until,
                stale_until: Some(fresh_until + Duration::minutes(5)),
                etag: Some(r#""abc123""#),
                last_modified: None,
            },
        )
        .await
        .unwrap();

        let entry = repo.get(&uri).await.unwrap().expect("row should exist");
        assert_eq!(entry.jwks_uri, uri);
        assert_eq!(entry.fetched_at, now);
        assert_eq!(entry.fresh_until, fresh_until);
        assert_eq!(entry.etag.as_deref(), Some(r#""abc123""#));
        assert_eq!(entry.last_used_at, now);
        assert!(entry.forced_refresh_at.is_none());

        // Second upsert overwrites the body and freshness metadata, but the
        // upsert SQL deliberately doesn't touch last_used_at or
        // forced_refresh_at.
        clock.advance(Duration::minutes(20));
        let later = clock.now();
        repo.upsert(
            &uri,
            JwksCacheUpsert {
                jwks: &jwks,
                fetched_at: later,
                fresh_until: later + Duration::minutes(15),
                stale_until: None,
                etag: Some(r#""def456""#),
                last_modified: Some("Mon, 18 May 2026 12:00:00 GMT"),
            },
        )
        .await
        .unwrap();

        let entry = repo.get(&uri).await.unwrap().unwrap();
        assert_eq!(entry.fetched_at, later);
        assert_eq!(entry.etag.as_deref(), Some(r#""def456""#));
        assert_eq!(entry.last_modified.as_deref(), Some("Mon, 18 May 2026 12:00:00 GMT"));
        assert_eq!(entry.last_used_at, now, "last_used_at must not be touched by upsert");
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_forced_refresh_cooldown(pool: PgPool) {
        let clock = MockClock::default();
        let mut conn = pool.acquire().await.unwrap();
        let mut repo = PgJwksCacheRepository::new(&mut conn);
        let uri: Url = "https://example.com/jwks".parse().unwrap();
        let jwks = PublicJsonWebKeySet::default();
        let cooldown = Duration::seconds(30);

        // With no row, the first claim wins (kid miss on never-seen URI).
        assert!(repo
            .try_claim_forced_refresh(&uri, clock.now(), cooldown)
            .await
            .unwrap());

        // Populate the row.
        let now = clock.now();
        repo.upsert(
            &uri,
            JwksCacheUpsert {
                jwks: &jwks,
                fetched_at: now,
                fresh_until: now + Duration::minutes(15),
                stale_until: None,
                etag: None,
                last_modified: None,
            },
        )
        .await
        .unwrap();

        // First claim wins; the row has no prior forced_refresh_at.
        assert!(repo
            .try_claim_forced_refresh(&uri, clock.now(), cooldown)
            .await
            .unwrap());

        // Second claim immediately after loses — still within the cooldown.
        clock.advance(Duration::seconds(5));
        assert!(!repo
            .try_claim_forced_refresh(&uri, clock.now(), cooldown)
            .await
            .unwrap());

        // After the cooldown elapses, claims succeed again.
        clock.advance(Duration::seconds(26));
        assert!(repo
            .try_claim_forced_refresh(&uri, clock.now(), cooldown)
            .await
            .unwrap());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_touch_and_cleanup(pool: PgPool) {
        let clock = MockClock::default();
        let mut conn = pool.acquire().await.unwrap();
        let mut repo = PgJwksCacheRepository::new(&mut conn);
        let uri_a: Url = "https://example.com/jwks-a".parse().unwrap();
        let uri_b: Url = "https://example.com/jwks-b".parse().unwrap();
        let jwks = PublicJsonWebKeySet::default();

        // Insert uri_a far in the past; insert uri_b later.
        let t0 = clock.now();
        repo.upsert(
            &uri_a,
            JwksCacheUpsert {
                jwks: &jwks,
                fetched_at: t0,
                fresh_until: t0 + Duration::minutes(15),
                stale_until: None,
                etag: None,
                last_modified: None,
            },
        )
        .await
        .unwrap();

        clock.advance(Duration::days(31));
        let t1 = clock.now();
        repo.upsert(
            &uri_b,
            JwksCacheUpsert {
                jwks: &jwks,
                fetched_at: t1,
                fresh_until: t1 + Duration::minutes(15),
                stale_until: None,
                etag: None,
                last_modified: None,
            },
        )
        .await
        .unwrap();

        // touch() with `last_used_at < threshold` bumps the row.
        clock.advance(Duration::seconds(1));
        let t2 = clock.now();
        repo.touch(&uri_a, t2, t2).await.unwrap();
        let entry = repo.get(&uri_a).await.unwrap().unwrap();
        assert_eq!(entry.last_used_at, t2);

        // touch() with threshold-in-past leaves the row alone.
        clock.advance(Duration::seconds(1));
        let t3 = clock.now();
        repo.touch(&uri_a, t3, t0).await.unwrap();
        let entry = repo.get(&uri_a).await.unwrap().unwrap();
        assert_eq!(
            entry.last_used_at, t2,
            "row must not be touched if last_used_at >= threshold",
        );

        // Cleanup: delete entries last used strictly before t2.
        //   uri_a.last_used_at = t2  → kept
        //   uri_b.last_used_at = t1  → dropped (t1 < t2)
        let removed = repo.delete_unused_since(t2).await.unwrap();
        assert_eq!(removed, 1);
        assert!(repo.get(&uri_a).await.unwrap().is_some());
        assert!(repo.get(&uri_b).await.unwrap().is_none());
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_delete_and_list(pool: PgPool) {
        let clock = MockClock::default();
        let mut conn = pool.acquire().await.unwrap();
        let mut repo = PgJwksCacheRepository::new(&mut conn);
        let uri_a: Url = "https://a.example.com/jwks".parse().unwrap();
        let uri_b: Url = "https://b.example.com/jwks".parse().unwrap();
        let jwks = PublicJsonWebKeySet::default();
        let now = clock.now();

        for uri in [&uri_a, &uri_b] {
            repo.upsert(
                uri,
                JwksCacheUpsert {
                    jwks: &jwks,
                    fetched_at: now,
                    fresh_until: now + Duration::minutes(15),
                    stale_until: None,
                    etag: None,
                    last_modified: None,
                },
            )
            .await
            .unwrap();
        }

        let entries = repo.list().await.unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].jwks_uri, uri_a);
        assert_eq!(entries[1].jwks_uri, uri_b);

        assert!(repo.delete(&uri_a).await.unwrap());
        assert!(!repo.delete(&uri_a).await.unwrap(), "second delete is a no-op");

        let entries = repo.list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].jwks_uri, uri_b);
    }
}
