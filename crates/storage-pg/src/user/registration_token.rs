// Copyright 2025 New Vector Ltd.
//
// SPDX-License-Identifier: AGPL-3.0-only
// Please see LICENSE in the repository root for full details.

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use mas_data_model::UserRegistrationToken;
use mas_storage::{
    Clock, Page, Pagination,
    user::{UserRegistrationTokenFilter, UserRegistrationTokenRepository},
};
use rand::RngCore;
use sea_query::{Condition, Expr, PostgresQueryBuilder, Query, enum_def};
use sea_query_binder::SqlxBinder;
use sqlx::PgConnection;
use ulid::Ulid;
use uuid::Uuid;

use crate::{
    DatabaseInconsistencyError,
    errors::DatabaseError,
    filter::{Filter, StatementExt},
    iden::UserRegistrationTokens,
    pagination::QueryBuilderExt,
    tracing::ExecuteExt,
};

/// An implementation of [`mas_storage::user::UserRegistrationTokenRepository`]
/// for a PostgreSQL connection
pub struct PgUserRegistrationTokenRepository<'c> {
    conn: &'c mut PgConnection,
}

impl<'c> PgUserRegistrationTokenRepository<'c> {
    /// Create a new [`PgUserRegistrationTokenRepository`] from an active
    /// PostgreSQL connection
    pub fn new(conn: &'c mut PgConnection) -> Self {
        Self { conn }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
#[enum_def]
struct UserRegistrationTokenLookup {
    user_registration_token_id: Uuid,
    token: String,
    usage_limit: Option<i32>,
    times_used: i32,
    created_at: DateTime<Utc>,
    last_used_at: Option<DateTime<Utc>>,
    expires_at: Option<DateTime<Utc>>,
    revoked_at: Option<DateTime<Utc>>,
}

impl Filter for UserRegistrationTokenFilter {
    #[expect(clippy::too_many_lines)]
    fn generate_condition(&self, _has_joins: bool) -> impl sea_query::IntoCondition {
        sea_query::Condition::all()
            .add_option(self.has_been_used().map(|has_been_used| {
                if has_been_used {
                    Expr::col((
                        UserRegistrationTokens::Table,
                        UserRegistrationTokens::TimesUsed,
                    ))
                    .gt(0)
                } else {
                    Expr::col((
                        UserRegistrationTokens::Table,
                        UserRegistrationTokens::TimesUsed,
                    ))
                    .eq(0)
                }
            }))
            .add_option(self.is_revoked().map(|is_revoked| {
                if is_revoked {
                    Expr::col((
                        UserRegistrationTokens::Table,
                        UserRegistrationTokens::RevokedAt,
                    ))
                    .is_not_null()
                } else {
                    Expr::col((
                        UserRegistrationTokens::Table,
                        UserRegistrationTokens::RevokedAt,
                    ))
                    .is_null()
                }
            }))
            .add_option(self.is_expired().map(|is_expired| {
                if is_expired {
                    Condition::all()
                        .add(
                            Expr::col((
                                UserRegistrationTokens::Table,
                                UserRegistrationTokens::ExpiresAt,
                            ))
                            .is_not_null(),
                        )
                        .add(
                            Expr::col((
                                UserRegistrationTokens::Table,
                                UserRegistrationTokens::ExpiresAt,
                            ))
                            .lt(Expr::val(self.now())),
                        )
                } else {
                    Condition::any()
                        .add(
                            Expr::col((
                                UserRegistrationTokens::Table,
                                UserRegistrationTokens::ExpiresAt,
                            ))
                            .is_null(),
                        )
                        .add(
                            Expr::col((
                                UserRegistrationTokens::Table,
                                UserRegistrationTokens::ExpiresAt,
                            ))
                            .gte(Expr::val(self.now())),
                        )
                }
            }))
            .add_option(self.is_valid().map(|is_valid| {
                let valid = Condition::all()
                    // Has not reached its usage limit
                    .add(
                        Condition::any()
                            .add(
                                Expr::col((
                                    UserRegistrationTokens::Table,
                                    UserRegistrationTokens::UsageLimit,
                                ))
                                .is_null(),
                            )
                            .add(
                                Expr::col((
                                    UserRegistrationTokens::Table,
                                    UserRegistrationTokens::TimesUsed,
                                ))
                                .lt(Expr::col((
                                    UserRegistrationTokens::Table,
                                    UserRegistrationTokens::UsageLimit,
                                ))),
                            ),
                    )
                    // Has not been revoked
                    .add(
                        Expr::col((
                            UserRegistrationTokens::Table,
                            UserRegistrationTokens::RevokedAt,
                        ))
                        .is_null(),
                    )
                    // Has not expired
                    .add(
                        Condition::any()
                            .add(
                                Expr::col((
                                    UserRegistrationTokens::Table,
                                    UserRegistrationTokens::ExpiresAt,
                                ))
                                .is_null(),
                            )
                            .add(
                                Expr::col((
                                    UserRegistrationTokens::Table,
                                    UserRegistrationTokens::ExpiresAt,
                                ))
                                .gte(Expr::val(self.now())),
                            ),
                    );

                if is_valid { valid } else { valid.not() }
            }))
    }
}

impl TryFrom<UserRegistrationTokenLookup> for UserRegistrationToken {
    type Error = DatabaseInconsistencyError;

    fn try_from(res: UserRegistrationTokenLookup) -> Result<Self, Self::Error> {
        let id = Ulid::from(res.user_registration_token_id);

        let usage_limit = res
            .usage_limit
            .map(u32::try_from)
            .transpose()
            .map_err(|e| {
                DatabaseInconsistencyError::on("user_registration_tokens")
                    .column("usage_limit")
                    .row(id)
                    .source(e)
            })?;

        let times_used = res.times_used.try_into().map_err(|e| {
            DatabaseInconsistencyError::on("user_registration_tokens")
                .column("times_used")
                .row(id)
                .source(e)
        })?;

        Ok(UserRegistrationToken {
            id,
            token: res.token,
            usage_limit,
            times_used,
            created_at: res.created_at,
            last_used_at: res.last_used_at,
            expires_at: res.expires_at,
            revoked_at: res.revoked_at,
        })
    }
}

#[async_trait]
impl UserRegistrationTokenRepository for PgUserRegistrationTokenRepository<'_> {
    type Error = DatabaseError;

    #[tracing::instrument(
        name = "db.user_registration_token.list",
        skip_all,
        fields(
            db.query.text,
        ),
        err,
    )]
    async fn list(
        &mut self,
        filter: UserRegistrationTokenFilter,
        pagination: Pagination,
    ) -> Result<Page<UserRegistrationToken>, Self::Error> {
        let (sql, values) = Query::select()
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::UserRegistrationTokenId,
                )),
                UserRegistrationTokenLookupIden::UserRegistrationTokenId,
            )
            .expr_as(
                Expr::col((UserRegistrationTokens::Table, UserRegistrationTokens::Token)),
                UserRegistrationTokenLookupIden::Token,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::UsageLimit,
                )),
                UserRegistrationTokenLookupIden::UsageLimit,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::TimesUsed,
                )),
                UserRegistrationTokenLookupIden::TimesUsed,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::CreatedAt,
                )),
                UserRegistrationTokenLookupIden::CreatedAt,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::LastUsedAt,
                )),
                UserRegistrationTokenLookupIden::LastUsedAt,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::ExpiresAt,
                )),
                UserRegistrationTokenLookupIden::ExpiresAt,
            )
            .expr_as(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::RevokedAt,
                )),
                UserRegistrationTokenLookupIden::RevokedAt,
            )
            .from(UserRegistrationTokens::Table)
            .apply_filter(filter)
            .generate_pagination(
                (
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::UserRegistrationTokenId,
                ),
                pagination,
            )
            .build_sqlx(PostgresQueryBuilder);

        let tokens = sqlx::query_as_with::<_, UserRegistrationTokenLookup, _>(&sql, values)
            .traced()
            .fetch_all(&mut *self.conn)
            .await?
            .into_iter()
            .map(TryInto::try_into)
            .collect::<Result<Vec<_>, _>>()?;

        let page = pagination.process(tokens);

        Ok(page)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.count",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.filter = ?filter,
        ),
        err,
    )]
    async fn count(&mut self, filter: UserRegistrationTokenFilter) -> Result<usize, Self::Error> {
        let (sql, values) = Query::select()
            .expr(
                Expr::col((
                    UserRegistrationTokens::Table,
                    UserRegistrationTokens::UserRegistrationTokenId,
                ))
                .count(),
            )
            .from(UserRegistrationTokens::Table)
            .apply_filter(filter)
            .build_sqlx(PostgresQueryBuilder);

        let count: i64 = sqlx::query_scalar_with(&sql, values)
            .traced()
            .fetch_one(&mut *self.conn)
            .await?;

        count
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.lookup",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %id,
        ),
        err,
    )]
    async fn lookup(&mut self, id: Ulid) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = sqlx::query_as!(
            UserRegistrationTokenLookup,
            r#"
                SELECT user_registration_token_id,
                       token,
                       usage_limit,
                       times_used,
                       created_at,
                       last_used_at,
                       expires_at,
                       revoked_at
                FROM user_registration_tokens
                WHERE user_registration_token_id = $1
            "#,
            Uuid::from(id)
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.find_by_token",
        skip_all,
        fields(
            db.query.text,
            token = %token,
        ),
        err,
    )]
    async fn find_by_token(
        &mut self,
        token: &str,
    ) -> Result<Option<UserRegistrationToken>, Self::Error> {
        let res = sqlx::query_as!(
            UserRegistrationTokenLookup,
            r#"
                SELECT user_registration_token_id,
                       token,
                       usage_limit,
                       times_used,
                       created_at,
                       last_used_at,
                       expires_at,
                       revoked_at
                FROM user_registration_tokens
                WHERE token = $1
            "#,
            token
        )
        .traced()
        .fetch_optional(&mut *self.conn)
        .await?;

        let Some(res) = res else {
            return Ok(None);
        };

        Ok(Some(res.try_into()?))
    }

    #[tracing::instrument(
        name = "db.user_registration_token.add",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.token = %token,
        ),
        err,
    )]
    async fn add(
        &mut self,
        rng: &mut (dyn RngCore + Send),
        clock: &dyn mas_storage::Clock,
        token: String,
        usage_limit: Option<u32>,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let created_at = clock.now();
        let id = Ulid::from_datetime_with_source(created_at.into(), rng);

        let usage_limit_i32 = usage_limit
            .map(i32::try_from)
            .transpose()
            .map_err(DatabaseError::to_invalid_operation)?;

        sqlx::query!(
            r#"
                INSERT INTO user_registration_tokens
                    (user_registration_token_id, token, usage_limit, created_at, expires_at)
                VALUES ($1, $2, $3, $4, $5)
            "#,
            Uuid::from(id),
            &token,
            usage_limit_i32,
            created_at,
            expires_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        Ok(UserRegistrationToken {
            id,
            token,
            usage_limit,
            times_used: 0,
            created_at,
            last_used_at: None,
            expires_at,
            revoked_at: None,
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.use_token",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn use_token(
        &mut self,
        clock: &dyn Clock,
        token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let now = clock.now();
        let new_times_used = sqlx::query_scalar!(
            r#"
                UPDATE user_registration_tokens
                SET times_used = times_used + 1,
                    last_used_at = $2
                WHERE user_registration_token_id = $1 AND revoked_at IS NULL
                RETURNING times_used
            "#,
            Uuid::from(token.id),
            now,
        )
        .traced()
        .fetch_one(&mut *self.conn)
        .await?;

        let new_times_used = new_times_used
            .try_into()
            .map_err(DatabaseError::to_invalid_operation)?;

        Ok(UserRegistrationToken {
            times_used: new_times_used,
            last_used_at: Some(now),
            ..token
        })
    }

    #[tracing::instrument(
        name = "db.user_registration_token.revoke",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn revoke(
        &mut self,
        clock: &dyn Clock,
        mut token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let revoked_at = clock.now();
        let res = sqlx::query!(
            r#"
                UPDATE user_registration_tokens
                SET revoked_at = $2
                WHERE user_registration_token_id = $1
            "#,
            Uuid::from(token.id),
            revoked_at,
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        token.revoked_at = Some(revoked_at);

        Ok(token)
    }

    #[tracing::instrument(
        name = "db.user_registration_token.unrevoke",
        skip_all,
        fields(
            db.query.text,
            user_registration_token.id = %token.id,
        ),
        err,
    )]
    async fn unrevoke(
        &mut self,
        mut token: UserRegistrationToken,
    ) -> Result<UserRegistrationToken, Self::Error> {
        let res = sqlx::query!(
            r#"
                UPDATE user_registration_tokens
                SET revoked_at = NULL
                WHERE user_registration_token_id = $1
            "#,
            Uuid::from(token.id),
        )
        .traced()
        .execute(&mut *self.conn)
        .await?;

        DatabaseError::ensure_affected_rows(&res, 1)?;

        token.revoked_at = None;

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use chrono::Duration;
    use mas_storage::{
        Clock as _, Pagination, clock::MockClock, user::UserRegistrationTokenFilter,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaChaRng;
    use sqlx::PgPool;

    use crate::PgRepository;

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_unrevoke(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create a token
        let token = repo
            .user_registration_token()
            .add(&mut rng, &clock, "test_token".to_owned(), None, None)
            .await
            .unwrap();

        // Revoke the token
        let revoked_token = repo
            .user_registration_token()
            .revoke(&clock, token)
            .await
            .unwrap();

        // Verify it's revoked
        assert!(revoked_token.revoked_at.is_some());

        // Unrevoke the token
        let unrevoked_token = repo
            .user_registration_token()
            .unrevoke(revoked_token)
            .await
            .unwrap();

        // Verify it's no longer revoked
        assert!(unrevoked_token.revoked_at.is_none());

        // Check that we can find it with the non-revoked filter
        let non_revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(false);
        let page = repo
            .user_registration_token()
            .list(non_revoked_filter, Pagination::first(10))
            .await
            .unwrap();

        assert!(page.edges.iter().any(|t| t.id == unrevoked_token.id));
    }

    #[sqlx::test(migrator = "crate::MIGRATOR")]
    async fn test_list_and_count(pool: PgPool) {
        let mut rng = ChaChaRng::seed_from_u64(42);
        let clock = MockClock::default();

        let mut repo = PgRepository::from_pool(&pool).await.unwrap().boxed();

        // Create different types of tokens
        // 1. A regular token
        let _token1 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token1".to_owned(), None, None)
            .await
            .unwrap();

        // 2. A token that has been used
        let token2 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token2".to_owned(), None, None)
            .await
            .unwrap();
        let token2 = repo
            .user_registration_token()
            .use_token(&clock, token2)
            .await
            .unwrap();

        // 3. A token that is expired
        let past_time = clock.now() - Duration::days(1);
        let token3 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token3".to_owned(), None, Some(past_time))
            .await
            .unwrap();

        // 4. A token that is revoked
        let token4 = repo
            .user_registration_token()
            .add(&mut rng, &clock, "token4".to_owned(), None, None)
            .await
            .unwrap();
        let token4 = repo
            .user_registration_token()
            .revoke(&clock, token4)
            .await
            .unwrap();

        // Test list with empty filter
        let empty_filter = UserRegistrationTokenFilter::new(clock.now());
        let page = repo
            .user_registration_token()
            .list(empty_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 4);

        // Test count with empty filter
        let count = repo
            .user_registration_token()
            .count(empty_filter)
            .await
            .unwrap();
        assert_eq!(count, 4);

        // Test has_been_used filter
        let used_filter = UserRegistrationTokenFilter::new(clock.now()).with_been_used(true);
        let page = repo
            .user_registration_token()
            .list(used_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].id, token2.id);

        // Test unused filter
        let unused_filter = UserRegistrationTokenFilter::new(clock.now()).with_been_used(false);
        let page = repo
            .user_registration_token()
            .list(unused_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_expired filter
        let expired_filter = UserRegistrationTokenFilter::new(clock.now()).with_expired(true);
        let page = repo
            .user_registration_token()
            .list(expired_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].id, token3.id);

        let not_expired_filter = UserRegistrationTokenFilter::new(clock.now()).with_expired(false);
        let page = repo
            .user_registration_token()
            .list(not_expired_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_revoked filter
        let revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(true);
        let page = repo
            .user_registration_token()
            .list(revoked_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].id, token4.id);

        let not_revoked_filter = UserRegistrationTokenFilter::new(clock.now()).with_revoked(false);
        let page = repo
            .user_registration_token()
            .list(not_revoked_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 3);

        // Test is_valid filter
        let valid_filter = UserRegistrationTokenFilter::new(clock.now()).with_valid(true);
        let page = repo
            .user_registration_token()
            .list(valid_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);

        let invalid_filter = UserRegistrationTokenFilter::new(clock.now()).with_valid(false);
        let page = repo
            .user_registration_token()
            .list(invalid_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);

        // Test combined filters
        let combined_filter = UserRegistrationTokenFilter::new(clock.now())
            .with_been_used(false)
            .with_revoked(true);
        let page = repo
            .user_registration_token()
            .list(combined_filter, Pagination::first(10))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 1);
        assert_eq!(page.edges[0].id, token4.id);

        // Test pagination
        let page = repo
            .user_registration_token()
            .list(empty_filter, Pagination::first(2))
            .await
            .unwrap();
        assert_eq!(page.edges.len(), 2);
    }
}
