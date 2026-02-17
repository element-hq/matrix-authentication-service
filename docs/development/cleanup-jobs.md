# Cleanup Jobs

In MAS, most of the data are initially only soft-deleted, by setting a `deleted_at`, `finished_at`, `consumed_at` timestamp on the row, instead of actually deleting the row.
They are kept around for a short period of time, for audit purposes or to help with the user experience in some case.
This document describes the cleanup jobs in MAS which delete those stale rows after some time, including how to add new cleanup jobs and understand the existing ones.

## Cleanup Job Architecture

Cleanup jobs are scheduled tasks that hard-delete old data from the database. They follow a consistent pattern:

1. **Job struct** in `crates/storage/src/queue/tasks.rs` - Defines the job and queue name
2. **Storage trait** in `crates/storage/src/{domain}/` - Declares the cleanup method interface
3. **PostgreSQL implementation** in `crates/storage-pg/src/{domain}/` - Implements the actual cleanup logic
4. **Job runner** in `crates/tasks/src/cleanup/` - Implements the `RunnableJob` trait with batching logic
5. **Registration** in `crates/tasks/src/lib.rs` - Registers the handler and schedules execution

### Module Structure

The cleanup job implementations are organized into submodules by domain:

```
crates/tasks/src/cleanup/
├── mod.rs           # Re-exports, shared BATCH_SIZE constant
├── tokens.rs        # OAuth token cleanup (access and refresh tokens)
├── sessions.rs      # Session cleanup (compat, OAuth2, user sessions and their IPs)
├── oauth.rs         # OAuth grants and upstream OAuth cleanup
├── user.rs          # User-related cleanup (registrations, recovery, email auth)
└── misc.rs          # Queue jobs, policy data cleanup
```

## All Cleanup Jobs

| Job | Entity | Retention | Notes |
|-----|--------|-----------|-------|
| `CleanupRevokedOAuthAccessTokensJob` | `oauth2_access_tokens` | 1 hour after `revoked_at` | |
| `CleanupExpiredOAuthAccessTokensJob` | `oauth2_access_tokens` | 30 days after `expires_at` | For idempotency |
| `CleanupRevokedOAuthRefreshTokensJob` | `oauth2_refresh_tokens` | 1 hour after `revoked_at` | |
| `CleanupConsumedOAuthRefreshTokensJob` | `oauth2_refresh_tokens` | 1 hour after `consumed_at` | |
| `CleanupUserRegistrationsJob` | `user_registrations` | 30 days | For abuse investigation |
| `CleanupFinishedCompatSessionsJob` | `compat_sessions` | 30 days after `finished_at` | Cascades to tokens |
| `CleanupFinishedOAuth2SessionsJob` | `oauth2_sessions` | 30 days after `finished_at` | Cascades to tokens |
| `CleanupFinishedUserSessionsJob` | `user_sessions` | 30 days after `finished_at` | Only if no child sessions |
| `CleanupOAuthAuthorizationGrantsJob` | `oauth2_authorization_grants` | 7 days | |
| `CleanupOAuthDeviceCodeGrantsJob` | `oauth2_device_code_grant` | 7 days | |
| `CleanupUserRecoverySessionsJob` | `user_recovery_sessions` | 7 days | Codes expire in 10 min |
| `CleanupUserEmailAuthenticationsJob` | `user_email_authentications` | 7 days | Codes expire in 10 min |
| `CleanupUpstreamOAuthSessionsJob` | `upstream_oauth_authorization_sessions` | 7 days (orphaned) | Where `user_session_id IS NULL` |
| `CleanupUpstreamOAuthLinksJob` | `upstream_oauth_links` | 7 days (orphaned) | Where `user_id IS NULL` |
| `CleanupInactiveOAuth2SessionIpsJob` | `oauth2_sessions.last_active_ip` | 30 days | Clears out IPs after inactivity |
| `CleanupInactiveCompatSessionIpsJob` | `compat_sessions.last_active_ip` | 30 days | Clears out IPs after inactivity |
| `CleanupInactiveUserSessionIpsJob` | `user_sessions.last_active_ip` | 30 days | Clears out IPs after inactivity |
| `CleanupQueueJobsJob` | `queue_jobs` | 30 days | Completed/failed jobs |

## Session Cleanup and Backchannel Logout

The session cleanup jobs must preserve the dependency chain required for backchannel logout to work correctly.

### Backchannel Logout Flow

When an upstream IdP sends a backchannel logout notification, MAS must trace through the session hierarchy to find and finish all related sessions:

```
          Upstream IdP logout notification
                   │
                   ▼
    ┌───────────────────────────────────────┐
    │ upstream_oauth_authorization_sessions │
    │ (matched by sub/sid claims)           │
    └──────────────┬────────────────────────┘
                   │ user_session_id
                   ▼
    ┌─────────────────────────────────────┐
    │         user_sessions               │
    │       (browser sessions)            │
    └──────────────┬──────────────────────┘
                   │ user_session_id FK
              ┌────┴──────────────┐
              │                   │
              ▼                   ▼
    ┌─────────────────┐  ┌─────────────────┐
    │ compat_sessions │  │ oauth2_sessions │
    └─────────────────┘  └─────────────────┘
```

### Cleanup Order

The cleanup jobs run in an order that respects this hierarchy:

1. **Compat sessions** (`CleanupFinishedCompatSessionsJob`)
   - Also deletes `compat_access_tokens`, `compat_refresh_tokens`
1. **OAuth2 sessions** (`CleanupFinishedOAuth2SessionsJob`)
   - Also deletes `oauth2_access_tokens`, `oauth2_refresh_tokens`
1. **User sessions** (`CleanupFinishedUserSessionsJob`)
   - Only deletes if NO `compat_sessions` or `oauth2_sessions` reference it. 
     This can make this job inefficient if there are lots of finished `user_sessions` that are still referenced by active `compat_sessions` or `oauth2_sessions`.
   - Also deletes `user_session_authentications`
   - Cascades to `SET NULL` the `user_session_id` on `upstream_oauth_authorization_sessions`
1. **Upstream OAuth authorization sessions** (`CleanupUpstreamOAuthSessionsJob`)
   - Only deletes if `user_session_id` is `NULL`, so if the authentication session was never finished *or* the user session was cleaned up.

### Why User Sessions Require Special Handling

The `user_session_id` foreign key links must be preserved for backchannel logout to work:

1. **Backchannel logout** traces: `upstream_oauth_authorization_sessions` → `user_sessions` → `compat_sessions`/`oauth2_sessions`
2. If `user_sessions` is deleted while child sessions exist, the link is broken and logout propagation fails
3. The `NOT EXISTS` checks in the cleanup query ensure we only delete `user_sessions` after all children are cleaned up
4. FK constraints (`ON DELETE NO ACTION`) provide a safety net - attempting to delete a referenced `user_session` will fail

## Adding a New Cleanup Job

### 1. Add Job Struct

In `crates/storage/src/queue/tasks.rs`:

```rust
/// Cleanup old foo records
#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CleanupFooJob;

impl InsertableJob for CleanupFooJob {
    const QUEUE_NAME: &'static str = "cleanup-foo";
}
```

### 2. Add Storage Trait Method

In `crates/storage/src/{domain}/foo.rs`, add to the repository trait and `repository_impl!` macro:

```rust
async fn cleanup(
    &mut self,
    since: Option<DateTime<Utc>>,
    until: DateTime<Utc>,
    limit: usize,
) -> Result<(usize, Option<DateTime<Utc>>), Self::Error>;
```

### 3. Implement in PostgreSQL

In `crates/storage-pg/src/{domain}/foo.rs`, use the CTE pattern:

```rust
async fn cleanup(
    &mut self,
    since: Option<DateTime<Utc>>,
    until: DateTime<Utc>,
    limit: usize,
) -> Result<(usize, Option<DateTime<Utc>>), Self::Error> {
    let res = sqlx::query!(
        r#"
            WITH
                to_delete AS (
                    SELECT id, timestamp_col
                    FROM table
                    WHERE timestamp_col IS NOT NULL
                      AND ($1::timestamptz IS NULL OR timestamp_col >= $1)
                      AND timestamp_col < $2
                    ORDER BY timestamp_col ASC
                    LIMIT $3
                    FOR UPDATE
                ),
                deleted AS (
                    DELETE FROM table USING to_delete
                    WHERE table.id = to_delete.id
                    RETURNING timestamp_col
                )
            SELECT COUNT(*) as "count!", MAX(timestamp_col) as last_timestamp FROM deleted
        "#,
        since,
        until,
        limit as i64,
    )
    .traced()
    .fetch_one(&mut *self.conn)
    .await?;

    Ok((
        res.count.try_into().unwrap_or(usize::MAX),
        res.last_timestamp,
    ))
}
```

### 4. Add Index Migration

Make sure to add an index on that timestamp column used by this cleanup job:

```sql
-- no-transaction
CREATE INDEX CONCURRENTLY IF NOT EXISTS "table_timestamp_idx"
    ON "table" ("timestamp_col")
    WHERE "timestamp_col" IS NOT NULL;
```

The partial index (`WHERE timestamp_col IS NOT NULL`) makes queries more efficient by only indexing rows that will actually be cleaned up.

### 5. Implement RunnableJob

In the appropriate submodule under `crates/tasks/src/cleanup/` (e.g., `tokens.rs`, `sessions.rs`, `oauth.rs`, `user.rs`, or `misc.rs`):

```rust
#[async_trait]
impl RunnableJob for CleanupFooJob {
    #[tracing::instrument(name = "job.cleanup_foo", skip_all)]
    async fn run(&self, state: &State, context: JobContext) -> Result<(), JobError> {
        // Cleanup records older than X days
        let until = state.clock.now() - chrono::Duration::days(30);
        let mut total = 0;

        let mut since = None;
        while !context.cancellation_token.is_cancelled() {
            let mut repo = state.repository().await.map_err(JobError::retry)?;

            let (count, last_timestamp) = repo
                .foo()
                .cleanup(since, until, BATCH_SIZE)
                .await
                .map_err(JobError::retry)?;
            repo.save().await.map_err(JobError::retry)?;

            since = last_timestamp;
            total += count;

            if count != BATCH_SIZE {
                break;
            }
        }

        if total == 0 {
            debug!("no foo records to clean up");
        } else {
            info!(count = total, "cleaned up foo records");
        }

        Ok(())
    }

    fn timeout(&self) -> Option<Duration> {
        Some(Duration::from_secs(10 * 60))
    }
}
```

### 6. Register and Schedule

In `crates/tasks/src/lib.rs`:

```rust
// Add to register_handler chain
.register_handler::<mas_storage::queue::CleanupFooJob>()

// Add schedule
.add_schedule(
    "cleanup-foo",
    // Run this job every hour
    "0 XX * * * *".parse()?,  // Choose a minute offset
    mas_storage::queue::CleanupFooJob,
)
```

## Implementation Notes

### Batching Pattern

All cleanup jobs use a batching pattern to avoid long-running transactions:

- Process records in batches (typically 1000 at a time)
- Use pagination cursor (`since`) to track progress
- Create a new transaction for each batch
- Check for cancellation between batches
- Log total count at the end

### Retention Policies

Retention periods vary by use case:

- **1 hour**: Revoked/consumed tokens (no longer useful)
- **7 days**: Short-lived grants/codes (abuse investigation)
- **30 days**: Sessions and registrations (longer audit trail)
