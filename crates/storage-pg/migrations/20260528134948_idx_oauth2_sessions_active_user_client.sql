-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Partial composite index to efficiently answer "does user X have an active
-- OAuth2 session for any of clients [Y, Z, ...]?", which is used by the
-- `UserFilter::with_active_oauth2_session_for_any_of_clients` filter (admin
-- API: `filter[active-oauth2-client]=<ulid>`).
-- The existing FK indexes can answer this query, but on installations with a
-- lot of churn this partial index avoids visiting finished sessions at all.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "oauth2_sessions_active_user_client_idx"
    ON "oauth2_sessions" ("user_id", "oauth2_client_id")
    WHERE "finished_at" IS NULL;
