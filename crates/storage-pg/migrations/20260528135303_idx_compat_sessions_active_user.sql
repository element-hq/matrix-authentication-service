-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Partial index to efficiently answer "does user X have an active compat
-- session?", which is used by the `UserFilter::with_active_compat_session`
-- filter (admin API: `filter[has-active-compat-session]=true|false`).
-- The existing `compat_sessions_user_fk` index can answer the query, but
-- it includes finished sessions; on installations with many finished
-- sessions, this partial index avoids visiting them at all.
CREATE INDEX CONCURRENTLY IF NOT EXISTS "compat_sessions_active_user_idx"
    ON "compat_sessions" ("user_id")
    WHERE "finished_at" IS NULL;
