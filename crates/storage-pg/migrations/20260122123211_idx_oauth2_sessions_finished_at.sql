-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Adds a partial index on oauth2_sessions.finished_at to help cleaning up
-- finished sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS "oauth2_sessions_finished_at_idx"
    ON "oauth2_sessions" ("finished_at")
    WHERE "finished_at" IS NOT NULL;
