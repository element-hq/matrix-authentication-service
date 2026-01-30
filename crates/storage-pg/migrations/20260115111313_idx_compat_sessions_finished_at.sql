-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Index to efficiently query finished compat sessions for cleanup
-- Only includes non-null finished_at values since we filter on finished_at IS NOT NULL
CREATE INDEX CONCURRENTLY IF NOT EXISTS "compat_sessions_finished_at_idx"
    ON "compat_sessions" ("finished_at")
    WHERE "finished_at" IS NOT NULL;
