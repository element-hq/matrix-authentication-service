-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Partial index for cleaning up IP addresses from inactive compat sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS "compat_sessions_inactive_ips_idx"
    ON "compat_sessions" ("last_active_at")
    WHERE "last_active_ip" IS NOT NULL AND "last_active_at" IS NOT NULL;
