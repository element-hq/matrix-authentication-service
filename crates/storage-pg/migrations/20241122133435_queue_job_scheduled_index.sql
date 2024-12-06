-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a partial index on scheduled jobs
CREATE INDEX "queue_jobs_scheduled_at_idx"
  ON "queue_jobs" ("scheduled_at")
  WHERE "status" = 'scheduled';
