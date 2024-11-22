-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a new status for scheduled jobs
ALTER TYPE "queue_job_status" ADD VALUE 'scheduled';

ALTER TABLE "queue_jobs"
  -- When the job is scheduled to run
  ADD COLUMN "scheduled_at" TIMESTAMP WITH TIME ZONE;
