-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a new status for failed jobs
ALTER TYPE "queue_job_status" ADD VALUE 'failed';

ALTER TABLE "queue_jobs"
  -- When the job failed
  ADD COLUMN "failed_at" TIMESTAMP WITH TIME ZONE,
  -- Error message of the failure
  ADD COLUMN "failed_reason" TEXT,
  -- How many times we've already tried to run the job
  ADD COLUMN "attempt" INTEGER NOT NULL DEFAULT 0,
  -- The next attempt, if it was retried
  ADD COLUMN "next_attempt_id" UUID REFERENCES "queue_jobs" ("queue_job_id");
