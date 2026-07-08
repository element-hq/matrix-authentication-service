-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Change the FK constraint on last_scheduled_job_id to SET NULL on delete
-- This allows us to clean up old completed/failed queue jobs without violating
-- the FK constraint from queue_schedules (fixes #5545)
ALTER TABLE queue_schedules
  DROP CONSTRAINT queue_schedules_last_scheduled_job_id_fkey,
  ADD CONSTRAINT queue_schedules_last_scheduled_job_id_fkey
    FOREIGN KEY (last_scheduled_job_id)
    REFERENCES queue_jobs (queue_job_id)
    ON DELETE SET NULL;
