-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Change the FK constraint on next_attempt_id to SET NULL on delete
-- This allows us to clean up old completed/failed jobs without breaking retry chains
ALTER TABLE queue_jobs
  DROP CONSTRAINT queue_jobs_next_attempt_id_fkey,
  ADD CONSTRAINT queue_jobs_next_attempt_id_fkey
    FOREIGN KEY (next_attempt_id)
    REFERENCES queue_jobs (queue_job_id)
    ON DELETE SET NULL
    NOT VALID;
