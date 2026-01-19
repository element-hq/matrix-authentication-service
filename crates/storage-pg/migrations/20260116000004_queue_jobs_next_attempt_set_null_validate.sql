-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Validate the FK constraint that was added in the previous migration
-- This is done in a separate migration to avoid holding locks for too long
ALTER TABLE queue_jobs
  VALIDATE CONSTRAINT queue_jobs_next_attempt_id_fkey;
