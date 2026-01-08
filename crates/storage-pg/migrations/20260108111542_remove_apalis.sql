-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We replaced apalis a while back but did not clean the database. This removes
-- everything related to apalis
DROP TRIGGER IF EXISTS notify_workers ON apalis.jobs;
DROP FUNCTION IF EXISTS apalis.notify_new_jobs();
DROP FUNCTION IF EXISTS apalis.get_jobs(text, text, integer);
DROP FUNCTION IF EXISTS apalis.push_job(text, json, text, timestamp with time zone, integer);
DROP TABLE IF EXISTS apalis.jobs;
DROP TABLE IF EXISTS apalis.workers;
DROP SCHEMA IF EXISTS apalis;
