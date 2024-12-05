-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a table to track the state of scheduled recurring jobs.
CREATE TABLE queue_schedules (
    -- A unique name for the schedule
    schedule_name TEXT NOT NULL PRIMARY KEY,

    -- The last time the job was scheduled. If NULL, it means that the job was
    -- never scheduled.
    last_scheduled_at TIMESTAMP WITH TIME ZONE,

    -- The job that was scheduled last time. If NULL, it means that either the
    -- job was never scheduled, or the job cleaned up from the database
    last_scheduled_job_id UUID
        REFERENCES queue_jobs (queue_job_id)
);

-- When a job is scheduled from a recurring schedule, we keep a column
-- referencing the name of the schedule
ALTER TABLE queue_jobs
    ADD COLUMN schedule_name TEXT
        REFERENCES queue_schedules (schedule_name);
