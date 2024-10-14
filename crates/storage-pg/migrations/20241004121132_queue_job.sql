-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE TYPE queue_job_status AS ENUM (
  -- The job is available to be picked up by a worker
  'available',

  -- The job is currently being processed by a worker
  'running',

  -- The job has been completed
  'completed',

  -- The worker running the job was lost
  'lost'
);

CREATE TABLE queue_jobs (
  queue_job_id UUID NOT NULL PRIMARY KEY,

  -- The status of the job
  status queue_job_status NOT NULL DEFAULT 'available',

  -- When the job was created
  created_at TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the job was grabbed by a worker
  started_at TIMESTAMP WITH TIME ZONE,

  -- Which worker is currently processing the job
  started_by UUID REFERENCES queue_workers (queue_worker_id),

  -- When the job was completed
  completed_at TIMESTAMP WITH TIME ZONE,

  -- The name of the queue this job belongs to
  queue_name TEXT NOT NULL,

  -- The arguments to the job
  payload JSONB NOT NULL DEFAULT '{}',

  -- Arbitrary metadata about the job, like the trace context
  metadata JSONB NOT NULL DEFAULT '{}'
);

-- When we grab jobs, we filter on the status of the job and the queue name
-- Then we order on the `queue_job_id` column, as it is a ULID, which ensures timestamp ordering
CREATE INDEX idx_queue_jobs_status_queue_job_id
  ON queue_jobs
  USING BTREE (status, queue_name, queue_job_id);

-- We would like to notify workers when a job is available to wake them up
CREATE OR REPLACE FUNCTION queue_job_notify()
  RETURNS TRIGGER
  AS $$
DECLARE
  payload json;
BEGIN
  IF NEW.status = 'available' THEN
    -- The idea with this trigger is to notify the queue worker that a new job
    -- is available on a queue. If there are many notifications with the same
    -- payload, PG will coalesce them in a single notification, which is why we
    -- keep the payload simple.
    payload = json_build_object('queue', NEW.queue_name);
    PERFORM
      pg_notify('queue_available', payload::text);
  END IF;
  RETURN NULL;
END;
$$
LANGUAGE plpgsql;

CREATE TRIGGER queue_job_notify_trigger
  AFTER INSERT OR UPDATE OF status
    ON queue_jobs
  FOR EACH ROW
  EXECUTE PROCEDURE queue_job_notify();
