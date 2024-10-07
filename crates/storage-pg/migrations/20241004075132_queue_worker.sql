-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- This table stores informations about worker, mostly to track their health
CREATE TABLE queue_workers (
  queue_worker_id UUID NOT NULL PRIMARY KEY,

  -- When the worker was registered
  registered_at TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the worker was last seen
  last_seen_at TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the worker was shut down
  shutdown_at TIMESTAMP WITH TIME ZONE
);

-- This single-row table stores the leader of the queue
-- The leader is responsible for running maintenance tasks
CREATE UNLOGGED TABLE queue_leader (
  -- This makes the row unique
  active BOOLEAN NOT NULL DEFAULT TRUE UNIQUE,

  -- When the leader was elected
  elected_at TIMESTAMP WITH TIME ZONE NOT NULL,

  -- Until when the lease is valid
  expires_at TIMESTAMP WITH TIME ZONE NOT NULL,

  -- The worker ID of the leader
  queue_worker_id UUID NOT NULL REFERENCES queue_workers (queue_worker_id),

  -- This, combined with the unique constraint, makes sure we only ever have a single row
  CONSTRAINT queue_leader_active CHECK (active IS TRUE)
);
