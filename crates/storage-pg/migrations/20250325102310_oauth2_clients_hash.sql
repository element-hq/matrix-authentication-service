-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Adds a column which stores a hash of the client metadata, so that we can
-- deduplicate client registrations
--
-- This hash is a SHA-256 hash of the JSON-encoded client metadata. Note that we
-- don't retroactively hash existing clients, so this will only be populated for
-- new clients.
ALTER TABLE oauth2_clients
  ADD COLUMN metadata_digest TEXT UNIQUE;
