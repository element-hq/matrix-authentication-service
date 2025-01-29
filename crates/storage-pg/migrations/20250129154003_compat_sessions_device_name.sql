-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

ALTER TABLE compat_sessions
  -- Stores a human-readable name for the device.
  -- syn2mas behaviour: Will be populated from the device name in Synapse.
  ADD COLUMN human_name TEXT;
