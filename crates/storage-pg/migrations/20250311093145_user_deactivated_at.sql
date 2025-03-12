-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

ALTER TABLE users
  -- Track when a user was deactivated.
  ADD COLUMN deactivated_at TIMESTAMP WITH TIME ZONE;
