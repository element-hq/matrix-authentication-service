-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

ALTER TABLE users
  -- Track whether users are guests.
  -- Although guest support is not present in MAS yet, syn2mas should import
  -- these users and therefore we should track their state.
  ADD COLUMN is_guest BOOLEAN NOT NULL DEFAULT FALSE;
