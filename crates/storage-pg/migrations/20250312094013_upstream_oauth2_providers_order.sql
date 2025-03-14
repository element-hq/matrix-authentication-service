-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Adds a column to track the 'UI order' of the upstream OAuth2 providers, so
-- that they can be consistently displayed in the UI
ALTER TABLE upstream_oauth_providers
  ADD COLUMN ui_order INTEGER NOT NULL DEFAULT 0;
