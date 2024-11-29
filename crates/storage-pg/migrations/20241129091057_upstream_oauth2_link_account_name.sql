-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add the human_account_name column to the upstream_oauth_links table to store
-- a human-readable name for the upstream account
ALTER TABLE "upstream_oauth_links"
  ADD COLUMN "human_account_name" TEXT;
