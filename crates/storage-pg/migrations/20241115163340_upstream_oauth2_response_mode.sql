-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add the response_mode column to the upstream_oauth_providers table
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "response_mode" text NOT NULL DEFAULT 'query';
