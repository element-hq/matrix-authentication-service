-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a column to the upstream_oauth_authorization_sessions table to store
-- extra query parameters
ALTER TABLE "upstream_oauth_authorization_sessions"
    ADD COLUMN "extra_callback_parameters" JSONB;
