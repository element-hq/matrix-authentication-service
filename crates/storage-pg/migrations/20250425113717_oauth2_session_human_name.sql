-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a user-provided human name to OAuth 2.0 sessions
ALTER TABLE oauth2_sessions
    ADD COLUMN human_name TEXT;
