-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Add user_session_id to track the browser session that gave consent.
-- This replaces oauth2_session_id as the field set at fulfillment time.
-- The oauth2_session_id is now set at code exchange time instead.
ALTER TABLE oauth2_authorization_grants
    ADD COLUMN user_session_id UUID
        REFERENCES user_sessions(user_session_id) ON DELETE SET NULL;

-- Backfill user_session_id from existing data (for already-fulfilled grants).
-- For grants that were fulfilled with the old code, the oauth2_session_id was
-- already set, so we can look up the browser session from the OAuth2 session.
UPDATE oauth2_authorization_grants g
SET user_session_id = s.user_session_id
FROM oauth2_sessions s
WHERE g.oauth2_session_id = s.oauth2_session_id
  AND g.fulfilled_at IS NOT NULL;
