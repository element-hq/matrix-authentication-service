-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Start tracking the associated `user_session` directly on the authorization session
-- This will be backfilled in a separate migration rolling in the next version
ALTER TABLE upstream_oauth_authorization_sessions
    ADD COLUMN user_session_id UUID
    REFERENCES user_sessions (user_session_id)
    ON DELETE SET NULL;
