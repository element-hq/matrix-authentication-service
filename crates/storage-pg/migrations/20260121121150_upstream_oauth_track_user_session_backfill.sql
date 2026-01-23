-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Backfill the upstream_oauth_authorization_sessions.user_session_id column
-- based on session authentications
UPDATE upstream_oauth_authorization_sessions
SET user_session_id = user_session_authentications.user_session_id
FROM user_session_authentications
WHERE upstream_oauth_authorization_sessions.user_session_id IS NULL
  AND upstream_oauth_authorization_sessions.upstream_oauth_authorization_session_id
             = user_session_authentications.upstream_oauth_authorization_session_id;
