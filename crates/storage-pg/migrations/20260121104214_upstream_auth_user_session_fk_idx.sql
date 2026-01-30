-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Adds an index on the user_session_id column on the
-- upstream_oauth_authorization_sessions table
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_authorization_sessions_user_session_id_idx
  ON upstream_oauth_authorization_sessions (user_session_id);
