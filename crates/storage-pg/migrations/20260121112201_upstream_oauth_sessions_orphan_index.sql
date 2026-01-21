-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Add partial index for cleanup of orphaned upstream OAuth sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS upstream_oauth_authorization_sessions_orphaned
    ON upstream_oauth_authorization_sessions (upstream_oauth_authorization_session_id)
    WHERE user_session_id IS NULL;
