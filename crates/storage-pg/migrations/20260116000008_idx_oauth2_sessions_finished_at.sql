-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Add partial index for cleanup of finished OAuth2 sessions
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_oauth2_sessions_finished_at
    ON oauth2_sessions (finished_at)
    WHERE finished_at IS NOT NULL;
