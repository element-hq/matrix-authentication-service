-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Index on the new foreign key added by the previous migration
CREATE INDEX CONCURRENTLY IF NOT EXISTS user_registrations_upstream_oauth_session_id_idx
    ON user_registrations (upstream_oauth_authorization_session_id);
