-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Index the new `user_session_id` FK so deleting a `user_sessions` row doesn't
-- seq-scan this table (mirrors the existing `oauth2_session_id` index). Built
-- CONCURRENTLY (hence `-- no-transaction`) to avoid locking out writes.
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    "oauth2_authorization_grants_user_session_id_idx"
    ON "oauth2_authorization_grants" ("user_session_id");
