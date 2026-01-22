-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Change compat_sessions.user_session_id FK from ON DELETE SET NULL to NO ACTION
-- This ensures user_sessions cannot be deleted while compat_sessions reference them,
-- which is required for backchannel logout propagation to work correctly.
--
-- Uses NOT VALID to avoid scanning the entire table while holding a lock.
-- A separate migration will validate the constraint.

ALTER TABLE compat_sessions
    DROP CONSTRAINT compat_sessions_user_session_id_fkey,
    ADD CONSTRAINT compat_sessions_user_session_id_fkey
        FOREIGN KEY (user_session_id)
        REFERENCES user_sessions (user_session_id)
        ON DELETE NO ACTION
        NOT VALID;
