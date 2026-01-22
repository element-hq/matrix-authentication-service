-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Validate the constraint added in the previous migration.
-- This scans the table but does not hold an exclusive lock.
ALTER TABLE compat_sessions
    VALIDATE CONSTRAINT compat_sessions_user_session_id_fkey;
