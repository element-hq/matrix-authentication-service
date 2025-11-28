-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This adds an index on the username field for ILIKE '%search%' operations,
-- enabling fuzzy searches of usernames
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_username_trgm_idx
  ON users USING gin(username gin_trgm_ops);
