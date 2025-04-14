-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Including the `last_active_at` column lets us effeciently filter in-memory
-- for those sessions without fetching the rows, and without including it in the
-- index btree
CREATE INDEX CONCURRENTLY
  user_sessions_user_fk
  ON user_sessions (user_id)
  INCLUDE (last_active_at);
