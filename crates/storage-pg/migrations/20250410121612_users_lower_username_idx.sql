-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Create an index on the username column, lower-cased, so that we can lookup
-- usernames in a case-insensitive manner.
CREATE INDEX CONCURRENTLY IF NOT EXISTS users_lower_username_idx
    ON users (LOWER(username));
