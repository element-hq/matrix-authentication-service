-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE files in the repository root for full details.


-- # syn2mas Temporary Tables
-- This file takes a MAS database and:
--
-- 1. creates temporary tables used by syn2mas for storing restore data
-- 2. renames important tables with the `syn2mas__` prefix, to prevent
--    running MAS instances from having any opportunity to see or modify
--    the partial data in the database, especially whilst it is not protected
--    by constraints.
--
-- All changes in this file must be reverted by `syn2mas_revert_temporary_tables.sql`
-- in the same directory.

-- corresponds to `ConstraintDescription`
CREATE TABLE syn2mas_restore_constraints (
    -- synthetic auto-incrementing ID so we can load these in order
    order_key SERIAL NOT NULL PRIMARY KEY,

    table_name TEXT NOT NULL,
    name TEXT NOT NULL,
    definition TEXT NOT NULL
);

-- corresponds to `IndexDescription`
CREATE TABLE syn2mas_restore_indices (
    -- synthetic auto-incrementing ID so we can load these in order
    order_key SERIAL NOT NULL PRIMARY KEY,

    table_name TEXT NOT NULL,
    name TEXT NOT NULL,
    definition TEXT NOT NULL
);

-- Now we rename all tables that we touch during the migration.
ALTER TABLE users RENAME TO syn2mas__users;
ALTER TABLE user_passwords RENAME TO syn2mas__user_passwords;
ALTER TABLE user_emails RENAME TO syn2mas__user_emails;
ALTER TABLE user_unsupported_third_party_ids RENAME TO syn2mas__user_unsupported_third_party_ids;
ALTER TABLE upstream_oauth_links RENAME TO syn2mas__upstream_oauth_links;
ALTER TABLE compat_sessions RENAME TO syn2mas__compat_sessions;
ALTER TABLE compat_access_tokens RENAME TO syn2mas__compat_access_tokens;
ALTER TABLE compat_refresh_tokens RENAME TO syn2mas__compat_refresh_tokens;
