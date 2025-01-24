-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- This script should revert what `syn2mas_temporary_tables.sql` does.

DROP TABLE syn2mas_restore_constraints;
DROP TABLE syn2mas_restore_indices;

ALTER TABLE syn2mas__users RENAME TO users;
ALTER TABLE syn2mas__user_passwords RENAME TO user_passwords;
ALTER TABLE syn2mas__user_emails RENAME TO user_emails;
ALTER TABLE syn2mas__user_unsupported_third_party_ids RENAME TO user_unsupported_third_party_ids;
