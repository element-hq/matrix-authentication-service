-- Copyright 2024 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE files in the repository root for full details.

-- This script should revert what `syn2mas_temporary_tables.sql` does.

DROP TABLE syn2mas_restore_constraints;
DROP TABLE syn2mas_restore_indices;

ALTER TABLE syn2mas__users RENAME TO users;
ALTER TABLE syn2mas__user_passwords RENAME TO user_passwords;
ALTER TABLE syn2mas__user_emails RENAME TO user_emails;
ALTER TABLE syn2mas__user_unsupported_third_party_ids RENAME TO user_unsupported_third_party_ids;
ALTER TABLE syn2mas__upstream_oauth_links RENAME TO upstream_oauth_links;
ALTER TABLE syn2mas__compat_sessions RENAME TO compat_sessions;
ALTER TABLE syn2mas__compat_access_tokens RENAME TO compat_access_tokens;
ALTER TABLE syn2mas__compat_refresh_tokens RENAME TO compat_refresh_tokens;
