-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- We don't use this column anymore, but… it will still tank the performance on
-- deletions of user_emails if we don't have it
CREATE INDEX CONCURRENTLY
  users_primary_email_fk
  ON users (primary_user_email_id);
