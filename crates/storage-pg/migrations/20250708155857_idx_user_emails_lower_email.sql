-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- When we're looking up an email address, we want to be able to do a case-insensitive
-- lookup, so we index the email address lowercase and request it like that
CREATE INDEX CONCURRENTLY
  user_emails_lower_email_idx
  ON user_emails (LOWER(email));
