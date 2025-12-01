-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  user_email_authentication_codes_authentication_fk
  ON user_email_authentication_codes (user_email_authentication_id);
