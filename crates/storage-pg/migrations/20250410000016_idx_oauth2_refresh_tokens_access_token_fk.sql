-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  oauth2_refresh_tokens_access_token_fk
  ON oauth2_refresh_tokens (oauth2_access_token_id);
