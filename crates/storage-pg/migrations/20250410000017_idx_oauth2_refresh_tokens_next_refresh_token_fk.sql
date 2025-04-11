-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  oauth2_refresh_tokens_next_refresh_token_fk
  ON oauth2_refresh_tokens (next_oauth2_refresh_token_id);
