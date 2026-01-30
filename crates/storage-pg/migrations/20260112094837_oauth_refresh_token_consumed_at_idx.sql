-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Adds a partial index on oauth2_refresh_tokens on the consumed_at field,
-- including other interesting fields to speed up cleaning up of consumed tokens
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_token_consumed_at_idx
  ON oauth2_refresh_tokens (consumed_at, next_oauth2_refresh_token_id, oauth2_refresh_token_id)
  WHERE consumed_at IS NOT NULL;
