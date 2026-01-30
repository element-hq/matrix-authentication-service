-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Adds a partial index on oauth2_refresh_tokens that are consumed
-- to speed up cleaning up of consumed tokens
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_token_not_consumed_idx
  ON oauth2_refresh_tokens (oauth2_refresh_token_id)
  WHERE consumed_at IS NOT NULL;
