-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This adds an index on the revoked_at field on oauth2_refresh_tokens to speed up cleaning them up
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_refresh_tokens_revoked_at_idx
  ON oauth2_refresh_tokens (revoked_at) WHERE revoked_at IS NOT NULL;
