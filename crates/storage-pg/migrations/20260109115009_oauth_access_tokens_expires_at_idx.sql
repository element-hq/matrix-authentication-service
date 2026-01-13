-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- This adds an index on the expires_at field on oauth2_access_tokens to speed up cleaning them up
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth_access_tokens_expires_at_idx
  ON oauth2_access_tokens (expires_at) WHERE expires_at IS NOT NULL;
