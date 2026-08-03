-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- This adds an index on the human_account_name field for ILIKE '%search%'
-- operations, enabling fuzzy searches of upstream OAuth link account names
CREATE INDEX CONCURRENTLY IF NOT EXISTS upstream_oauth_links_human_account_name_trgm_idx
  ON upstream_oauth_links USING gin(human_account_name gin_trgm_ops);
