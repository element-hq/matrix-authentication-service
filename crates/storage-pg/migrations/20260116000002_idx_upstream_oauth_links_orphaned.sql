-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Add partial index for cleanup of orphaned upstream OAuth links
CREATE INDEX CONCURRENTLY IF NOT EXISTS idx_upstream_oauth_links_orphaned
    ON upstream_oauth_links (upstream_oauth_link_id)
    WHERE user_id IS NULL;
