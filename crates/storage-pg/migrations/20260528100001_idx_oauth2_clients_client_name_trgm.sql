-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- This adds an index on the client_name field for ILIKE '%search%' operations,
-- enabling fuzzy searches of OAuth 2.0 client names
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth2_clients_client_name_trgm_idx
  ON oauth2_clients USING gin(client_name gin_trgm_ops);
