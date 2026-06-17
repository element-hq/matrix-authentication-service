-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- This adds an index on the client_uri field for ILIKE '%search%' operations,
-- enabling fuzzy searches of OAuth 2.0 client URIs
CREATE INDEX CONCURRENTLY IF NOT EXISTS oauth2_clients_client_uri_trgm_idx
  ON oauth2_clients USING gin(client_uri gin_trgm_ops);
