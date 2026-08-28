-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

CREATE TABLE upstream_oauth_link_tokens (
    upstream_oauth_link_token_id UUID PRIMARY KEY,
    upstream_oauth_link_id       UUID NOT NULL
        REFERENCES upstream_oauth_links(upstream_oauth_link_id) ON DELETE CASCADE,
    encrypted_access_token       TEXT NOT NULL,
    encrypted_refresh_token      TEXT,
    access_token_expires_at      TIMESTAMPTZ,
    token_scope                  TEXT,
    created_at                   TIMESTAMPTZ NOT NULL,
    updated_at                   TIMESTAMPTZ NOT NULL
);

CREATE UNIQUE INDEX idx_upstream_oauth_link_tokens_link_id
  ON upstream_oauth_link_tokens(upstream_oauth_link_id);
