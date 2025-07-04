-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We'll be requesting authorization sessions by provider, sub and sid, so we'll
-- need to index those columns
CREATE INDEX CONCURRENTLY IF NOT EXISTS
    upstream_oauth_authorization_sessions_sub_sid_idx
    ON upstream_oauth_authorization_sessions (
      upstream_oauth_provider_id,
      (id_token_claims->>'sub'),
      (id_token_claims->>'sid')
    );
