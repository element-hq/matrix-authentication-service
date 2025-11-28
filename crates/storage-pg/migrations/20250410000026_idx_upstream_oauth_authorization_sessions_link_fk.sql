-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY IF NOT EXISTS
  upstream_oauth_authorization_sessions_link_fk
  ON upstream_oauth_authorization_sessions (upstream_oauth_link_id);
