-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY IF NOT EXISTS
  user_session_authentications_upstream_oauth_session_fk
  ON user_session_authentications (upstream_oauth_authorization_session_id);
