-- no-transaction
-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Speeds up the "does this client have an active session" EXISTS probe used by
-- the OAuth2ClientFilter active-sessions filter, including the negative branch
-- which has to confirm a client has no active session.
CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_sessions_active_client_idx
  ON oauth2_sessions (oauth2_client_id)
  WHERE finished_at IS NULL;
