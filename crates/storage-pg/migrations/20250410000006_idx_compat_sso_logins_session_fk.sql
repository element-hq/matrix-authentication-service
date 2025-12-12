-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY IF NOT EXISTS
  compat_sso_logins_session_fk
  ON compat_sso_logins (compat_session_id);
