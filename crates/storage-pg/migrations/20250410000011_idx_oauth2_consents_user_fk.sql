-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY IF NOT EXISTS
  oauth2_consents_user_fk
  ON oauth2_consents (user_id);
