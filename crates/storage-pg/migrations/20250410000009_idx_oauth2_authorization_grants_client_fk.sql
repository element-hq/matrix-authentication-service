-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  oauth2_authorization_grants_client_fk
  ON oauth2_authorization_grants (oauth2_client_id);
