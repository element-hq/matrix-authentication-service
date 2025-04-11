-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  oauth2_device_code_grants_client_fk
  ON oauth2_device_code_grant (oauth2_client_id);
