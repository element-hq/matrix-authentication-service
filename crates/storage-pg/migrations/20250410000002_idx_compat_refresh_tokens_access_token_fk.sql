-- no-transaction
-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE INDEX CONCURRENTLY
  compat_refresh_tokens_access_token_fk
  ON compat_refresh_tokens (compat_access_token_id);
