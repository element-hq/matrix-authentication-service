-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Replace the foreign key constraint on the next refresh token to set the field
-- to NULL on delete. We re-introduce the constraint as NOT VALID to avoid
-- locking the table, and a second migration validates the constraint
ALTER TABLE oauth2_refresh_tokens
  DROP CONSTRAINT IF EXISTS oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey,
  ADD CONSTRAINT oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey
    FOREIGN KEY (next_oauth2_refresh_token_id)
    REFERENCES oauth2_refresh_tokens (oauth2_refresh_token_id)
    ON DELETE SET NULL
    NOT VALID;
