-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- Validate the foreign key constraint on the next refresh token introduced in
-- the previous migration
ALTER TABLE oauth2_refresh_tokens
  VALIDATE CONSTRAINT oauth2_refresh_tokens_next_oauth2_refresh_token_id_fkey;
