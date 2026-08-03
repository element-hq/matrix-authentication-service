-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

ALTER TABLE "oauth2_authorization_grants"
  ADD COLUMN "user_session_id" UUID
    CONSTRAINT "oauth2_authorization_grants_user_session_id_fkey"
    REFERENCES "user_sessions" ("user_session_id")
    ON DELETE SET NULL;