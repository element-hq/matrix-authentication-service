-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

ALTER TABLE "oauth2_authorization_grants"
  ADD COLUMN "user_session_id" UUID
    CONSTRAINT "oauth2_authorization_grants_user_session_id_fkey"
    REFERENCES "user_sessions" ("user_session_id");

UPDATE "oauth2_authorization_grants" AS g
SET "user_session_id" = s."user_session_id"
FROM "oauth2_sessions" AS s
WHERE g."oauth2_session_id" = s."oauth2_session_id"
  AND g."fulfilled_at" IS NOT NULL;

UPDATE "oauth2_authorization_grants"
SET "oauth2_session_id" = NULL
WHERE "fulfilled_at" IS NOT NULL
  AND "exchanged_at" IS NULL;
