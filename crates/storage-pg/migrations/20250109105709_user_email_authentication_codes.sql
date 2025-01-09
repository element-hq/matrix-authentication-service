-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a table for storing email authentication sessions
CREATE TABLE "user_email_authentications" (
  "user_email_authentication_id" UUID PRIMARY KEY,
  "user_session_id" UUID
    REFERENCES "user_sessions" ("user_session_id")
    ON DELETE SET NULL,
  "email" TEXT NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "completed_at" TIMESTAMP WITH TIME ZONE
);

-- A single authentication session has multiple codes, in case the user ask for re-sending
CREATE TABLE "user_email_authentication_codes" (
  "user_email_authentication_code_id" UUID PRIMARY KEY,
  "user_email_authentication_id" UUID
    NOT NULL
    REFERENCES "user_email_authentications" ("user_email_authentication_id")
    ON DELETE CASCADE,
  "code" TEXT NOT NULL,
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  "expires_at" TIMESTAMP WITH TIME ZONE NOT NULL,
  CONSTRAINT "user_email_authentication_codes_auth_id_code_unique"
    UNIQUE ("user_email_authentication_id", "code")
);
