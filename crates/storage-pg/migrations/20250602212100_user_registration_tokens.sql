-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a table for storing user registration tokens
CREATE TABLE "user_registration_tokens" (
  "user_registration_token_id" UUID PRIMARY KEY,

  -- The token string that users need to provide during registration
  "token" TEXT NOT NULL UNIQUE,

  -- Optional limit on how many times this token can be used
  "usage_limit" INTEGER,

  -- How many times this token has been used
  "times_used" INTEGER NOT NULL DEFAULT 0,

  -- When the token was created
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the token was last used
  "last_used_at" TIMESTAMP WITH TIME ZONE,

  -- Optional expiration time for the token
  "expires_at" TIMESTAMP WITH TIME ZONE,

  -- When the token was revoked
  "revoked_at" TIMESTAMP WITH TIME ZONE
);

-- Create a few indices on the table, as we use those for filtering
-- They are safe to create non-concurrently, as the table is empty at this point
CREATE INDEX "user_registration_tokens_usage_limit_idx"
  ON "user_registration_tokens" ("usage_limit");
  
CREATE INDEX "user_registration_tokens_times_used_idx"
  ON "user_registration_tokens" ("times_used");

CREATE INDEX "user_registration_tokens_created_at_idx"
  ON "user_registration_tokens" ("created_at");

CREATE INDEX "user_registration_tokens_last_used_at_idx"
  ON "user_registration_tokens" ("last_used_at");

CREATE INDEX "user_registration_tokens_expires_at_idx"
  ON "user_registration_tokens" ("expires_at");

CREATE INDEX "user_registration_tokens_revoked_at_idx"
  ON "user_registration_tokens" ("revoked_at");

-- Add foreign key reference to registration tokens in user registrations
-- A second migration will add the index for this foreign key
ALTER TABLE "user_registrations"
  ADD COLUMN "user_registration_token_id" UUID
    REFERENCES "user_registration_tokens" ("user_registration_token_id")
    ON DELETE SET NULL;