-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Add a table for storing user registrations
CREATE TABLE "user_registrations" (
  "user_registration_id" UUID PRIMARY KEY,

  -- The IP address of the user agent, if any
  "ip_address" INET,

  -- The user agent string of the user agent, if any
  "user_agent" TEXT,

  -- The post auth action to execute after the registration, if any
  "post_auth_action" JSONB,

  -- The username the user asked for
  "username" TEXT NOT NULL,

  -- The display name the user asked for
  "display_name" TEXT,

  -- The URL to the terms of service at the time of registration
  "terms_url" TEXT,

  -- The ID of the email authentication session
  "email_authentication_id" UUID
    REFERENCES "user_email_authentications" ("user_email_authentication_id")
    ON DELETE SET NULL,

  -- The hashed password of the user
  "hashed_password" TEXT,
  -- The scheme version used to hash the password
  "hashed_password_version" INTEGER,

  -- When the object was created
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the registration was completed
  "completed_at" TIMESTAMP WITH TIME ZONE
);

-- Allow using user email authentications for user registrations
ALTER TABLE "user_email_authentications"
  ADD COLUMN "user_registration_id" UUID
    REFERENCES "user_registrations" ("user_registration_id")
    ON DELETE CASCADE;
