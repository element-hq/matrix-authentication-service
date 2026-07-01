-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- An in-progress login flow that needs state persisted across its steps,
-- analogous to user_registrations for the registration flow. Created today
-- only for account-management deeplinks carrying an id_token_hint/login_hint.
CREATE TABLE "login_sessions" (
  "login_session_id" UUID PRIMARY KEY,

  -- The IP address of the user agent, if any
  "ip_address" INET,

  -- The user agent string of the user agent, if any
  "user_agent" TEXT,

  -- The post auth action to execute once the login flow completes, if any
  "post_auth_action" JSONB,

  -- The untrusted client-supplied login_hint, if any
  "login_hint" TEXT,

  -- The user resolved from a verified id_token_hint, if any
  "target_user_id" UUID
    REFERENCES "users" ("user_id"),

  -- The user session resolved from the sid claim of a verified
  -- id_token_hint, if any
  "target_user_session_id" UUID
    REFERENCES "user_sessions" ("user_session_id")
    ON DELETE SET NULL,

  -- When the object was created
  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  -- When the login flow was completed
  "completed_at" TIMESTAMP WITH TIME ZONE,

  -- The user session which completed the login flow
  "user_session_id" UUID
    REFERENCES "user_sessions" ("user_session_id")
    ON DELETE SET NULL
);

-- Support the ON DELETE SET NULL clauses when user_sessions rows are reaped
CREATE INDEX "login_sessions_target_user_session_fk"
  ON "login_sessions" ("target_user_session_id");
CREATE INDEX "login_sessions_user_session_fk"
  ON "login_sessions" ("user_session_id");
