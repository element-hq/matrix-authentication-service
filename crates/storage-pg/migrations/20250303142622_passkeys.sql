-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

CREATE TABLE "user_passkeys" (
  "user_passkey_id" UUID NOT NULL
    CONSTRAINT "user_passkey_id_pkey"
    PRIMARY KEY,

  "user_id" UUID NOT NULL
    CONSTRAINT "user_passkeys_user_id_fkey"
    REFERENCES "users" ("user_id")
    ON DELETE CASCADE,

  "credential_id" TEXT NOT NULL
    CONSTRAINT "user_passkeys_credential_id_unique"
    UNIQUE,

  "name" TEXT NOT NULL,

  "transports" JSONB NOT NULL,

  "static_state" BYTEA NOT NULL,

  "dynamic_state" BYTEA NOT NULL,

  "metadata" BYTEA NOT NULL,

  "last_used_at" TIMESTAMP WITH TIME ZONE,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL
);

CREATE INDEX
  user_passkeys_user_id_fk
  ON user_passkeys (user_id);

CREATE TABLE "user_passkey_challenges" (
  "user_passkey_challenge_id" UUID NOT NULL
    CONSTRAINT "user_passkey_challenge_id_pkey"
    PRIMARY KEY,

  "user_session_id" UUID
    REFERENCES "user_sessions" ("user_session_id")
    ON DELETE SET NULL,

  "state" BYTEA NOT NULL,

  "created_at" TIMESTAMP WITH TIME ZONE NOT NULL,

  "completed_at" TIMESTAMP WITH TIME ZONE
);

CREATE INDEX
  user_passkey_challenges_user_session_id_fk
  ON user_passkey_challenges (user_session_id);

ALTER TABLE "user_session_authentications"
    ADD COLUMN "user_passkey_id" UUID
        REFERENCES "user_passkeys" ("user_passkey_id")
        ON DELETE SET NULL;

