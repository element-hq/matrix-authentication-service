-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- A family of personal access tokens. This is a long-lived wrapper around the personal access tokens
-- themselves, allowing tokens to be regenerated whilst still retaining a persistent identifier for them.
CREATE TABLE personal_sessions (
    personal_session_id UUID NOT NULL PRIMARY KEY,

    -- If this session is owned by a user, the ID of the user.
    -- Null otherwise.
    owner_user_id UUID REFERENCES users(user_id),

    -- If this session is owned by an OAuth 2 Client (via Client Credentials grant),
    -- the ID of the owning client.
    -- Null otherwise.
    owner_oauth2_client_id UUID REFERENCES oauth2_clients(oauth2_client_id),

    actor_user_id UUID NOT NULL REFERENCES users(user_id),
    -- A human-readable label, intended to describe what the session is for.
    human_name TEXT NOT NULL,
    -- The OAuth2 scopes for the session, identical to OAuth2 sessions.
    -- May include a device ID, but this is optional (sessions can be deviceless).
    scope_list TEXT[] NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- If set, none of the tokens will be valid anymore.
    revoked_at TIMESTAMP WITH TIME ZONE,
    last_active_at TIMESTAMP WITH TIME ZONE,
    last_active_ip INET,

    -- There must be exactly one owner.
    CONSTRAINT personal_sessions_exactly_one_owner CHECK ((owner_user_id IS NULL) <> (owner_oauth2_client_id IS NULL))
);

-- Individual tokens.
CREATE TABLE personal_access_tokens (
    personal_access_token_id UUID NOT NULL PRIMARY KEY,
    -- The session this access token belongs to.
    personal_session_id UUID NOT NULL REFERENCES personal_sessions(personal_session_id),
    -- SHA256 of the access token.
    -- This is a lightweight measure to stop a database backup (or other
    -- unauthorised read-only database access) escalating into real permissions
    -- on a live system.
    -- We could have used a hash with secret key, but this would no longer be
    -- 'free' protection because it would need configuration (and introduce
    -- potential issues with configuring it wrong).
    -- This is currently inconsistent with other access token tables but it would
    -- make sense to migrate those to match in the future.
    access_token_sha256 BYTEA NOT NULL UNIQUE
        -- A SHA256 hash is 32 bytes long
        CHECK (octet_length(access_token_sha256) = 32),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- If set, the token won't be valid after this time.
    -- If not set, the token never automatically expires.
    expires_at TIMESTAMP WITH TIME ZONE,
    -- If set, this token is not valid anymore.
    revoked_at TIMESTAMP WITH TIME ZONE
);

-- Ensure we can only have one active personal access token in each family.
CREATE UNIQUE INDEX ON personal_access_tokens (personal_session_id) WHERE revoked_at IS NOT NULL;

-- Add indices to satisfy foreign key backward checks
-- (and likely filter queries)
CREATE INDEX ON personal_sessions (owner_user_id) WHERE owner_user_id IS NOT NULL;
CREATE INDEX ON personal_sessions (owner_oauth2_client_id) WHERE owner_oauth2_client_id IS NOT NULL;
CREATE INDEX ON personal_sessions (actor_user_id);
