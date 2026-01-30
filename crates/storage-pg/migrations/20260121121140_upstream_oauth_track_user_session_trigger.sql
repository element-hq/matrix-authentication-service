-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Adds a trigger which will backfill the user_session_id column when inserting
-- a new user_session_authentications row. This is to help supporting rolling
-- back to previous releases and should be dropped in a future version.
CREATE OR REPLACE FUNCTION upstream_oauth_authorization_sessions_insert_trigger()
RETURNS TRIGGER AS $$
BEGIN
    IF NEW.upstream_oauth_authorization_session_id IS NOT NULL THEN
        UPDATE upstream_oauth_authorization_sessions
        SET user_session_id = NEW.user_session_id
        WHERE upstream_oauth_authorization_sessions.upstream_oauth_authorization_session_id
               = NEW.upstream_oauth_authorization_session_id
          AND upstream_oauth_authorization_sessions.user_session_id IS NULL;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger
CREATE TRIGGER upstream_oauth_authorization_sessions_insert_trigger
  AFTER INSERT ON user_session_authentications
  FOR EACH ROW
  EXECUTE FUNCTION upstream_oauth_authorization_sessions_insert_trigger();
