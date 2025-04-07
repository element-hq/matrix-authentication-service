-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.


-- Compat SSO Logins in the 'fulfilled' state will now be attached to
-- browser sessions, not compat sessions.
-- Only those in the 'exchanged' state will now have a compat session.
--
-- Rationale: We can't create the compat session without the client
-- being given an opportunity to specify the device_id, which does not happen
-- until the exchange phase.

-- Empty the table because we don't want to need to think about backwards
-- compatibility for fulfilled logins that don't have an attached
-- browser session ID.
TRUNCATE compat_sso_logins;

ALTER TABLE compat_sso_logins
    -- browser sessions and user sessions are the same thing
    ADD COLUMN user_session_id UUID
        REFERENCES user_sessions(user_session_id) ON DELETE CASCADE;
