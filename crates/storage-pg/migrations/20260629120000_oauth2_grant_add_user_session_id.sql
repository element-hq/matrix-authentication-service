-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Records the browser session that gave consent. The OAuth 2.0 session (and
-- `oauth2_session_id`) is now created at code exchange instead of at consent,
-- mirroring `oauth2_device_code_grant`.
--
-- Adding a nullable column with no default is metadata-only: no table rewrite,
-- no meaningful lock. It is also rollback-safe — the N-1 binary ignores the
-- column. No backfill on purpose: the only grants that differ between versions
-- are fulfilled-but-unexchanged ones (<10 min lived), and backfilling them
-- would make the new binary create a second session at exchange. Such in-flight
-- grants straddling the deploy are simply rejected and the client retries.
ALTER TABLE oauth2_authorization_grants
    ADD COLUMN user_session_id UUID
        REFERENCES user_sessions (user_session_id);
