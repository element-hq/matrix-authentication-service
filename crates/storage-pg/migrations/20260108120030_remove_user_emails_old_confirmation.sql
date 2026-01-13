-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We reworked how email verification works in
-- https://github.com/element-hq/matrix-authentication-service/pull/3784
-- but kept some old schema around to allow rolling back. We're safe to drop
-- those now

-- Users don't have a 'primary email' anymore
ALTER TABLE users DROP COLUMN primary_user_email_id;

-- Replaced by user_email_authentications
DROP TABLE user_email_confirmation_codes;

-- User emails are always confirmed when they are in this table now
ALTER TABLE user_emails DROP COLUMN confirmed_at;
