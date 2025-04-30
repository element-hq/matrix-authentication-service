-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Track the locale of the user which asked for the authorization grant
ALTER TABLE oauth2_authorization_grants
    ADD COLUMN locale TEXT;
