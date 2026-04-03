-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Add a flag to allow static clients to skip the consent screen
ALTER TABLE oauth2_clients
    ADD COLUMN skip_consent
        BOOLEAN NOT NULL
        DEFAULT FALSE;
