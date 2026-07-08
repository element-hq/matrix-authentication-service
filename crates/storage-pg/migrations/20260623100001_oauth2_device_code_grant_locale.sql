-- Copyright 2026 Element Creations Ltd.
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE files in the repository root for full details.

-- Stores the locale detected from the browser which fulfilled the device code
-- grant, so that the token endpoint can render a human-readable device name.
ALTER TABLE "oauth2_device_code_grant"
    ADD COLUMN "locale" TEXT;
