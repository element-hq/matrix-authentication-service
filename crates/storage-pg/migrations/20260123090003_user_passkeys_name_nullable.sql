-- Copyright 2026 Element Creations Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- Make the passkey name column nullable
-- The frontend will determine the display name based on AAGUID or transports
ALTER TABLE "user_passkeys"
    ALTER COLUMN "name" DROP NOT NULL;
