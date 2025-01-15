-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.

-- This drops all the unverified email addresses from the database, as they are
-- now always verified when they land in the user_emails table.
-- We don't drop the `confirmed_at` column to allow rolling back

-- First, truncate all the confirmation codes
TRUNCATE TABLE user_email_confirmation_codes;

-- Then, delete all the unverified email addresses
DELETE FROM user_emails WHERE confirmed_at IS NULL;
