-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only
-- Please see LICENSE in the repository root for full details.



-- Tracks third-party ID associations that have been verified but are
-- not currently supported by MAS.
-- This is currently used when importing third-party IDs from Synapse,
-- which historically could verify at least phone numbers.
-- E-mail associations will not be stored in this table because those are natively
-- supported by MAS; see the `user_emails` table.

CREATE TABLE user_unsupported_third_party_ids(
    -- The owner of the third-party ID assocation
    user_id UUID NOT NULL
      REFERENCES users(user_id) ON DELETE CASCADE,

    -- What type of association is this?
    medium TEXT NOT NULL,

    -- The address of the associated ID, e.g. a phone number or other identifier.
    address TEXT NOT NULL,

    -- When the association was created
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,

    PRIMARY KEY (user_id, medium, address)
);
