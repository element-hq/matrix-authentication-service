-- Copyright 2025 New Vector Ltd.
--
-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-Element-Commercial
-- Please see LICENSE in the repository root for full details.

-- We may be running an older version of the app that doesn't fill in the
-- id_token_claims column when the id_token column is populated. So we add a
-- trigger to fill in the id_token_claims column if it's NULL.
--
-- We will be able to remove this trigger in a future version of the app.
--
-- We backfill in a second migration after this one to make sure we don't miss
-- any rows, and don't lock the table for too long.
CREATE OR REPLACE FUNCTION fill_id_token_claims()
RETURNS TRIGGER AS $$
BEGIN
    -- Only process if id_token_claims is NULL but id_token is not NULL
    IF NEW.id_token_claims IS NULL AND NEW.id_token IS NOT NULL AND NEW.id_token != '' THEN
        BEGIN
            -- Decode JWT payload inline
            NEW.id_token_claims := (
                CASE
                    WHEN split_part(NEW.id_token, '.', 2) = '' THEN NULL
                    ELSE
                        (convert_from(
                            decode(
                                replace(replace(split_part(NEW.id_token, '.', 2), '-', '+'), '_', '/') ||
                                repeat('=', (4 - length(split_part(NEW.id_token, '.', 2)) % 4) % 4),
                                'base64'
                            ),
                            'UTF8'
                        ))::JSONB
                END
            );
        EXCEPTION
            WHEN OTHERS THEN
                -- If JWT decoding fails, leave id_token_claims as NULL
                NEW.id_token_claims := NULL;
        END;
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Create the trigger
CREATE TRIGGER trg_fill_id_token_claims
    BEFORE INSERT OR UPDATE ON upstream_oauth_authorization_sessions
    FOR EACH ROW
    WHEN (NEW.id_token_claims IS NULL AND NEW.id_token IS NOT NULL AND NEW.id_token <> '')
    EXECUTE FUNCTION fill_id_token_claims();
