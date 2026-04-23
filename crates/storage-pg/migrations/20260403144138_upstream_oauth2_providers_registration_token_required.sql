-- Adds a `registration_token_required` column to the UpstreamOauthProvider table

ALTER TABLE upstream_oauth_providers
  ADD COLUMN registration_token_required BOOLEAN NOT NULL DEFAULT FALSE;