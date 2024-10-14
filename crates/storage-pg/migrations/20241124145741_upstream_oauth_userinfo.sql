-- Add migration script here
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "fetch_userinfo" BOOLEAN NOT NULL DEFAULT FALSE,
  ADD COLUMN "userinfo_endpoint_override" TEXT;

ALTER TABLE "upstream_oauth_authorization_sessions"
  ADD COLUMN "userinfo" JSONB;
