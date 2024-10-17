-- Add migration script here
ALTER TABLE "upstream_oauth_providers"
  ADD COLUMN "user_profile_method" TEXT NOT NULL DEFAULT 'auto',
  ADD COLUMN "userinfo_endpoint_override" TEXT;
