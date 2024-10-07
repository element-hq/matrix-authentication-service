-- Add login_hint to oauth2_authorization_grants
ALTER TABLE "oauth2_authorization_grants"
  ADD COLUMN "login_hint" TEXT;
