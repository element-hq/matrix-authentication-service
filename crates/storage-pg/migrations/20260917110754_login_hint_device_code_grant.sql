-- Add login_hint to oauth2_device_code_grant
ALTER TABLE "oauth2_device_code_grant"
  ADD COLUMN "login_hint" TEXT;