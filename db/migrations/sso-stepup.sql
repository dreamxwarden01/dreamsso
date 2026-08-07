-- Step-up sudo window: solving a step-up challenge stamps the MASTER session;
-- protected surfaces compare the stamp's age to the stepup_validity_minutes
-- setting. Pre-clearance: a login whose amr carried a strong factor (otp/passkey)
-- stamps at session creation, so login-MFA isn't followed by a door challenge.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS stepup_at timestamptz;
