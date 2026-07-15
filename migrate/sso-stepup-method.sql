-- Tiered step-up: record the METHOD of the last verification alongside stepup_at,
-- so each protected scenario can demand a tier (org/settings accept strong factors
-- only; the factor-management pages fall back to email/password). Method values:
-- passkey | totp | email | password (strength order passkey > totp > email > password).
-- Backfill is intentionally left NULL — an unknown method reads as "below any bar",
-- so every live session must re-verify once, which is the safe default.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS stepup_method text;
