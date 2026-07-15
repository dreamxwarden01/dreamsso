-- ============================================================================
-- videosite LOCAL-dev DB prep — run AFTER reloading videosite-dump.sql.gz.
-- The prod dump carries prod state; this re-applies the local-only adjustments
-- that a reload wipes out. NOT for prod. Idempotent (safe to re-run).
--
-- Apply:
--   docker compose exec -T videosite-db mariadb -uroot -proot videosite < migrate/local-db-prep.sql
-- Then apply the identity rewrite:
--   docker compose exec -T videosite-db mariadb -uroot -proot videosite < migrate/rewrite-user-id-to-sub.sql
-- Then flush the cached settings so the app picks these up:
--   docker compose exec redis redis-cli -n 1 FLUSHDB   (or restart videosite-web)
-- ============================================================================

-- 1. Local hostname — the prod dump has `stream.dreamxwarden.ca`.
UPDATE site_settings SET setting_value = 'stream-dev.dreamxwarden.ca' WHERE setting_key = 'site_hostname';

-- 2. Drop prod-key-encrypted secrets. They were encrypted with prod's
--    SETTINGS_SECRET_ENCRYPTION_KEY; the local key differs, so decryption throws.
DELETE FROM site_settings WHERE setting_value LIKE 'enc:v1:%';

-- 3. Disable all MFA step-up policies. Login-first removed local factor
--    verification, so an enabled policy demands MFA nothing can satisfy until
--    Phase-2 SSO step-up exists.
UPDATE site_settings SET setting_value = REPLACE(setting_value, '"enabled":true', '"enabled":false')
  WHERE setting_key LIKE 'mfa_policy_%';

-- 4. Shorten session TTLs to idle 1 / absolute 3 days (re-auth is cheap via the SSO).
UPDATE site_settings SET setting_value = '1' WHERE setting_key = 'session_inactivity_days';
UPDATE site_settings SET setting_value = '3' WHERE setting_key = 'session_max_days';

-- Note: SSO identity passwords live in the SSO's *Postgres* DB and are NOT touched
-- by a videosite dump reload. For login tests use the seed-dev throwaway `tester`
-- (Test1234!); don't overwrite real migrated accounts. `tester` is promoted to
-- role 0 locally (UPDATE users SET role_id=0 WHERE username='tester') for admin tests.
