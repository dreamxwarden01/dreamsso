SET LOCAL lock_timeout='5s';
-- Per-account verification state; targets are deliberately NOT globally reserved.
ALTER TABLE identities ADD COLUMN IF NOT EXISTS email_change_revision bigint NOT NULL DEFAULT 0;
CREATE TABLE IF NOT EXISTS email_change_operations (
  user_sub uuid PRIMARY KEY REFERENCES identities(sub) ON DELETE CASCADE,
  request_id uuid NOT NULL,
  revision bigint NOT NULL,
  kind text NOT NULL CHECK(kind IN ('change','confirm')),
  new_email citext NOT NULL,
  token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
  token_enc bytea,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at timestamptz NOT NULL,
  last_sent_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  CHECK(expires_at>created_at),
  CHECK((completed_at IS NULL AND token_enc IS NOT NULL) OR (completed_at IS NOT NULL AND token_enc IS NULL))
);
-- Fence every writer, including an admin change followed by restoring the old
-- address, and password recovery. No old token is imported from Redis.
CREATE OR REPLACE FUNCTION invalidate_email_change_operation() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.email IS DISTINCT FROM OLD.email
     OR NEW.email_verified IS DISTINCT FROM OLD.email_verified
     OR NEW.status IS DISTINCT FROM OLD.status
     OR NEW.deleted_at IS DISTINCT FROM OLD.deleted_at
     OR NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
    NEW.email_change_revision := OLD.email_change_revision + 1;
    DELETE FROM email_change_operations WHERE user_sub=OLD.sub;
  END IF;
  RETURN NEW;
END $$;
DO $email_operation_trigger$
BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identities'::regclass AND tgname='trg_identity_email_operation') THEN
    EXECUTE 'CREATE TRIGGER trg_identity_email_operation BEFORE UPDATE OF email,email_verified,status,deleted_at,password_hash ON identities FOR EACH ROW EXECUTE FUNCTION invalidate_email_change_operation()';
  END IF;
END $email_operation_trigger$;
