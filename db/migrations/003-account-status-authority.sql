-- Existing rows have no historically versioned status. Keep NULL as unknown;
-- the next real reconciliation publishes a current baseline once, atomically.
ALTER TABLE app_role_effective ADD COLUMN IF NOT EXISTS account_status text;
DO $$ BEGIN
  IF NOT EXISTS(SELECT 1 FROM pg_constraint WHERE conrelid='app_role_effective'::regclass
    AND conname='app_role_effective_account_status_check') THEN
    ALTER TABLE app_role_effective ADD CONSTRAINT app_role_effective_account_status_check
      CHECK(account_status IS NULL OR account_status IN('active','disabled','locked','deleted'));
  END IF;
END $$;
