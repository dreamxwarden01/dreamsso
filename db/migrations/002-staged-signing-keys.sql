-- Keys are published before a separately armed activation window begins.
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS rotation_id uuid;
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS published_at timestamptz;
ALTER TABLE signing_keys ADD COLUMN IF NOT EXISTS activate_after timestamptz;

-- Existing ambiguous state must be investigated, never silently repaired.
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_current
  ON signing_keys ((1)) WHERE status = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_one_next
  ON signing_keys ((1)) WHERE status = 'next';
CREATE UNIQUE INDEX IF NOT EXISTS signing_keys_rotation_id
  ON signing_keys (rotation_id) WHERE rotation_id IS NOT NULL;

DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='signing_keys'::regclass AND conname='signing_keys_publication_window') THEN
    ALTER TABLE signing_keys ADD CONSTRAINT signing_keys_publication_window CHECK (
      (published_at IS NULL AND activate_after IS NULL)
      OR (published_at IS NOT NULL AND activate_after IS NOT NULL
          AND activate_after >= published_at + interval '300 seconds')
    );
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='signing_keys'::regclass AND conname='signing_keys_pending_identity') THEN
    ALTER TABLE signing_keys ADD CONSTRAINT signing_keys_pending_identity CHECK (
      status <> 'next' OR (rotation_id IS NOT NULL AND activated_at IS NULL AND retired_at IS NULL)
    );
  END IF;
END $$;
