-- Admin panel: client lifecycle. Disabled clients are rejected at /authorize and
-- /token; permanent delete is only allowed FROM the disabled state (admin API).
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
