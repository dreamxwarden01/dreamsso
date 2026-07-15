-- System clients: built-in registrations the SSO itself depends on (today just
-- 'account', the account portal / BFF). They can't be disabled or deleted from
-- the admin panel; a future installation page will auto-provision them.
ALTER TABLE oauth_clients ADD COLUMN IF NOT EXISTS is_system boolean NOT NULL DEFAULT false;

UPDATE oauth_clients SET is_system = true WHERE client_id = 'account';
