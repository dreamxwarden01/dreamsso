-- Admin-editable site settings (email module milestone). Secret values are sealed
-- with KEY_ENCRYPTION_KEY (secretbox) and stored as 'enc:v1:<base64>' — same
-- philosophy as videosite's encrypted site_settings; the KEK stays in .env.
CREATE TABLE IF NOT EXISTS settings (
    key        text PRIMARY KEY,
    value      text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT now()
);
