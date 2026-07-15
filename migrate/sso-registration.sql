-- Registration: invitation codes (user design, 2026-07-08)
-- Lifecycle: live -> CONSUMED (row kept forever: used_by uuid, username via
-- join at read) | VOIDED (row deleted) | EXPIRED-unused (deleted by sweeper).
-- use_count counts EMAIL SWITCHES at /register/start (first use included;
-- same-email resends are free) — a 4th switch voids the code.
-- invited_role_slug: org role picked at creation (strictly below creator);
-- NULL (or role deleted -> FK sets NULL) falls back to default_org_role.
CREATE TABLE IF NOT EXISTS invitation_codes (
    code             text PRIMARY KEY CHECK (code ~ '^[A-Z0-9]{12}$'),
    created_by       uuid REFERENCES identities(sub) ON DELETE SET NULL,
    created_by_label text NOT NULL,          -- snapshot, survives creator deletion
    invited_role_slug text REFERENCES org_roles(slug) ON DELETE SET NULL,
    created_at       timestamptz NOT NULL DEFAULT now(),
    expires_at       timestamptz NOT NULL,
    use_count        integer NOT NULL DEFAULT 0,
    pending_email    citext,                 -- the one in-flight registration
    pending_at       timestamptz,            -- stamp for the stale-pending sweep
    used_by          uuid REFERENCES identities(sub) ON DELETE SET NULL,
    used_at          timestamptz
);
CREATE INDEX IF NOT EXISTS idx_invitation_codes_expiry ON invitation_codes (expires_at) WHERE used_by IS NULL;
