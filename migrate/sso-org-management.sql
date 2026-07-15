-- Org management slice 1: audit log, system-role flag, singular default org
-- role (settings key — same normalization as app catalogs: no per-row boolean).

BEGIN;

ALTER TABLE org_roles ADD COLUMN IF NOT EXISTS is_system boolean NOT NULL DEFAULT false;
UPDATE org_roles SET is_system = true WHERE slug IN ('superadmin', 'admin', 'standard_user');

-- Who did what to whom. Labels are SNAPSHOTS (display name at the time) so the
-- log stays readable after renames/deletions; no FKs — log rows outlive users.
-- Timestamps are UTC; today/yesterday/... grouping is client-side, local tz.
-- "Clear" is soft: cleared rows are hidden by default but never deleted, and
-- cleared_by/cleared_at keep the clearing itself accountable.
CREATE TABLE IF NOT EXISTS org_audit_log (
    id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    actor_sub    uuid NOT NULL,
    actor_label  text NOT NULL,
    target_sub   uuid,
    target_label text,
    action       text NOT NULL,           -- user.role_change | user.password_set | logs.clear | ...
    detail       jsonb NOT NULL DEFAULT '{}',
    created_at   timestamptz NOT NULL DEFAULT now(),
    cleared_at   timestamptz,
    cleared_by   uuid
);
CREATE INDEX IF NOT EXISTS idx_org_audit_page ON org_audit_log (created_at DESC, id DESC);

INSERT INTO settings (key, value) VALUES ('default_org_role', 'standard_user')
ON CONFLICT (key) DO NOTHING;

COMMIT;
