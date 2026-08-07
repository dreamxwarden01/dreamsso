-- Org management slices 2-4: SSO-held app-role assignments (two layers of the
-- effective-role chain: user override ?? org-role default ?? catalog default).
-- Three-state per layer: no row = inherit downward; row with a role = that
-- role; row with NULL = No access. No FK on app_role_id — the roles.sync
-- reconciliation owns consistency when catalog roles disappear.

BEGIN;

-- schema.sql's original (unwired) draft of this table had different columns
-- (org_role_slug/default_app_role/grants_entry) — replace it outright.
DROP TABLE IF EXISTS org_role_app_defaults;
CREATE TABLE org_role_app_defaults (
    role_slug   text NOT NULL REFERENCES org_roles(slug) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    app_role_id int,                                  -- NULL = No access
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (role_slug, client_id)
);

CREATE TABLE IF NOT EXISTS user_app_role_overrides (
    user_sub    uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    client_id   text NOT NULL REFERENCES oauth_clients(client_id) ON DELETE CASCADE,
    app_role_id int,                                  -- NULL = No access
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (user_sub, client_id)
);

-- System-originated audit entries (roles.sync reconciliation) have no actor.
ALTER TABLE org_audit_log ALTER COLUMN actor_sub DROP NOT NULL;

COMMIT;
