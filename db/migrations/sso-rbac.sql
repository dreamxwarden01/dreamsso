-- RBAC Phase A: per-role + per-user permission storage. `org_roles` and
-- `user_org_roles` already exist (schema.sql); this adds the permission tables and
-- the one-role-per-user guard. Seed data (roles, role_permissions, assignments) is
-- applied by scripts/seed-rbac.ts from the code catalog (src/rbac/catalog.ts).

-- One org role per user: the matrix is tier-based (level IS the tier), so a user
-- holds exactly one org role. (Relax later if additive roles are ever needed.)
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_user_org_role') THEN
    ALTER TABLE user_org_roles ADD CONSTRAINT uq_user_org_role UNIQUE (user_sub);
  END IF;
END $$;

-- Per-role permission defaults (seeded from the matrix; admin-editable later).
CREATE TABLE IF NOT EXISTS role_permissions (
    role_slug text NOT NULL REFERENCES org_roles(slug) ON DELETE CASCADE,
    perm_key  text NOT NULL,                          -- validated against the code catalog
    effect    text NOT NULL CHECK (effect IN ('grant','deny')),
    PRIMARY KEY (role_slug, perm_key)
);

-- Per-user overrides (grant/deny; ABSENCE of a row = inherit from the role).
CREATE TABLE IF NOT EXISTS user_permission_overrides (
    user_sub uuid NOT NULL REFERENCES identities(sub) ON DELETE CASCADE,
    perm_key text NOT NULL,
    effect   text NOT NULL CHECK (effect IN ('grant','deny')),
    PRIMARY KEY (user_sub, perm_key)
);
