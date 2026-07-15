import { pool } from '../db.js';

// Effective app role resolution — the three-layer chain the Org UI edits:
//   user override ?? org-role default ?? catalog default
// Each stored layer is three-state: no row = fall through; row with a role =
// that role; row with NULL = No access. role_id null in the RESULT = No access.
//
// Root guarantee (bootstrap chicken-and-egg, user design): NOT a resolution
// rule — every roles.sync re-points level-0 org roles' app DEFAULT at the
// catalog's top role (see applyRolesSync), so superadmin privilege arrives
// through this ordinary chain and the UI shows the truth.
export interface EffectiveAppRole {
  role_id: number | null;
  source: 'override' | 'org' | 'catalog' | 'none';
}

export async function effectiveAppRole(sub: string, clientId: string): Promise<EffectiveAppRole> {
  const { rows: [ov] } = await pool.query<{ app_role_id: number | null }>(
    'SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2',
    [sub, clientId],
  );
  if (ov) return { role_id: ov.app_role_id, source: 'override' };
  const { rows: [od] } = await pool.query<{ app_role_id: number | null }>(
    `SELECT d.app_role_id FROM org_role_app_defaults d
       JOIN user_org_roles ur ON ur.org_role_slug = d.role_slug
      WHERE ur.user_sub = $1 AND d.client_id = $2`,
    [sub, clientId],
  );
  if (od) return { role_id: od.app_role_id, source: 'org' };
  const { rows: [cat] } = await pool.query<{ default_role_id: number | null }>(
    'SELECT default_role_id FROM app_role_catalogs WHERE client_id = $1',
    [clientId],
  );
  if (cat) return { role_id: cat.default_role_id, source: 'catalog' };
  return { role_id: null, source: 'none' };
}

// Privilege level of an app-role VALUE for guard comparisons. Smaller = more
// privileged; No access (null) and vanished roles rank below everything.
export async function appRoleLevel(clientId: string, roleId: number | null): Promise<number> {
  if (roleId == null) return Number.POSITIVE_INFINITY;
  const { rows: [r] } = await pool.query<{ level: number }>(
    'SELECT level FROM app_roles WHERE client_id = $1 AND role_id = $2',
    [clientId, roleId],
  );
  return r ? r.level : Number.POSITIVE_INFINITY;
}

export async function hasAppCatalog(clientId: string): Promise<boolean> {
  const { rows: [cat] } = await pool.query(
    'SELECT client_id FROM app_role_catalogs WHERE client_id = $1',
    [clientId],
  );
  return !!cat;
}

// Sign-in safeguard (SSO side): enforced ONLY for clients with a synced role
// catalog — catalog-less clients (the account portal itself) have no role
// model and always pass. Refuses when the effective role is No access OR
// references a role no longer in the catalog (removed but not yet reconciled).
export async function appAccessAllowed(clientId: string, sub: string): Promise<boolean> {
  if (!(await hasAppCatalog(clientId))) return true;
  const eff = await effectiveAppRole(sub, clientId);
  if (eff.role_id == null) return false;
  const { rows: [r] } = await pool.query(
    'SELECT 1 FROM app_roles WHERE client_id = $1 AND role_id = $2',
    [clientId, eff.role_id],
  );
  return !!r;
}
