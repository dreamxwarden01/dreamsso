import type { AccessState } from './accessState.js';
export interface AccessStateQuery {
  query(sql: string, parameters: unknown[]): Promise<{ rows: Record<string, unknown>[] }>;
}

// One statement has one PostgreSQL snapshot. NULL overrides must not fall through.
// Existing schema enforces one org role per user (uq_user_org_role) and unique
// per-client overrides, catalog rows and role ids, so every requested sub has one row.
export const ACCESS_STATE_SQL = `
WITH resolved AS (
  SELECT requested.sub, requested.ordinality, i.status, i.deleted_at,
    i.sub IS NOT NULL AS account_exists, cat.client_id IS NOT NULL AS catalog_synced,
    CASE WHEN ov.user_sub IS NOT NULL THEN ov.app_role_id
         WHEN od.role_slug IS NOT NULL THEN od.app_role_id
         ELSE cat.default_role_id END AS role_id,
    CASE WHEN ov.user_sub IS NOT NULL THEN 'override'
         WHEN od.role_slug IS NOT NULL THEN 'org'
         WHEN cat.client_id IS NOT NULL THEN 'catalog'
         ELSE 'none' END AS role_source
  FROM unnest($2::uuid[]) WITH ORDINALITY AS requested(sub, ordinality)
  LEFT JOIN identities i ON i.sub = requested.sub
  LEFT JOIN user_app_role_overrides ov ON ov.user_sub = requested.sub AND ov.client_id = $1
  LEFT JOIN user_org_roles ur ON ur.user_sub = requested.sub
  LEFT JOIN org_role_app_defaults od ON od.role_slug = ur.org_role_slug AND od.client_id = $1
  LEFT JOIN app_role_catalogs cat ON cat.client_id = $1
  WHERE EXISTS (SELECT 1 FROM oauth_clients client WHERE client.client_id = $1 AND client.disabled_at IS NULL)
)
SELECT resolved.*, ar.role_id IS NOT NULL AS role_exists
FROM resolved LEFT JOIN app_roles ar ON ar.client_id = $1 AND ar.role_id = resolved.role_id
ORDER BY ordinality`;

export async function readAccessStates(db: AccessStateQuery, clientId: string, subjects: readonly string[]): Promise<AccessState[]> {
  const { rows } = await db.query(ACCESS_STATE_SQL, [clientId, [...subjects]]);
  return rows.map(row => {
    const status = !row.account_exists ? 'not_found' : row.deleted_at !== null ? 'deleted' : row.status;
    if (!['active', 'disabled', 'locked', 'deleted', 'not_found'].includes(String(status))) throw new Error('Invalid stored account state.');
    const exists = status !== 'not_found';
    const roleId = exists && row.catalog_synced === true && row.role_id !== null ? Number(row.role_id) : null;
    if (roleId !== null && !Number.isInteger(roleId)) throw new Error('Invalid stored role.');
    const source = exists && row.catalog_synced === true ? String(row.role_source) : 'none';
    if (!['override', 'org', 'catalog', 'none'].includes(source)) throw new Error('Invalid role source.');
    const access = !exists ? 'no_access' : !row.catalog_synced ? 'unmanaged'
      : roleId === null ? 'no_access' : row.role_exists ? 'allowed' : 'unknown_role';
    return { sub: String(row.sub), account: { status: status as AccessState['account']['status'] },
      rp: { catalog_synced: row.catalog_synced === true, role_id: roleId,
        role_source: source as AccessState['rp']['role_source'], access },
      allowed: status === 'active' && (access === 'allowed' || access === 'unmanaged') };
  });
}
