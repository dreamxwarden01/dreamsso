import type pg from 'pg';
import { lockRoleWrites } from './rbac/roleChanges.js';

/** Existing registration transaction calls this before creating the identity. */
export async function resolveRegistrationRole(db: pg.PoolClient, invitedRole: string | null): Promise<string> {
  await lockRoleWrites(db);
  // Keep the already-validated invitation choice/grace behavior unchanged.
  if (invitedRole) return invitedRole;
  const { rows: [setting] } = await db.query<{ value: string }>("SELECT value FROM settings WHERE key='default_org_role'");
  return setting?.value || 'standard_user';
}
