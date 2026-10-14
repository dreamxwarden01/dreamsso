import type pg from 'pg';
import { PERM_KEYS } from './catalog.js';
import { resolveAuthz } from './index.js';
import { appRoleLevel, effectiveAppRole } from './appRoles.js';
import { publishRoleChanges } from './roleChanges.js';

const UUID = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
const MFA_DISABLE = 'profile.security.mfa.disable';
type Value = number | null | 'inherit';
const validValue = (value: unknown): value is Value => value === null || value === 'inherit'
  || (typeof value === 'number' && Number.isInteger(value) && value >= -2147483648 && value <= 2147483647);
export class RoleAccessError extends Error {
  constructor(readonly status: number, readonly body: Record<string, unknown>) { super(String(body.error)); }
}
const fail = (status: number, error: string, extra: Record<string, unknown> = {}): never => {
  throw new RoleAccessError(status, { error, ...extra });
};
const map = (value: unknown): Record<string, unknown> => {
  if (value === undefined || value === null) return {};
  if (typeof value !== 'object' || Array.isArray(value)) return fail(400, 'invalid_request');
  return value as Record<string, unknown>;
};
const requirePermission = (granted: ReadonlySet<string>, key: string) => {
  if (!granted.has(key)) fail(403, 'permission_denied', { permission: key });
};
const fieldError = (status: number, errors: Record<string, string>): never => {
  throw new RoleAccessError(status, { errors });
};

async function lockActors(db: pg.PoolClient, actor: string, targets: string[] = []) {
  if (!UUID.test(actor)) return fail(401, 'invalid_token');
  if (targets.some(target => !UUID.test(target))) return fail(404, 'not_found');
  const subjects = [...new Set([actor, ...targets])].sort();
  // These locks also fence writers that use ordinary FK/row operations outside this service.
  await db.query('SELECT sub FROM identities WHERE sub=ANY($1::uuid[]) ORDER BY sub FOR UPDATE', [subjects]);
  await db.query('SELECT user_sub FROM user_org_roles WHERE user_sub=ANY($1::uuid[]) ORDER BY user_sub FOR SHARE', [subjects]);
  await db.query(`SELECT slug FROM org_roles WHERE slug IN(SELECT org_role_slug FROM user_org_roles WHERE user_sub=ANY($1::uuid[]))
    ORDER BY slug FOR SHARE`, [subjects]);
  await db.query(`SELECT rp.perm_key FROM role_permissions rp JOIN user_org_roles ur ON ur.org_role_slug=rp.role_slug
    WHERE ur.user_sub=$1 ORDER BY rp.perm_key FOR SHARE OF rp`, [actor]);
  await db.query('SELECT perm_key FROM user_permission_overrides WHERE user_sub=$1 ORDER BY perm_key FOR SHARE', [actor]);
  const { rows: [identity] } = await db.query('SELECT status,deleted_at,display_name,username FROM identities WHERE sub=$1', [actor]);
  if (!identity || identity.deleted_at !== null || identity.status !== 'active') return fail(403, 'permission_denied');
  const auth = await resolveAuthz(actor, db);
  return { ...auth, sub: actor, label: identity.display_name || identity.username || actor };
}
async function orgDefault(db: pg.PoolClient, slug: string | null, client: string): Promise<number | null> {
  const { rows: [row] } = await db.query(`SELECT CASE WHEN d.role_slug IS NOT NULL THEN d.app_role_id ELSE c.default_role_id END AS role_id
    FROM app_role_catalogs c LEFT JOIN org_role_app_defaults d ON d.client_id=c.client_id AND d.role_slug=$2 WHERE c.client_id=$1`, [client, slug]);
  return row?.role_id ?? null;
}
async function writeAudit(db: pg.PoolClient, actor: { sub: string; label: string }, action: string,
  detail: Record<string, unknown>, target?: { sub: string; label: string }) {
  await db.query(`INSERT INTO org_audit_log(actor_sub,actor_label,target_sub,target_label,action,detail) VALUES($1,$2,$3,$4,$5,$6)`,
    [actor.sub, actor.label, target?.sub ?? null, target?.label ?? null, action, JSON.stringify(detail)]);
}

/** Call only within withRoleTransaction; validation and all changes share its locks. */
export async function applyUserAccess(db: pg.PoolClient, actorSub: string, targetSub: string, changes: Record<string, unknown>,
  action = 'user.access_change'): Promise<void> {
  const actor = await lockActors(db, actorSub, [targetSub]);
  const { rows: [target] } = await db.query(`SELECT i.sub,i.display_name,i.username,ur.org_role_slug,r.level FROM identities i
    LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub LEFT JOIN org_roles r ON r.slug=ur.org_role_slug
    WHERE i.sub=$1 AND i.deleted_at IS NULL`, [targetSub]);
  if (!target || targetSub === actorSub || (target.level ?? Infinity) <= actor.level) return fail(404, 'not_found');
  const orgRole = typeof changes.org_role === 'string' ? changes.org_role : undefined;
  const permissions = map(changes.permissions), appRoles = map(changes.app_roles);
  const permissionEntries = Object.entries(permissions), appEntries = Object.entries(appRoles);
  if (!orgRole && !permissionEntries.length && !appEntries.length) return fail(400, 'no_changes');
  if (permissionEntries.length > 100 || appEntries.length > 50) return fail(400, 'too_many_changes');
  if (orgRole !== undefined || permissionEntries.length) requirePermission(actor.granted, 'org.users.edit.permissions.acctPortal');
  if (appEntries.length) requirePermission(actor.granted, 'org.users.edit.permissions.app');
  let newSlug: string | null = target.org_role_slug;
  if (orgRole !== undefined) {
    const { rows: [role] } = await db.query('SELECT slug,level FROM org_roles WHERE slug=$1 FOR SHARE', [orgRole]);
    if (!role || role.level <= actor.level) return fail(403, 'role_above_level', { item: { type: 'org_role' } });
    newSlug = role.slug;
  }
  for (const [key, effect] of permissionEntries) {
    if (!PERM_KEYS.has(key) || !['grant', 'deny', 'inherit'].includes(String(effect))) return fail(400, 'invalid_request', { item: { type: 'permission', key } });
    if (key !== MFA_DISABLE && !actor.granted.has(key)) return fail(403, 'permission_denied', { permission: key, item: { type: 'permission', key } });
  }
  const clients = (await db.query<{ client_id: string }>('SELECT client_id FROM app_role_catalogs ORDER BY client_id')).rows.map(row => row.client_id);
  const before = new Map<string, number | null>();
  for (const client of clients) before.set(client, (await effectiveAppRole(targetSub, client, db)).role_id);
  for (const [client, value] of appEntries) {
    const item = { type: 'app_role', client };
    if (!before.has(client)) return fail(404, 'not_found', { item });
    if (!validValue(value)) return fail(400, 'invalid_request', { item });
    if (typeof value === 'number' && !(await db.query('SELECT 1 FROM app_roles WHERE client_id=$1 AND role_id=$2', [client, value])).rowCount) return fail(400, 'unknown_app_role', { item });
    const actorLevel = await appRoleLevel(client, (await effectiveAppRole(actorSub, client, db)).role_id, db);
    if (await appRoleLevel(client, before.get(client)!, db) < actorLevel) return fail(403, 'app_role_above_level', { item });
    const resulting = value === 'inherit' ? await orgDefault(db, newSlug, client) : value;
    if (await appRoleLevel(client, resulting, db) < actorLevel) return fail(403, 'app_role_above_level', { item });
  }
  if (orgRole !== undefined) {
    for (const client of clients) {
      if (Object.hasOwn(appRoles, client) || (await db.query('SELECT 1 FROM user_app_role_overrides WHERE user_sub=$1 AND client_id=$2', [targetSub, client])).rowCount) continue;
      const resulting = await orgDefault(db, newSlug, client);
      if (resulting === before.get(client)) continue;
      const actorLevel = await appRoleLevel(client, (await effectiveAppRole(actorSub, client, db)).role_id, db);
      if (await appRoleLevel(client, resulting, db) < actorLevel) return fail(403, 'app_role_above_level', { item: { type: 'app_role', client } });
    }
  }
  if (orgRole !== undefined) await db.query(`INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)
    ON CONFLICT(user_sub) DO UPDATE SET org_role_slug=excluded.org_role_slug`, [targetSub, newSlug]);
  for (const [key, effect] of permissionEntries) {
    if (effect === 'inherit') await db.query('DELETE FROM user_permission_overrides WHERE user_sub=$1 AND perm_key=$2', [targetSub, key]);
    else await db.query(`INSERT INTO user_permission_overrides(user_sub,perm_key,effect) VALUES($1,$2,$3)
      ON CONFLICT(user_sub,perm_key) DO UPDATE SET effect=excluded.effect`, [targetSub, key, effect]);
  }
  for (const [client, value] of appEntries) {
    if (value === 'inherit') await db.query('DELETE FROM user_app_role_overrides WHERE user_sub=$1 AND client_id=$2', [targetSub, client]);
    else await db.query(`INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,$2,$3)
      ON CONFLICT(user_sub,client_id) DO UPDATE SET app_role_id=excluded.app_role_id,updated_at=now()`, [targetSub, client, value]);
  }
  if (orgRole !== undefined || appEntries.length) await publishRoleChanges(db, orgRole !== undefined ? clients : appEntries.map(([client]) => client), [targetSub]);
  await writeAudit(db, actor, action, { ...(orgRole !== undefined ? { org_role: { from: target.org_role_slug, to: newSlug } } : {}),
    ...(permissionEntries.length ? { permissions } : {}), ...(appEntries.length ? { app_roles: appRoles } : {}) },
    { sub: targetSub, label: target.display_name || target.username || targetSub });
}

export async function applyRoleAccess(db: pg.PoolClient, actorSub: string, slug: string, changes: Record<string, unknown>,
  action = 'role.access_change'): Promise<void> {
  const actor = await lockActors(db, actorSub);
  const { rows: [role] } = await db.query('SELECT slug,level FROM org_roles WHERE slug=$1 FOR UPDATE', [slug]);
  if (!role) return fail(404, 'not_found');
  if (role.level <= actor.level) return fail(403, 'role_above_level');
  const permissions = map(changes.permissions), defaults = map(changes.app_defaults);
  const permissionEntries = Object.entries(permissions), defaultEntries = Object.entries(defaults);
  if (!permissionEntries.length && !defaultEntries.length) return fail(400, 'no_changes');
  if (permissionEntries.length > 100 || defaultEntries.length > 50) return fail(400, 'too_many_changes');
  if (permissionEntries.length) requirePermission(actor.granted, 'org.roles.edit.permissions.acctPortal');
  if (defaultEntries.length) requirePermission(actor.granted, 'org.roles.edit.permissions.app');
  for (const [key, effect] of permissionEntries) {
    if (!PERM_KEYS.has(key) || !['grant', 'deny'].includes(String(effect))) return fail(400, 'invalid_request', { item: { type: 'permission', key } });
    if (key !== MFA_DISABLE && !actor.granted.has(key)) return fail(403, 'permission_denied', { permission: key, item: { type: 'permission', key } });
  }
  for (const [client, value] of defaultEntries) {
    const item = { type: 'app_default', client };
    const { rows: [catalog] } = await db.query('SELECT default_role_id FROM app_role_catalogs WHERE client_id=$1', [client]);
    if (!catalog) return fail(404, 'not_found', { item });
    if (!validValue(value)) return fail(400, 'invalid_request', { item });
    if (typeof value === 'number' && !(await db.query('SELECT 1 FROM app_roles WHERE client_id=$1 AND role_id=$2', [client, value])).rowCount) return fail(400, 'unknown_app_role', { item });
    const actorLevel = await appRoleLevel(client, (await effectiveAppRole(actorSub, client, db)).role_id, db);
    if (await appRoleLevel(client, await orgDefault(db, slug, client), db) < actorLevel) return fail(403, 'app_role_above_level', { item });
    const resulting = value === 'inherit' ? catalog.default_role_id : value;
    if (await appRoleLevel(client, resulting, db) <= actorLevel) return fail(403, 'app_role_above_level', { item });
  }
  for (const [key, effect] of permissionEntries) await db.query(`INSERT INTO role_permissions(role_slug,perm_key,effect) VALUES($1,$2,$3)
    ON CONFLICT(role_slug,perm_key) DO UPDATE SET effect=excluded.effect`, [slug, key, effect]);
  for (const [client, value] of defaultEntries) {
    if (value === 'inherit') await db.query('DELETE FROM org_role_app_defaults WHERE role_slug=$1 AND client_id=$2', [slug, client]);
    else await db.query(`INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES($1,$2,$3)
      ON CONFLICT(role_slug,client_id) DO UPDATE SET app_role_id=excluded.app_role_id,updated_at=now()`, [slug, client, value]);
  }
  if (defaultEntries.length) await publishRoleChanges(db, defaultEntries.map(([client]) => client));
  await writeAudit(db, actor, action, { slug, ...(permissionEntries.length ? { permissions } : {}), ...(defaultEntries.length ? { app_defaults: defaults } : {}) });
}

async function defaultOrgRole(db: pg.PoolClient): Promise<string> {
  const { rows: [setting] } = await db.query("SELECT value FROM settings WHERE key='default_org_role' FOR UPDATE");
  return setting?.value || 'standard_user';
}

/** Role lifecycle writes share the role lock with assignments and catalog sync. */
export async function createOrgRole(db: pg.PoolClient, actorSub: string, body: Record<string, unknown>): Promise<{ slug: string }> {
  const actor = await lockActors(db, actorSub);requirePermission(actor.granted, 'org.roles.create');
  const slug = typeof body.slug === 'string' ? body.slug.trim() : '';
  const label = typeof body.label === 'string' ? body.label.trim() : '';
  const level = Number(body.level), errors: Record<string, string> = {};
  if (!/^[a-z][a-z0-9_-]{1,39}$/.test(slug)) errors.slug = 'lowercase letters, digits, - and _ (2-40)';
  if (!label || label.length > 60) errors.label = 'Required, max 60 chars';
  if (!Number.isInteger(level) || level < 1 || level > 9999) errors.level = 'Whole number 1-9999';
  else if (level <= actor.level) errors.level = 'Must be below your own level';
  if (Object.keys(errors).length) return fieldError(422, errors);
  if ((await db.query('SELECT 1 FROM org_roles WHERE slug=$1', [slug])).rowCount) return fieldError(409, { slug: 'Already exists' });
  const seed = await defaultOrgRole(db);
  if (!(await db.query('SELECT slug FROM org_roles WHERE slug=$1 FOR SHARE', [seed])).rowCount) throw new Error('Default organization role is unavailable.');
  try { await db.query('INSERT INTO org_roles(slug,label,level) VALUES($1,$2,$3)', [slug, label, level]); }
  catch (error) {
    if ((error as { code?: string }).code === '23505') return fieldError(409, { slug: 'Already exists' });
    throw error;
  }
  await db.query(`INSERT INTO role_permissions(role_slug,perm_key,effect)
    SELECT $1,perm_key,effect FROM role_permissions WHERE role_slug=$2`, [slug, seed]);
  await db.query(`INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id)
    SELECT $1,client_id,app_role_id FROM org_role_app_defaults WHERE role_slug=$2`, [slug, seed]);
  await writeAudit(db, actor, 'role.create', { slug, level, seeded_from: seed });
  return { slug };
}

export async function patchOrgRole(db: pg.PoolClient, actorSub: string, slug: string, body: Record<string, unknown>): Promise<void> {
  const actor = await lockActors(db, actorSub);
  const { rows: [role] } = await db.query('SELECT slug,level FROM org_roles WHERE slug=$1 FOR UPDATE', [slug]);
  if (!role) return fail(404, 'not_found');
  if (role.level <= actor.level) return fail(403, 'role_above_level');
  const detail: Record<string, unknown> = {};
  if (typeof body.label === 'string') {
    requirePermission(actor.granted, 'org.roles.edit.rename');
    const label = body.label.trim();
    if (!label || label.length > 60) return fieldError(422, { label: 'Required, max 60 chars' });
    detail.label = label;
  }
  if (body.level !== undefined) {
    requirePermission(actor.granted, 'org.roles.edit.level');
    const level = Number(body.level);
    if (!Number.isInteger(level) || level < 1 || level > 9999 || level <= actor.level) {
      return fieldError(422, { level: 'Whole number 1-9999, below your own level' });
    }
    detail.level = level;
  }
  if (!Object.keys(detail).length) return fail(400, 'no_fields');
  // Validate every supplied field before the first write.
  if (detail.label !== undefined) await db.query('UPDATE org_roles SET label=$2 WHERE slug=$1', [slug, detail.label]);
  if (detail.level !== undefined) await db.query('UPDATE org_roles SET level=$2 WHERE slug=$1', [slug, detail.level]);
  await writeAudit(db, actor, 'role.edit', { slug, ...detail });
}

export async function deleteOrgRole(db: pg.PoolClient, actorSub: string, slug: string): Promise<void> {
  const actor = await lockActors(db, actorSub);requirePermission(actor.granted, 'org.roles.remove');
  // Acquire this before the membership query. It waits for earlier FK inserts
  // and fences later ones, including registration outside the role service.
  const { rows: [role] } = await db.query('SELECT slug,level,is_system FROM org_roles WHERE slug=$1 FOR UPDATE', [slug]);
  if (!role) return fail(404, 'not_found');
  if (role.is_system) return fail(409, 'system_role');
  if (role.level <= actor.level) return fail(403, 'role_above_level');
  if ((await db.query('SELECT 1 FROM user_org_roles WHERE org_role_slug=$1 LIMIT 1', [slug])).rowCount) return fail(409, 'role_in_use');
  if (await defaultOrgRole(db) === slug) return fail(409, 'role_is_default');
  await db.query('DELETE FROM org_roles WHERE slug=$1', [slug]);
  await writeAudit(db, actor, 'role.delete', { slug });
}

export async function setDefaultOrgRole(db: pg.PoolClient, actorSub: string, slug: string): Promise<void> {
  const actor = await lockActors(db, actorSub);requirePermission(actor.granted, 'org.roles.edit.default');
  const { rows: [role] } = await db.query('SELECT slug,level FROM org_roles WHERE slug=$1 FOR SHARE', [slug]);
  if (!role) return fail(404, 'not_found');
  if (role.level <= actor.level) return fail(403, 'role_above_level');
  await db.query(`INSERT INTO settings(key,value) VALUES('default_org_role',$1)
    ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=now()`, [slug]);
  await writeAudit(db, actor, 'role.default_change', { slug });
}

export interface PreparedOrgUser {
  sub: string; username: string; displayName: string; email: string; passwordHash: string; roleSlug: string;
}
export async function createOrgUser(db: pg.PoolClient, actorSub: string, input: PreparedOrgUser): Promise<{ sub: string }> {
  const actor = await lockActors(db, actorSub);requirePermission(actor.granted, 'org.users.create');
  const { rows: [role] } = await db.query('SELECT slug,level FROM org_roles WHERE slug=$1 FOR SHARE', [input.roleSlug]);
  if (!role || role.level <= actor.level) return fieldError(422, { org_role: 'Pick a role below your own' });
  // Hashing and public-field validation happen before acquiring database locks.
  // The identity and membership become visible together; no RP can observe a
  // half-created user inheriting the catalog fallback before assignment.
  try {
    await db.query(`INSERT INTO identities(sub,username,display_name,email,email_verified,password_hash,password_changed_at)
      VALUES($1,$2,$3,NULLIF($4,''),$4<>'',$5,now())`,
    [input.sub, input.username, input.displayName, input.email, input.passwordHash]);
  } catch (error) {
    if ((error as { code?: string }).code === '23505') {
      const constraint = (error as { constraint?: string }).constraint ?? '';
      return fieldError(409, constraint.includes('email') ? { email: 'Already in use' } : { username: 'Already taken' });
    }
    throw error;
  }
  await db.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)', [input.sub, role.slug]);
  await writeAudit(db, actor, 'user.create', { username: input.username, org_role: role.slug },
    { sub: input.sub, label: input.displayName || input.username });
  return { sub: input.sub };
}
