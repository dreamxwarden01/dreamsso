import type { Response, NextFunction } from 'express';
import { pool } from '../db.js';
import type { AuthedRequest } from '../resourceAuth.js';
import { PERMISSIONS, type Effect } from './catalog.js';

// The permission engine. Resolution per (user, key):
//   per-user override (grant/deny) -> role default (grant/deny) -> deny.
// A user holds exactly one org role (uq_user_org_role). Unspecified = deny.

export interface UserAuthz {
  role: string | null; // org role slug, or null if unassigned
  level: number; // role level (lower = more privileged); +Infinity if unassigned
  granted: ReadonlySet<string>; // effective granted permission keys
}

export async function resolveAuthz(userSub: string): Promise<UserAuthz> {
  const [{ rows: roleRows }, { rows: roleEff }, { rows: overrides }] = await Promise.all([
    pool.query<{ slug: string; level: number }>(
      `SELECT r.slug, r.level FROM user_org_roles ur
         JOIN org_roles r ON r.slug = ur.org_role_slug
        WHERE ur.user_sub = $1 LIMIT 1`,
      [userSub],
    ),
    pool.query<{ perm_key: string; effect: Effect }>(
      `SELECT rp.perm_key, rp.effect FROM role_permissions rp
         JOIN user_org_roles ur ON ur.org_role_slug = rp.role_slug
        WHERE ur.user_sub = $1`,
      [userSub],
    ),
    pool.query<{ perm_key: string; effect: Effect }>(
      `SELECT perm_key, effect FROM user_permission_overrides WHERE user_sub = $1`,
      [userSub],
    ),
  ]);

  const roleEffect = new Map(roleEff.map((r) => [r.perm_key, r.effect]));
  const override = new Map(overrides.map((r) => [r.perm_key, r.effect]));

  const granted = new Set<string>();
  for (const def of PERMISSIONS) {
    const eff = override.get(def.key) ?? roleEffect.get(def.key) ?? 'deny';
    if (eff === 'grant') granted.add(def.key);
  }
  return {
    role: roleRows[0]?.slug ?? null,
    level: roleRows[0]?.level ?? Number.POSITIVE_INFINITY,
    granted,
  };
}

export async function hasPerm(userSub: string, key: string): Promise<boolean> {
  return (await resolveAuthz(userSub)).granted.has(key);
}

// --- wildcard matching (CHECK-side only — grants/overrides stay concrete keys) ---
// '*'  matches exactly one segment:  org.*   -> org.a, org.b (NOT org.a.c)
//                                    org.*.c -> org.a.c, org.b.c
// '**' matches any non-empty suffix, TERMINAL position only:
//                                    org.**  -> org.a, org.a.c, ...
// 'org.**.d' is invalid (matches nothing).
export function matchPerm(pattern: string, key: string): boolean {
  const ps = pattern.split('.');
  const ks = key.split('.');
  for (let i = 0; i < ps.length; i++) {
    if (ps[i] === '**') return i === ps.length - 1 && ks.length > i;
    if (ks.length <= i) return false;
    if (ps[i] !== '*' && ps[i] !== ks[i]) return false;
  }
  return ks.length === ps.length;
}

// Does the user hold ANY concrete permission matching the pattern? Powers the
// org-area entry check (hasAnyPerm(sub, 'org.**')).
export async function hasAnyPerm(userSub: string, pattern: string): Promise<boolean> {
  const { granted } = await resolveAuthz(userSub);
  for (const k of granted) if (matchPerm(pattern, k)) return true;
  return false;
}

// Standard permission-denied response. The `error` code is the discriminant the
// client switches on (vs the reserved `step_up_required` once step-up lands).
export function permissionDenied(res: Response, key: string, detail?: string): void {
  res.status(403).json({ error: 'permission_denied', permission: key, ...(detail ? { detail } : {}) });
}

// Middleware: 403 unless the access-token subject holds `key`. Runs AFTER a
// requireScope() that has set req.auth.
export function requirePerm(key: string) {
  return async (req: AuthedRequest, res: Response, next: NextFunction): Promise<void> => {
    const sub = req.auth?.sub;
    if (!sub) {
      res.status(401).set('WWW-Authenticate', 'Bearer error="invalid_token"').json({ error: 'invalid_token' });
      return;
    }
    if (!(await hasPerm(sub, key))) {
      permissionDenied(res, key);
      return;
    }
    next();
  };
}

export async function getRoleLevel(userSub: string): Promise<number> {
  const { rows } = await pool.query<{ level: number }>(
    `SELECT r.level FROM user_org_roles ur JOIN org_roles r ON r.slug = ur.org_role_slug
      WHERE ur.user_sub = $1 LIMIT 1`,
    [userSub],
  );
  return rows[0]?.level ?? Number.POSITIVE_INFINITY;
}

// Org-users delegation guard: an actor may administer a target only if strictly
// more privileged (lower level number) and never themselves — self-service goes
// through the profile page, not the org-users page.
export async function canAdminister(actorSub: string, targetSub: string): Promise<boolean> {
  if (actorSub === targetSub) return false;
  const [a, t] = await Promise.all([getRoleLevel(actorSub), getRoleLevel(targetSub)]);
  return a < t;
}
