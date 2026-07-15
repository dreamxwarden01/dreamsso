import { Router, type Response, type NextFunction } from 'express';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import { uuidv7 } from 'uuidv7';
import { pool } from '../db.js';
import { redis } from '../redis.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { requirePerm, hasPerm, resolveAuthz, permissionDenied } from '../rbac/index.js';
import { PERMISSIONS, PERM_KEYS } from '../rbac/catalog.js';
import { effectiveAppRole, appRoleLevel } from '../rbac/appRoles.js';
import { isStepupFresh } from '../oidc/sessions.js';
import { acceptedStepupMethods, stepupSatisfies } from '../oidc/stepupPolicy.js';
import { getSetting, setSetting } from '../settings.js';
import { audit, actorLabel } from '../audit.js';
import { fanOutLogout } from '../oidc/backchannel.js';
import { enqueueEvents } from '../events.js';
import { parseDevice } from '../deviceName.js';
import { verifyLoginTotp } from '../mfa.js';
import { loginAuthOptions, verifyLoginAssertion } from '../webauthn.js';
import { sendEmail } from '../email.js';
import { renderPasswordResetEmail, renderPasswordChangedEmail } from '../emailTemplates.js';
import { issueResetToken, resetTokenValidityMinutes } from '../passwordReset.js';
import { generateInviteCode, voidInvite, emailReserved, CODE_RE } from '../registration.js';
import { passwordComplexityOk } from './security.js';
import { pushAvatarChange } from './avatar.js';
import { deleteAvatarFile } from '../avatars.js';
import { config } from '../config.js';

// Organization management resource API (/account/org/*) — access-token
// protected like the rest of /account/*, permission-gated per endpoint
// (org.* keys), with EVERY endpoint (reads AND mutations) re-checking the
// step-up sudo window server-side (the portal door alone isn't enough: a stale
// tab must not keep read OR write powers past the window). The only exceptions
// are the action-challenge/action-token ceremony endpoints, which PROVE
// elevated auth and therefore can't require a pre-existing fresh window.
export const orgRouter = Router();
const scoped = requireScope('profile');

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');

// Fresh-sudo check for org endpoints (reads and mutations alike), active only
// while the portal step-up switch is on. The BFF forwards the caller's OWN
// master-session sid in x-stepup-sid; it must belong to the token's subject and
// carry a fresh stamp. On failure it returns 403 step_up_required, which the
// portal decodes to (re)open the step-up modal.
async function requireFreshStepup(req: AuthedRequest, res: Response, next: NextFunction): Promise<void> {
  if ((await getSetting('stepup_portal_required', 'false')) !== 'true') return next();
  const sid = qstr(req.headers['x-stepup-sid']);
  if (sid) {
    const { rows: [s] } = await pool.query<{ user_sub: string; stepup_at: string | null; stepup_method: string | null }>(
      // Full-precision epoch (no ::bigint second-flooring) so this agrees with
      // the ms-precision /account/stepup/status probe at the expiry instant —
      // otherwise a read can 403 while status still reports verified, spinning.
      'SELECT user_sub, EXTRACT(EPOCH FROM stepup_at)::text AS stepup_at, stepup_method FROM sessions WHERE sid = $1',
      [sid],
    );
    if (s && s.user_sub === req.auth!.sub) {
      // Strong-mandatory: fresh AND the recorded method is passkey/totp per the
      // user's owned factors (passkey preempts totp; no email/password fallback).
      const fresh = await isStepupFresh(s.stepup_at ? Number(s.stepup_at) : null);
      const { accepted } = await acceptedStepupMethods(req.auth!.sub, 'strong-mandatory');
      if (stepupSatisfies(accepted, s.stepup_method, fresh)) return next();
    }
  }
  res.status(403).json({ error: 'step_up_required' });
}

// GET /account/org/dashboard — org overview. Tiles degrade with permissions:
// recent activity is included only when the caller also holds org.logs.view.
orgRouter.get('/account/org/dashboard', scoped, requirePerm('org.dashboard'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const [users, sessions, roles, apps, defaultRole] = await Promise.all([
    pool.query(
      `SELECT count(*)::int AS total,
              count(*) FILTER (WHERE status <> 'active')::int AS suspended,
              count(*) FILTER (WHERE mfa_enabled)::int AS mfa_on
         FROM identities WHERE deleted_at IS NULL`,
    ),
    pool.query('SELECT count(*)::int AS n FROM sessions'),
    pool.query(
      `SELECT r.slug, r.label, r.level, r.is_system, count(ur.user_sub)::int AS members
         FROM org_roles r LEFT JOIN user_org_roles ur ON ur.org_role_slug = r.slug
        GROUP BY r.slug, r.label, r.level, r.is_system
        ORDER BY r.level ASC, r.slug ASC`,
    ),
    pool.query(
      `SELECT c.client_id, c.name, cat.synced_at, cat.default_role_id,
              (SELECT count(*)::int FROM app_roles ar WHERE ar.client_id = c.client_id) AS roles
         FROM app_role_catalogs cat JOIN oauth_clients c ON c.client_id = cat.client_id
        ORDER BY c.client_id`,
    ),
    getSetting('default_org_role', 'standard_user'),
  ]);

  const out: Record<string, unknown> = {
    users: users.rows[0],
    sessions_active: sessions.rows[0].n,
    roles: roles.rows,
    default_org_role: defaultRole,
    apps: apps.rows,
  };
  if (await hasPerm(req.auth!.sub, 'org.logs.view')) {
    const { rows } = await pool.query(
      `SELECT id, actor_label, target_label, action, detail, created_at
         FROM org_audit_log WHERE cleared_at IS NULL
        ORDER BY created_at DESC, id DESC LIMIT 5`,
    );
    out.recent = rows;
  }
  res.json(out);
});

// GET /account/org/logs?cursor=&limit=&include_cleared=1 — UTC timestamps,
// (created_at, id) keyset pagination; today/yesterday grouping is client-side.
orgRouter.get('/account/org/logs', scoped, requirePerm('org.logs.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const limit = Math.min(Math.max(parseInt(qstr(req.query.limit) || '50', 10) || 50, 1), 200);
  const includeCleared = qstr(req.query.include_cleared) === '1';
  const cursor = qstr(req.query.cursor); // "<ISO>_<uuid>"
  const params: unknown[] = [];
  let where = includeCleared ? 'TRUE' : 'cleared_at IS NULL';
  const m = /^(.+)_([0-9a-f-]{36})$/.exec(cursor);
  if (m && !Number.isNaN(Date.parse(m[1]))) {
    params.push(m[1], m[2]);
    where += ` AND (created_at, id) < ($1::timestamptz, $2::uuid)`;
  }
  const { rows } = await pool.query(
    `SELECT id, actor_sub, actor_label, target_sub, target_label, action, detail,
            created_at, cleared_at, cleared_by
       FROM org_audit_log WHERE ${where}
      ORDER BY created_at DESC, id DESC LIMIT ${limit + 1}`,
    params,
  );
  const page = rows.slice(0, limit);
  const last = page[page.length - 1];
  res.json({
    entries: page,
    next_cursor: rows.length > limit && last ? `${new Date(last.created_at).toISOString()}_${last.id}` : null,
  });
});

// POST /account/org/logs/clear {ids} — soft-hide (cleared_at/cleared_by, never
// deleted); the clearing itself is audited.
orgRouter.post('/account/org/logs/clear', scoped, requirePerm('org.logs.clear'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ids = (req.body ?? {}).ids;
    if (!Array.isArray(ids) || ids.length === 0 || ids.length > 200 ||
        !ids.every((x) => typeof x === 'string' && /^[0-9a-f-]{36}$/.test(x))) {
      return res.status(400).json({ error: 'invalid_ids' });
    }
    const sub = req.auth!.sub;
    const { rowCount } = await pool.query(
      `UPDATE org_audit_log SET cleared_at = now(), cleared_by = $2
        WHERE id = ANY($1::uuid[]) AND cleared_at IS NULL`,
      [ids, sub],
    );
    if (rowCount) {
      audit({ actorSub: sub, actorLabel: await actorLabel(sub), action: 'logs.clear', detail: { count: rowCount } });
    }
    res.status(204).end();
  });

// ============================================================================
// Slices 2-4: users / roles / apps. THE GUARD MATRIX (all server-enforced;
// "above" is always strictly >, levels: smaller = more privileged):
//   - list: same-or-lower org level visible (higher hidden); detail/edit:
//     strictly lower only, never self
//   - org-role grants: strictly below the actor (no peer creation)
//   - app-role changes: target's CURRENT effective must be <= actor's own
//     effective for that app, and the RESULTING effective <= actor's (equal
//     allowed) — inherit is resolved before checking, so falling through to
//     a higher default is blocked too
//   - permission overrides: only keys the actor effectively holds — EXCEPT
//     profile.security.mfa.disable, the sole exemption (admins/superadmin are
//     denied it themselves but MAY set it for lower-privilege users); the org
//     privilege rule still applies
// Every mutation passes requireFreshStepup and writes audit().
// ============================================================================

const INF_LEVEL = 2147483647; // SQL stand-in for "no role" (lowest privilege)

// The one permission an actor may set without holding it (see the matrix note).
const MFA_DISABLE = 'profile.security.mfa.disable';
const mayEditPerm = (granted: ReadonlySet<string>, key: string): boolean =>
  key === MFA_DISABLE || granted.has(key);

interface ActorCtx { sub: string; level: number; granted: ReadonlySet<string>; label: string }
async function actorCtx(req: AuthedRequest): Promise<ActorCtx> {
  const sub = req.auth!.sub;
  const az = await resolveAuthz(sub);
  return { sub, level: Number.isFinite(az.level) ? az.level : INF_LEVEL, granted: az.granted, label: await actorLabel(sub) };
}

interface TargetRow {
  sub: string; username: string; display_name: string; email: string | null;
  status: string; mfa_enabled: boolean; created_at: string;
  password_changed_at: string | null; avatar: string | null;
  role_slug: string | null; role_label: string | null; role_level: number | null;
}
async function loadTarget(sub: string): Promise<TargetRow | null> {
  const { rows: [t] } = await pool.query(
    `SELECT i.sub, i.username, i.display_name, i.email, i.status, i.mfa_enabled,
            i.created_at, i.password_changed_at, i.avatar,
            r.slug AS role_slug, r.label AS role_label, r.level AS role_level
       FROM identities i
       LEFT JOIN user_org_roles ur ON ur.user_sub = i.sub
       LEFT JOIN org_roles r ON r.slug = ur.org_role_slug
      WHERE i.sub = $1 AND i.deleted_at IS NULL`,
    [sub],
  );
  return (t as TargetRow) ?? null;
}
const levelOf = (t: TargetRow): number => t.role_level ?? INF_LEVEL;
const targetLabel = (t: TargetRow): string => t.display_name || t.username;

// Detail/edit authority: strictly lower target, never self. 404 hides users
// the actor may not even know details about.
async function editableTarget(req: AuthedRequest, res: Response): Promise<{ a: ActorCtx; t: TargetRow } | null> {
  const a = await actorCtx(req);
  const sub = String(req.params.sub ?? '');
  if (!/^[0-9a-f-]{36}$/.test(sub)) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }
  const t = await loadTarget(sub);
  if (!t || t.sub === a.sub || levelOf(t) <= a.level) {
    res.status(404).json({ error: 'not_found' });
    return null;
  }
  return { a, t };
}

async function revokeAllSessions(sub: string): Promise<number> {
  const { rows } = await pool.query<{ sid: string; clients: string[] | null }>(
    'DELETE FROM sessions WHERE user_sub = $1 RETURNING sid, clients',
    [sub],
  );
  await Promise.allSettled(rows.map((r) => fanOutLogout(sub, r.sid, r.clients ?? [])));
  return rows.length;
}

function pushRoleChange(clientId: string, sub: string, roleId: number | null): void {
  enqueueEvents(clientId, [{ type: 'account.roles_change', payload: { sub, role_id: roleId } }])
    .catch((e) => console.warn('roles_change enqueue failed:', (e as Error).message));
}

// --- users -----------------------------------------------------------------

// GET /account/org/users?query=&limit=&offset= — same-or-lower privilege only;
// sort level asc, display name (ci), sub. Self + equals render (chevron-less
// client-side); editable = strictly lower.
orgRouter.get('/account/org/users', scoped, requirePerm('org.users.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const q = qstr(req.query.query).trim().slice(0, 100);
  const limit = Math.min(Math.max(parseInt(qstr(req.query.limit) || '100', 10) || 100, 1), 200);
  const offset = Math.max(parseInt(qstr(req.query.offset) || '0', 10) || 0, 0);
  const params: unknown[] = [a.level];
  let filter = '';
  if (q) {
    params.push(`%${q}%`);
    filter = ` AND (i.username ILIKE $2 OR i.display_name ILIKE $2 OR i.email ILIKE $2)`;
  }
  const { rows } = await pool.query(
    `SELECT i.sub, i.username, i.display_name, i.email, i.status, i.mfa_enabled, i.avatar,
            r.slug AS role_slug, r.label AS role_label, r.level AS role_level,
            count(*) OVER()::int AS total
       FROM identities i
       LEFT JOIN user_org_roles ur ON ur.user_sub = i.sub
       LEFT JOIN org_roles r ON r.slug = ur.org_role_slug
      WHERE i.deleted_at IS NULL AND COALESCE(r.level, ${INF_LEVEL}) >= $1${filter}
      ORDER BY COALESCE(r.level, ${INF_LEVEL}) ASC, lower(i.display_name) ASC, i.sub ASC
      LIMIT ${limit} OFFSET ${offset}`,
    params,
  );
  res.json({
    total: rows[0]?.total ?? 0,
    users: rows.map((u) => ({
      sub: u.sub, username: u.username, display_name: u.display_name, email: u.email,
      status: u.status, mfa_enabled: u.mfa_enabled, avatar: u.avatar,
      role: u.role_slug ? { slug: u.role_slug, label: u.role_label, level: u.role_level } : null,
      me: u.sub === a.sub,
      editable: u.sub !== a.sub && (u.role_level ?? INF_LEVEL) > a.level,
    })),
  });
});

// POST /account/org/users — create (videosite AddUserModal rules; org role
// strictly below the actor; admin-set email counts as verified).
orgRouter.post('/account/org/users', scoped, requirePerm('org.users.create'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const username = typeof b.username === 'string' ? b.username.trim() : '';
    const displayName = typeof b.display_name === 'string' ? b.display_name.trim() : '';
    const email = typeof b.email === 'string' ? b.email.trim() : '';
    const password = typeof b.password === 'string' ? b.password : '';
    const roleSlug = typeof b.org_role === 'string' ? b.org_role : '';

    const errors: Record<string, string> = {};
    if (!/^[A-Za-z0-9_-]{3,20}$/.test(username)) errors.username = '3-20 characters: letters, digits, - and _';
    if (!displayName || displayName.length > 100) errors.display_name = 'Required, max 100 chars';
    if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) errors.email = 'Enter a valid email address';
    if (/\s/.test(password) || !passwordComplexityOk(password)) {
      errors.password = 'At least 8 characters, no spaces, and 3 of: uppercase, lowercase, digits, special characters';
    }
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [roleSlug]);
    if (!role || role.level <= a.level) errors.org_role = 'Pick a role below your own';
    if (Object.keys(errors).length) return res.status(422).json({ errors });

    // Both fields checked and BOTH reported (citext -> case-insensitive) so
    // one round trip surfaces everything, not username-then-email ping-pong.
    const { rows: dup } = await pool.query(
      `SELECT username = $1 AS u, ($2 <> '' AND email = $2) AS e FROM identities
        WHERE deleted_at IS NULL AND (username = $1 OR ($2 <> '' AND email = $2))`,
      [username, email],
    );
    // A live pending registration OR pending email change reserves its
    // address (user rule) — an admin-created account must not collide.
    const pendingHit = email !== '' && (await emailReserved(email));
    if (dup.length || pendingHit) {
      const dupErrs: Record<string, string> = {};
      if (dup.some((d) => d.u)) dupErrs.username = 'Already taken';
      if (dup.some((d) => d.e) || pendingHit) dupErrs.email = 'Already in use';
      return res.status(409).json({ errors: dupErrs });
    }

    const sub = uuidv7();
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    try {
      await pool.query(
        `INSERT INTO identities (sub, username, display_name, email, email_verified, password_hash, password_changed_at)
         VALUES ($1, $2, $3, NULLIF($4, ''), $4 <> '', $5, now())`,
        [sub, username, displayName, email, hash],
      );
    } catch (e) {
      // TOCTOU: a concurrent duplicate slipped past the SELECT — map the
      // unique violation to the same 409 shape instead of a raw 500.
      if ((e as { code?: string; constraint?: string }).code === '23505') {
        const c = (e as { constraint?: string }).constraint ?? '';
        return res.status(409).json({
          errors: c.includes('email') ? { email: 'Already in use' } : { username: 'Already taken' },
        });
      }
      throw e;
    }
    await pool.query('INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, $2)', [sub, role.slug]);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: sub, targetLabel: displayName || username,
            action: 'user.create', detail: { username, org_role: role.slug } });
    res.status(201).json({ sub });
  });

// GET /account/org/users/:sub — full detail (strictly-lower targets only).
orgRouter.get('/account/org/users/:sub', scoped, requirePerm('org.users.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const ctx = await editableTarget(req, res);
  if (!ctx) return;
  const { a, t } = ctx;

  const [totp, passkeys, overrides, roleEff, clients] = await Promise.all([
    pool.query(`SELECT id, label, created_at, last_used_at FROM totp_credentials
                 WHERE user_sub = $1 AND confirmed_at IS NOT NULL ORDER BY created_at`, [t.sub]),
    pool.query(`SELECT id, label, created_at, last_used_at FROM webauthn_credentials
                 WHERE user_sub = $1 ORDER BY created_at`, [t.sub]),
    pool.query(`SELECT perm_key, effect FROM user_permission_overrides WHERE user_sub = $1`, [t.sub]),
    pool.query(`SELECT perm_key, effect FROM role_permissions WHERE role_slug = $1`, [t.role_slug ?? '']),
    pool.query(`SELECT c.client_id, c.name, cat.default_role_id
                  FROM app_role_catalogs cat JOIN oauth_clients c ON c.client_id = cat.client_id
                 ORDER BY c.client_id`),
  ]);
  const ovMap = new Map(overrides.rows.map((r) => [r.perm_key, r.effect]));
  const roleMap = new Map(roleEff.rows.map((r) => [r.perm_key, r.effect]));

  const appRoles = [];
  for (const c of clients.rows) {
    const [{ rows: catalogRoles }, ovRow, orgRow, actorEff] = await Promise.all([
      pool.query('SELECT role_id, name, level, is_system FROM app_roles WHERE client_id = $1 ORDER BY level, role_id', [c.client_id]),
      pool.query('SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2', [t.sub, c.client_id]),
      pool.query(`SELECT app_role_id FROM org_role_app_defaults WHERE role_slug = $1 AND client_id = $2`, [t.role_slug ?? '', c.client_id]),
      effectiveAppRole(a.sub, c.client_id),
    ]);
    const eff = await effectiveAppRole(t.sub, c.client_id);
    const [effLevel, actorLevelHere] = await Promise.all([
      appRoleLevel(c.client_id, eff.role_id),
      appRoleLevel(c.client_id, actorEff.role_id),
    ]);
    appRoles.push({
      client_id: c.client_id,
      name: c.name,
      roles: catalogRoles,
      catalog_default: c.default_role_id,
      org_default: orgRow.rows[0] ? { role_id: orgRow.rows[0].app_role_id } : null,
      override: ovRow.rows[0] ? { role_id: ovRow.rows[0].app_role_id } : null,
      effective: eff,
      // current above the actor's own effective -> the whole row locks
      editable: effLevel >= actorLevelHere,
      // choices are capped at the actor's own effective level (equal allowed)
      actor_level: Number.isFinite(actorLevelHere) ? actorLevelHere : null,
    });
  }

  res.json({
    profile: {
      sub: t.sub, username: t.username, display_name: t.display_name, email: t.email,
      status: t.status, created_at: t.created_at, avatar: t.avatar,
    },
    org_role: t.role_slug ? { slug: t.role_slug, label: t.role_label, level: t.role_level } : null,
    security: {
      mfa_enabled: t.mfa_enabled,
      password_changed_at: t.password_changed_at,
      totp: totp.rows,
      passkeys: passkeys.rows,
    },
    permissions: PERMISSIONS.map((d) => ({
      key: d.key,
      group: d.group,
      description: d.description ?? null,
      role_effect: roleMap.get(d.key) ?? 'deny',
      override: ovMap.get(d.key) ?? null,
      editable: mayEditPerm(a.granted, d.key),
    })),
    app_roles: appRoles,
  });
});

// PATCH /account/org/users/:sub — profile fields, each behind its own key.
orgRouter.patch('/account/org/users/:sub', scoped, requireFreshStepup, async (req: AuthedRequest, res) => {
  const ctx = await editableTarget(req, res);
  if (!ctx) return;
  const { a, t } = ctx;
  const b = (req.body ?? {}) as Record<string, unknown>;
  const changes: Record<string, string> = {};

  if (typeof b.display_name === 'string') {
    if (!a.granted.has('org.users.edit.displayname')) return permissionDenied(res, 'org.users.edit.displayname');
    const v = b.display_name.trim();
    if (!v || v.length > 100) return res.status(422).json({ errors: { display_name: 'Required, max 100 chars' } });
    changes.display_name = v;
  }
  if (typeof b.email === 'string') {
    if (!a.granted.has('org.users.edit.email')) return permissionDenied(res, 'org.users.edit.email');
    const v = b.email.trim();
    if (v && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) return res.status(422).json({ errors: { email: 'Enter a valid email address' } });
    if (v) {
      const { rows } = await pool.query(
        'SELECT 1 FROM identities WHERE email = $1 AND sub <> $2 AND deleted_at IS NULL', [v, t.sub]);
      if (rows.length || (await emailReserved(v))) {
        return res.status(409).json({ errors: { email: 'Already in use' } });
      }
    }
    changes.email = v;
  }
  if (typeof b.username === 'string') {
    if (!a.granted.has('org.users.edit.username')) return permissionDenied(res, 'org.users.edit.username');
    const v = b.username.trim();
    if (!/^[A-Za-z0-9_-]{3,20}$/.test(v)) return res.status(422).json({ errors: { username: '3-20 characters: letters, digits, - and _' } });
    const { rows } = await pool.query(
      'SELECT 1 FROM identities WHERE username = $1 AND sub <> $2 AND deleted_at IS NULL', [v, t.sub]);
    if (rows.length) return res.status(409).json({ errors: { username: 'Already taken' } });
    changes.username = v;
  }
  if (!Object.keys(changes).length) return res.status(400).json({ error: 'no_fields' });

  // Admin-set email stays verified (the admin is the authority here).
  const sets: string[] = [];
  const vals: unknown[] = [t.sub];
  for (const [k, v] of Object.entries(changes)) {
    if (k === 'email') {
      vals.push(v || null);
      sets.push(`email = $${vals.length}, email_verified = ${v ? 'true' : 'false'}`);
    } else {
      vals.push(v);
      sets.push(`${k} = $${vals.length}`);
    }
  }
  try {
    await pool.query(`UPDATE identities SET ${sets.join(', ')} WHERE sub = $1`, vals);
  } catch (e) {
    // TOCTOU: concurrent duplicate past the SELECT — same 409 shape, not a 500.
    if ((e as { code?: string; constraint?: string }).code === '23505') {
      const c = (e as { constraint?: string }).constraint ?? '';
      return res.status(409).json({
        errors: c.includes('email') ? { email: 'Already in use' } : { username: 'Already taken' },
      });
    }
    throw e;
  }
  audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
          action: 'user.profile_edit', detail: { fields: Object.keys(changes) } });
  res.status(204).end();
});

// DELETE /account/org/users/:sub/avatar — remove the target's profile picture.
// Remove-only by design: pictures are self-service (profile.picture.set); an
// admin can take an inappropriate one down but never set one for someone else.
orgRouter.delete('/account/org/users/:sub/avatar', scoped, requirePerm('org.users.edit.profilePicture.remove'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    if (t.avatar) {
      await pool.query('UPDATE identities SET avatar = NULL WHERE sub = $1', [t.sub]);
      await deleteAvatarFile(t.avatar);
      pushAvatarChange(t.sub, null);
      audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
              action: 'user.avatar_remove' });
    }
    res.status(204).end();
  });

// POST /account/org/users/:sub/password — admin set-password: complexity
// checked, ALL target sessions terminated (stated in the UI), change notice
// emailed best-effort. The password itself is never mailed.
orgRouter.post('/account/org/users/:sub/password', scoped, requirePerm('org.users.edit.password'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const password = (req.body ?? {}).password;
    if (typeof password !== 'string' || /\s/.test(password) || !passwordComplexityOk(password)) {
      return res.status(422).json({ error: 'weak_password' });
    }
    const hash = await argon2.hash(password, { type: argon2.argon2id });
    await pool.query('UPDATE identities SET password_hash = $2, password_changed_at = now() WHERE sub = $1', [t.sub, hash]);
    const revoked = await revokeAllSessions(t.sub);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.password_set', detail: { sessions_revoked: revoked } });
    if (t.email) {
      void (async () => {
        const [site, portal] = await Promise.all([
          getSetting('site_name', 'DreamSSO'), getSetting('account_portal_url', config.accountPortalUrl)]);
        await sendEmail({ to: t.email!, ...renderPasswordChangedEmail({ siteName: site!, username: t.username, portalUrl: portal! }) });
      })().catch(() => { /* best effort */ });
    }
    res.status(204).end();
  });

// POST /account/org/users/:sub/password/send-reset — mail the standard reset
// link (admin-driven: audited, deliberately outside the per-address limiter).
orgRouter.post('/account/org/users/:sub/password/send-reset', scoped, requirePerm('org.users.edit.password'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    if (!t.email) return res.status(400).json({ error: 'no_email' });
    const token = await issueResetToken(t.sub);
    const [site, portal] = await Promise.all([
      getSetting('site_name', 'DreamSSO'), getSetting('account_portal_url', config.accountPortalUrl)]);
    const sent = await sendEmail({
      to: t.email,
      ...renderPasswordResetEmail({
        siteName: site!, username: t.username,
        link: `${portal}/reset?token=${token}`, minutes: resetTokenValidityMinutes,
      }),
    });
    if (!sent.ok) return res.status(502).json({ error: sent.reason });
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t), action: 'user.reset_link_sent' });
    res.status(204).end();
  });

// --- MFA: toggle off / full reset (the lockout-recovery nuke) ---

orgRouter.post('/account/org/users/:sub/mfa/disable', scoped, requirePerm('org.users.edit.mfa.disable'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [t.sub]);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t), action: 'user.mfa_disable' });
    res.status(204).end();
  });

// The one-time action ceremony: when the portal step-up switch is on, MFA
// reset demands a FRESH strong-factor ceremony from the ACTOR — the sudo
// window's pre-clearance deliberately does NOT count. Success mints a
// single-use token bound to (actor, action, target), 2 min TTL.
const ACTION_TTL = 120;
const actKey = (tok: string) => `orgact:tok:${tok}`;
const actPkKey = (sub: string) => `orgact:pk:${sub}`;

orgRouter.post('/account/org/action-challenge', scoped, async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const [{ rows: totp }, { rows: pk }] = await Promise.all([
    pool.query(`SELECT count(*)::int AS n FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL`, [sub]),
    pool.query(`SELECT count(*)::int AS n FROM webauthn_credentials WHERE user_sub = $1`, [sub]),
  ]);
  const methods: string[] = [];
  if (pk[0].n > 0) methods.push('passkey');
  if (totp[0].n > 0) methods.push('totp');
  let passkeyOptions;
  if (methods.includes('passkey')) {
    passkeyOptions = await loginAuthOptions(sub);
    await redis.set(actPkKey(sub), passkeyOptions.challenge, 'EX', 300);
  }
  res.json({ methods, passkey_options: passkeyOptions ?? null });
});

orgRouter.post('/account/org/action-token', scoped, async (req: AuthedRequest, res) => {
  const sub = req.auth!.sub;
  const b = (req.body ?? {}) as Record<string, unknown>;
  const action = qstr(b.action);
  const target = qstr(b.target_sub);
  if (!action || !/^[0-9a-f-]{36}$/.test(target)) return res.status(400).json({ error: 'invalid_request' });

  if (qstr(b.method) === 'totp') {
    const code = qstr(b.code).trim();
    if (!/^\d{6}$/.test(code) || !(await verifyLoginTotp(sub, code))) {
      return res.status(401).json({ error: 'challenge_failed' });
    }
  } else if (qstr(b.method) === 'passkey') {
    const expected = await redis.getdel(actPkKey(sub));
    if (!expected) return res.status(401).json({ error: 'challenge_expired' });
    let cred;
    try { cred = JSON.parse(qstr(b.credential)); } catch { return res.status(401).json({ error: 'challenge_failed' }); }
    const v = await verifyLoginAssertion(cred, expected, sub);
    if (!v.ok) return res.status(401).json({ error: 'challenge_failed' });
  } else {
    return res.status(400).json({ error: 'invalid_method' });
  }
  const token = crypto.randomUUID();
  await redis.set(actKey(token), JSON.stringify({ actor: sub, action, target }), 'EX', ACTION_TTL);
  res.json({ action_token: token });
});

orgRouter.post('/account/org/users/:sub/mfa/reset', scoped, requirePerm('org.users.edit.mfa.reset'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    if ((await getSetting('stepup_portal_required', 'false')) === 'true') {
      const raw = await redis.getdel(actKey(qstr((req.body ?? {}).action_token)));
      const tok = raw ? (JSON.parse(raw) as { actor: string; action: string; target: string }) : null;
      if (!tok || tok.actor !== a.sub || tok.action !== 'mfa.reset' || tok.target !== t.sub) {
        return res.status(403).json({ error: 'action_challenge_required' });
      }
    }
    const [{ rowCount: nTotp }, { rowCount: nPk }] = await Promise.all([
      pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [t.sub]),
      pool.query('DELETE FROM webauthn_credentials WHERE user_sub = $1', [t.sub]),
    ]);
    await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [t.sub]);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.mfa_reset', detail: { totp_removed: nTotp ?? 0, passkeys_removed: nPk ?? 0 } });
    res.status(204).end();
  });

// --- sessions / status -------------------------------------------------------

orgRouter.get('/account/org/users/:sub/sessions', scoped, requirePerm('org.users.edit.sessions.view'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { rows } = await pool.query(
      `SELECT sid, user_agent, country, auth_time, last_seen FROM sessions
        WHERE user_sub = $1 ORDER BY last_seen DESC NULLS LAST, auth_time DESC`,
      [ctx.t.sub],
    );
    res.json({
      sessions: rows.map((s) => ({
        sid: s.sid,
        device: parseDevice(s.user_agent ?? ''),
        country: s.country ?? null,
        auth_time: s.auth_time,
        last_seen: s.last_seen,
      })),
    });
  });

orgRouter.delete('/account/org/users/:sub/sessions/:sid', scoped, requirePerm('org.users.edit.sessions.terminate'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const { rows } = await pool.query(
      'DELETE FROM sessions WHERE sid = $1 AND user_sub = $2 RETURNING clients',
      [String(req.params.sid), t.sub],
    );
    if (!rows.length) return res.status(404).json({ error: 'not_found' });
    await fanOutLogout(t.sub, String(req.params.sid), rows[0].clients ?? []);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t), action: 'user.session_terminate' });
    res.status(204).end();
  });

orgRouter.post('/account/org/users/:sub/sessions/terminate-all', scoped, requirePerm('org.users.edit.sessions.terminate'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const n = await revokeAllSessions(t.sub);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.sessions_terminate_all', detail: { count: n } });
    res.status(204).end();
  });

orgRouter.post('/account/org/users/:sub/suspend', scoped, requirePerm('org.users.edit.deactivate'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    await pool.query(`UPDATE identities SET status = 'disabled' WHERE sub = $1`, [t.sub]);
    const n = await revokeAllSessions(t.sub);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.suspend', detail: { sessions_revoked: n } });
    res.status(204).end();
  });

orgRouter.post('/account/org/users/:sub/reactivate', scoped, requirePerm('org.users.edit.reactivate'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    await pool.query(`UPDATE identities SET status = 'active' WHERE sub = $1`, [t.sub]);
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t), action: 'user.reactivate' });
    res.status(204).end();
  });

// --- access: org role, permission overrides, app roles ----------------------

orgRouter.post('/account/org/users/:sub/org-role', scoped, requirePerm('org.users.edit.permissions.acctPortal'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const slug = qstr((req.body ?? {}).role_slug);
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [slug]);
    // Grant ceiling: strictly below the actor — promotion can never mint a peer.
    if (!role || role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
    // A role change can shift INHERITED app roles — diff effective per client.
    const { rows: cats } = await pool.query('SELECT client_id FROM app_role_catalogs');
    const beforeEff = new Map<string, number | null>();
    for (const cRow of cats) beforeEff.set(cRow.client_id, (await effectiveAppRole(t.sub, cRow.client_id)).role_id);
    // App-role ceiling: assigning this role must not leave the target inheriting an
    // app role that outranks the actor for any app (equal allowed).
    const overClient = await orgRoleInheritCeiling(a.sub, t.sub, role.slug, beforeEff, new Set());
    if (overClient) return res.status(403).json({ error: 'app_role_above_level', detail: { client: overClient } });
    await pool.query(
      `INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, $2)
       ON CONFLICT (user_sub) DO UPDATE SET org_role_slug = $2`,
      [t.sub, role.slug],
    );
    for (const cRow of cats) {
      const nowEff = (await effectiveAppRole(t.sub, cRow.client_id)).role_id;
      if (nowEff !== beforeEff.get(cRow.client_id)) pushRoleChange(cRow.client_id, t.sub, nowEff);
    }
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.role_change', detail: { from: t.role_slug, to: role.slug } });
    res.status(204).end();
  });

orgRouter.put('/account/org/users/:sub/permissions/:key', scoped, requirePerm('org.users.edit.permissions.acctPortal'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const key = String(req.params.key ?? '');
    const effect = qstr((req.body ?? {}).effect);
    if (!PERM_KEYS.has(key) || !['grant', 'deny', 'inherit'].includes(effect)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    // You can only touch keys you effectively hold — except the mfa.disable exemption.
    if (!mayEditPerm(a.granted, key)) return permissionDenied(res, key, 'you do not hold this permission');
    if (effect === 'inherit') {
      await pool.query('DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = $2', [t.sub, key]);
    } else {
      await pool.query(
        `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, $2, $3)
         ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = $3`,
        [t.sub, key, effect],
      );
    }
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.permission_override', detail: { key, effect } });
    res.status(204).end();
  });

// PUT /account/org/users/:sub/app-roles/:clientId {value: role_id | null | 'inherit'}
// Both the CURRENT and the RESULTING effective must sit at-or-below the
// actor's own effective for that app (inherit is resolved before checking).
orgRouter.put('/account/org/users/:sub/app-roles/:clientId', scoped, requirePerm('org.users.edit.permissions.app'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const ctx = await editableTarget(req, res);
    if (!ctx) return;
    const { a, t } = ctx;
    const clientId = String(req.params.clientId ?? '');
    const { rows: [cat] } = await pool.query('SELECT client_id FROM app_role_catalogs WHERE client_id = $1', [clientId]);
    if (!cat) return res.status(404).json({ error: 'not_found' });
    const value = (req.body ?? {}).value as number | null | 'inherit';
    if (value !== 'inherit' && value !== null && !Number.isInteger(value)) {
      return res.status(400).json({ error: 'invalid_request' });
    }
    if (typeof value === 'number') {
      const { rows } = await pool.query('SELECT 1 FROM app_roles WHERE client_id = $1 AND role_id = $2', [clientId, value]);
      if (!rows.length) return res.status(400).json({ error: 'unknown_app_role' });
    }

    const actorEff = await effectiveAppRole(a.sub, clientId);
    const actorLvl = await appRoleLevel(clientId, actorEff.role_id);
    const before = await effectiveAppRole(t.sub, clientId);
    if ((await appRoleLevel(clientId, before.role_id)) < actorLvl) {
      return res.status(403).json({ error: 'app_role_above_level', detail: 'current value outranks yours — view only' });
    }

    if (value === 'inherit') {
      await pool.query('DELETE FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2', [t.sub, clientId]);
    } else {
      await pool.query(
        `INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, $2, $3)
         ON CONFLICT (user_sub, client_id) DO UPDATE SET app_role_id = $3, updated_at = now()`,
        [t.sub, clientId, value],
      );
    }
    const after = await effectiveAppRole(t.sub, clientId);
    if ((await appRoleLevel(clientId, after.role_id)) < actorLvl) {
      // The RESULT outranks the actor (an inherit fell through to a higher
      // default) — roll back.
      if (value === 'inherit' && before.source === 'override') {
        await pool.query(
          `INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, $2, $3)`,
          [t.sub, clientId, before.role_id],
        );
      } else if (value !== 'inherit') {
        await pool.query('DELETE FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2', [t.sub, clientId]);
      }
      return res.status(403).json({ error: 'app_role_above_level' });
    }
    if (before.role_id !== after.role_id) {
      pushRoleChange(clientId, t.sub, after.role_id);
    }
    audit({ actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
            action: 'user.app_role_change', detail: { client: clientId, value: value === 'inherit' ? 'inherit' : value, effective: after.role_id } });
    res.status(204).end();
  });

// --- roles -------------------------------------------------------------------

orgRouter.get('/account/org/roles', scoped, requirePerm('org.roles.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const [{ rows }, defaultSlug] = await Promise.all([
    pool.query(
      `SELECT r.slug, r.label, r.level, r.is_system, count(ur.user_sub)::int AS members
         FROM org_roles r LEFT JOIN user_org_roles ur ON ur.org_role_slug = r.slug
        GROUP BY r.slug ORDER BY r.level ASC, r.slug ASC`),
    getSetting('default_org_role', 'standard_user'),
  ]);
  res.json({
    default_role: defaultSlug,
    roles: rows.map((r) => ({ ...r, editable: r.level > a.level })),
  });
});

orgRouter.get('/account/org/roles/:slug', scoped, requirePerm('org.roles.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const slug = String(req.params.slug ?? '');
  const { rows: [role] } = await pool.query(
    `SELECT r.slug, r.label, r.level, r.is_system,
            (SELECT count(*)::int FROM user_org_roles ur WHERE ur.org_role_slug = r.slug) AS members
       FROM org_roles r WHERE r.slug = $1`, [slug]);
  if (!role) return res.status(404).json({ error: 'not_found' });
  const [{ rows: perms }, { rows: appDefaults }, { rows: clients }] = await Promise.all([
    pool.query('SELECT perm_key, effect FROM role_permissions WHERE role_slug = $1', [slug]),
    pool.query('SELECT client_id, app_role_id FROM org_role_app_defaults WHERE role_slug = $1', [slug]),
    pool.query(`SELECT c.client_id, c.name, cat.default_role_id FROM app_role_catalogs cat
                  JOIN oauth_clients c ON c.client_id = cat.client_id ORDER BY c.client_id`),
  ]);
  const permMap = new Map(perms.map((p) => [p.perm_key, p.effect]));
  const adMap = new Map(appDefaults.map((d) => [d.client_id, d.app_role_id]));
  const apps = [];
  for (const c of clients) {
    const { rows: catalogRoles } = await pool.query(
      'SELECT role_id, name, level FROM app_roles WHERE client_id = $1 ORDER BY level, role_id', [c.client_id]);
    const actorEff = await effectiveAppRole(a.sub, c.client_id);
    const actorLvl = await appRoleLevel(c.client_id, actorEff.role_id);
    const current = adMap.has(c.client_id) ? { role_id: adMap.get(c.client_id) ?? null } : null;
    const currentLvl = current ? await appRoleLevel(c.client_id, current.role_id) : await appRoleLevel(c.client_id, c.default_role_id);
    apps.push({
      client_id: c.client_id, name: c.name, roles: catalogRoles,
      catalog_default: c.default_role_id,
      org_default: current,
      editable: role.level > a.level && currentLvl >= actorLvl,
      actor_level: Number.isFinite(actorLvl) ? actorLvl : null,
    });
  }
  res.json({
    role: { ...role, editable: role.level > a.level },
    permissions: PERMISSIONS.map((d) => ({
      key: d.key, group: d.group, description: d.description ?? null,
      effect: permMap.get(d.key) ?? 'deny',
      editable: role.level > a.level && mayEditPerm(a.granted, d.key),
    })),
    apps,
  });
});

orgRouter.post('/account/org/roles', scoped, requirePerm('org.roles.create'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const b = (req.body ?? {}) as Record<string, unknown>;
    const slug = typeof b.slug === 'string' ? b.slug.trim() : '';
    const label = typeof b.label === 'string' ? b.label.trim() : '';
    const level = Number(b.level);
    const errors: Record<string, string> = {};
    if (!/^[a-z][a-z0-9_-]{1,39}$/.test(slug)) errors.slug = 'lowercase letters, digits, - and _ (2-40)';
    if (!label || label.length > 60) errors.label = 'Required, max 60 chars';
    if (!Number.isInteger(level) || level < 1 || level > 9999) errors.level = 'Whole number 1-9999';
    else if (level <= a.level) errors.level = 'Must be below your own level';
    if (Object.keys(errors).length) return res.status(422).json({ errors });
    const { rows: dup } = await pool.query('SELECT 1 FROM org_roles WHERE slug = $1', [slug]);
    if (dup.length) return res.status(409).json({ errors: { slug: 'Already exists' } });
    await pool.query('INSERT INTO org_roles (slug, label, level) VALUES ($1, $2, $3)', [slug, label, level]);
    // Seed from the current default role: a new role starts with the same
    // permission grants + app defaults, then the admin tunes from there.
    const defSlug = (await getSetting('default_org_role', 'standard_user'))!;
    await pool.query(
      `INSERT INTO role_permissions (role_slug, perm_key, effect)
         SELECT $1, perm_key, effect FROM role_permissions WHERE role_slug = $2`,
      [slug, defSlug]);
    await pool.query(
      `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id)
         SELECT $1, client_id, app_role_id FROM org_role_app_defaults WHERE role_slug = $2`,
      [slug, defSlug]);
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.create', detail: { slug, level, seeded_from: defSlug } });
    res.status(201).json({ slug });
  });

orgRouter.patch('/account/org/roles/:slug', scoped, requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const slug = String(req.params.slug ?? '');
  const { rows: [role] } = await pool.query('SELECT slug, level, is_system FROM org_roles WHERE slug = $1', [slug]);
  if (!role) return res.status(404).json({ error: 'not_found' });
  if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
  const b = (req.body ?? {}) as Record<string, unknown>;
  const detail: Record<string, unknown> = {};
  if (typeof b.label === 'string') {
    if (!a.granted.has('org.roles.edit.rename')) return permissionDenied(res, 'org.roles.edit.rename');
    const v = b.label.trim();
    if (!v || v.length > 60) return res.status(422).json({ errors: { label: 'Required, max 60 chars' } });
    await pool.query('UPDATE org_roles SET label = $2 WHERE slug = $1', [slug, v]);
    detail.label = v;
  }
  if (b.level !== undefined) {
    if (!a.granted.has('org.roles.edit.level')) return permissionDenied(res, 'org.roles.edit.level');
    // Level is editable even for system roles — the guards are the actor being
    // strictly above BOTH the current level (checked above) and the target.
    const v = Number(b.level);
    if (!Number.isInteger(v) || v < 1 || v > 9999 || v <= a.level) {
      return res.status(422).json({ errors: { level: 'Whole number 1-9999, below your own level' } });
    }
    await pool.query('UPDATE org_roles SET level = $2 WHERE slug = $1', [slug, v]);
    detail.level = v;
  }
  if (!Object.keys(detail).length) return res.status(400).json({ error: 'no_fields' });
  audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.edit', detail: { slug, ...detail } });
  res.status(204).end();
});

orgRouter.put('/account/org/roles/:slug/permissions/:key', scoped, requirePerm('org.roles.edit.permissions.acctPortal'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const slug = String(req.params.slug ?? '');
    const key = String(req.params.key ?? '');
    const effect = qstr((req.body ?? {}).effect);
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [slug]);
    if (!role) return res.status(404).json({ error: 'not_found' });
    if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
    if (!PERM_KEYS.has(key) || !['grant', 'deny'].includes(effect)) return res.status(400).json({ error: 'invalid_request' });
    if (!mayEditPerm(a.granted, key)) return permissionDenied(res, key, 'you do not hold this permission');
    await pool.query(
      `INSERT INTO role_permissions (role_slug, perm_key, effect) VALUES ($1, $2, $3)
       ON CONFLICT (role_slug, perm_key) DO UPDATE SET effect = $3`,
      [slug, key, effect],
    );
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.permission_change', detail: { slug, key, effect } });
    res.status(204).end();
  });

orgRouter.put('/account/org/roles/:slug/app-defaults/:clientId', scoped, requirePerm('org.roles.edit.permissions.app'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const slug = String(req.params.slug ?? '');
    const clientId = String(req.params.clientId ?? '');
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [slug]);
    if (!role) return res.status(404).json({ error: 'not_found' });
    if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
    const { rows: [cat] } = await pool.query('SELECT default_role_id FROM app_role_catalogs WHERE client_id = $1', [clientId]);
    if (!cat) return res.status(404).json({ error: 'not_found' });
    const value = (req.body ?? {}).value as number | null | 'inherit';
    if (value !== 'inherit' && value !== null && !Number.isInteger(value)) return res.status(400).json({ error: 'invalid_request' });
    if (typeof value === 'number') {
      const { rows } = await pool.query('SELECT 1 FROM app_roles WHERE client_id = $1 AND role_id = $2', [clientId, value]);
      if (!rows.length) return res.status(400).json({ error: 'unknown_app_role' });
    }

    const actorEff = await effectiveAppRole(a.sub, clientId);
    const actorLvl = await appRoleLevel(clientId, actorEff.role_id);
    const { rows: [curRow] } = await pool.query(
      'SELECT app_role_id FROM org_role_app_defaults WHERE role_slug = $1 AND client_id = $2', [slug, clientId]);
    const currentVal = curRow ? curRow.app_role_id : cat.default_role_id; // inherit resolves to catalog
    if ((await appRoleLevel(clientId, currentVal)) < actorLvl) {
      return res.status(403).json({ error: 'app_role_above_level' });
    }
    // Defining a role's app default is stricter than assigning a role: the value set
    // must be STRICTLY below the actor (equal rejected), so no one can mint a role
    // that hands out their own app level. The top app role stays reserved for the
    // level-0 org roles the root guarantee points there.
    const resulting = value === 'inherit' ? cat.default_role_id : value;
    if ((await appRoleLevel(clientId, resulting)) <= actorLvl) {
      return res.status(403).json({ error: 'app_role_above_level' });
    }

    if (value === 'inherit') {
      await pool.query('DELETE FROM org_role_app_defaults WHERE role_slug = $1 AND client_id = $2', [slug, clientId]);
    } else {
      await pool.query(
        `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id) VALUES ($1, $2, $3)
         ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = $3, updated_at = now()`,
        [slug, clientId, value],
      );
    }
    // Members WITHOUT their own override just changed effective role — notify the app.
    if (currentVal !== resulting) {
      const { rows: members } = await pool.query(
        `SELECT ur.user_sub FROM user_org_roles ur
          WHERE ur.org_role_slug = $1
            AND NOT EXISTS (SELECT 1 FROM user_app_role_overrides o WHERE o.user_sub = ur.user_sub AND o.client_id = $2)`,
        [slug, clientId],
      );
      for (const m of members) pushRoleChange(clientId, m.user_sub, resulting ?? null);
    }
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.app_default_change',
            detail: { slug, client: clientId, value: value === 'inherit' ? 'inherit' : value } });
    res.status(204).end();
  });

orgRouter.delete('/account/org/roles/:slug', scoped, requirePerm('org.roles.remove'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const slug = String(req.params.slug ?? '');
    const { rows: [role] } = await pool.query(
      `SELECT r.slug, r.level, r.is_system,
              (SELECT count(*)::int FROM user_org_roles ur WHERE ur.org_role_slug = r.slug) AS members
         FROM org_roles r WHERE r.slug = $1`, [slug]);
    if (!role) return res.status(404).json({ error: 'not_found' });
    if (role.is_system) return res.status(409).json({ error: 'system_role' });
    if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
    if (role.members > 0) return res.status(409).json({ error: 'role_in_use' });
    if ((await getSetting('default_org_role', 'standard_user')) === slug) return res.status(409).json({ error: 'role_is_default' });
    await pool.query('DELETE FROM org_roles WHERE slug = $1', [slug]); // cascades role_permissions + app defaults
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.delete', detail: { slug } });
    res.status(204).end();
  });

orgRouter.put('/account/org/roles-default', scoped, requirePerm('org.roles.edit.default'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const slug = qstr((req.body ?? {}).slug);
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [slug]);
    if (!role) return res.status(404).json({ error: 'not_found' });
    if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
    await setSetting('default_org_role', role.slug);
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'role.default_change', detail: { slug } });
    res.status(204).end();
  });

// --- apps --------------------------------------------------------------------

orgRouter.get('/account/org/apps', scoped, requirePerm('org.apps.view'), requireFreshStepup, async (_req: AuthedRequest, res) => {
  const { rows: clients } = await pool.query(
    `SELECT c.client_id, c.name, cat.default_role_id, cat.synced_at
       FROM app_role_catalogs cat JOIN oauth_clients c ON c.client_id = cat.client_id
      ORDER BY c.client_id`);
  const apps = [];
  for (const c of clients) {
    const { rows: roles } = await pool.query(
      'SELECT role_id, name, level, is_system FROM app_roles WHERE client_id = $1 ORDER BY level, role_id', [c.client_id]);
    apps.push({ ...c, roles });
  }
  res.json({ apps });
});

orgRouter.post('/account/org/apps/:clientId/request-sync', scoped, requirePerm('org.apps.sync'), requireFreshStepup,
  async (req: AuthedRequest, res) => {
    const a = await actorCtx(req);
    const clientId = String(req.params.clientId ?? '');
    const { rows: [client] } = await pool.query(
      'SELECT client_id, events_uri, disabled_at FROM oauth_clients WHERE client_id = $1', [clientId]);
    if (!client || !client.events_uri || client.disabled_at) return res.status(404).json({ error: 'not_found' });
    await enqueueEvents(clientId, [{ type: 'roles.sync_request', payload: {} }]);
    audit({ actorSub: a.sub, actorLabel: a.label, action: 'app.sync_request', detail: { client: clientId } });
    res.status(204).end();
  });

// ============================================================================
// Batch access saves (the save-bar model): ONE request per page, validated in
// FULL before anything is written, then applied atomically. App events fire
// from the effective-role DIFF (before vs after) — which also covers the side
// effects of an org-role change on inherited app roles.
// ============================================================================

type BatchValue = number | null | 'inherit';
const validBatchValue = (v: unknown): v is BatchValue => v === 'inherit' || v === null || Number.isInteger(v);

async function orgDefaultFor(roleSlug: string | null, clientId: string): Promise<number | null> {
  const { rows: [od] } = await pool.query(
    'SELECT app_role_id FROM org_role_app_defaults WHERE role_slug = $1 AND client_id = $2',
    [roleSlug ?? '', clientId]);
  if (od) return od.app_role_id;
  const { rows: [cat] } = await pool.query('SELECT default_role_id FROM app_role_catalogs WHERE client_id = $1', [clientId]);
  return cat?.default_role_id ?? null;
}

// Ceiling for an org-role ASSIGNMENT (picking a defined role for a user): the change
// may not leave the target INHERITING an app role that outranks the actor for any
// app. Equal IS allowed, matching the per-client app-role endpoints. Only a client
// where the target has NO app-role override can shift (an override wins and is
// unchanged here), and only a client whose effective app role actually CHANGES can
// introduce a new grant. `skip` = clients the same request also sets an explicit
// app-role override for (validated separately). Returns the first offending
// client_id, or null if every changed client stays within the ceiling.
async function orgRoleInheritCeiling(
  actorSub: string,
  targetSub: string,
  newRoleSlug: string | null,
  before: Map<string, number | null>,
  skip: Set<string>,
): Promise<string | null> {
  for (const clientId of before.keys()) {
    if (skip.has(clientId)) continue;
    const { rows: [ov] } = await pool.query(
      'SELECT 1 FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2',
      [targetSub, clientId],
    );
    if (ov) continue; // override wins and is unchanged -> effective unchanged
    const resulting = await orgDefaultFor(newRoleSlug, clientId);
    if (resulting === before.get(clientId)) continue; // no change -> no new grant
    const actorLvl = await appRoleLevel(clientId, (await effectiveAppRole(actorSub, clientId)).role_id);
    if ((await appRoleLevel(clientId, resulting)) < actorLvl) return clientId;
  }
  return null;
}

// POST /account/org/users/:sub/access
// { org_role?, permissions?: {key: grant|deny|inherit}, app_roles?: {clientId: role_id|null|'inherit'} }
orgRouter.post('/account/org/users/:sub/access', scoped, requireFreshStepup, async (req: AuthedRequest, res) => {
  const ctx = await editableTarget(req, res);
  if (!ctx) return;
  const { a, t } = ctx;
  const b = (req.body ?? {}) as Record<string, unknown>;
  const orgRole = typeof b.org_role === 'string' ? b.org_role : undefined;
  const perms = b.permissions && typeof b.permissions === 'object' ? (b.permissions as Record<string, unknown>) : {};
  const appRoles = b.app_roles && typeof b.app_roles === 'object' ? (b.app_roles as Record<string, unknown>) : {};
  const nPerms = Object.keys(perms).length;
  const nApps = Object.keys(appRoles).length;
  if (!orgRole && !nPerms && !nApps) return res.status(400).json({ error: 'no_changes' });
  if (nPerms > 100 || nApps > 50) return res.status(400).json({ error: 'too_many_changes' });
  if ((orgRole || nPerms) && !a.granted.has('org.users.edit.permissions.acctPortal')) {
    return permissionDenied(res, 'org.users.edit.permissions.acctPortal');
  }
  if (nApps && !a.granted.has('org.users.edit.permissions.app')) {
    return permissionDenied(res, 'org.users.edit.permissions.app');
  }

  // --- validate EVERYTHING before writing anything ---
  let newRoleSlug = t.role_slug;
  if (orgRole !== undefined) {
    const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [orgRole]);
    if (!role || role.level <= a.level) {
      return res.status(403).json({ error: 'role_above_level', item: { type: 'org_role' } });
    }
    newRoleSlug = role.slug;
  }
  for (const [key, effect] of Object.entries(perms)) {
    if (!PERM_KEYS.has(key) || !['grant', 'deny', 'inherit'].includes(String(effect))) {
      return res.status(400).json({ error: 'invalid_request', item: { type: 'permission', key } });
    }
    if (!mayEditPerm(a.granted, key)) {
      return res.status(403).json({ error: 'permission_denied', permission: key, item: { type: 'permission', key } });
    }
  }
  const { rows: catalogClients } = await pool.query('SELECT client_id FROM app_role_catalogs');
  const catalogSet = new Set<string>(catalogClients.map((c) => c.client_id));
  const before = new Map<string, number | null>();
  for (const cid of catalogSet) before.set(cid, (await effectiveAppRole(t.sub, cid)).role_id);

  for (const [clientId, raw] of Object.entries(appRoles)) {
    const item = { type: 'app_role', client: clientId };
    if (!catalogSet.has(clientId)) return res.status(404).json({ error: 'not_found', item });
    if (!validBatchValue(raw)) return res.status(400).json({ error: 'invalid_request', item });
    if (typeof raw === 'number') {
      const { rows } = await pool.query('SELECT 1 FROM app_roles WHERE client_id = $1 AND role_id = $2', [clientId, raw]);
      if (!rows.length) return res.status(400).json({ error: 'unknown_app_role', item });
    }
    const actorLvl = await appRoleLevel(clientId, (await effectiveAppRole(a.sub, clientId)).role_id);
    if ((await appRoleLevel(clientId, before.get(clientId)!)) < actorLvl) {
      return res.status(403).json({ error: 'app_role_above_level', item });
    }
    // predicted result under the FINAL org role (the same batch may change it)
    const resulting = raw === 'inherit' ? await orgDefaultFor(newRoleSlug, clientId) : raw;
    if ((await appRoleLevel(clientId, resulting)) < actorLvl) {
      return res.status(403).json({ error: 'app_role_above_level', item });
    }
  }

  // A bare org-role change also shifts inherited app roles for clients NOT named in
  // app_roles above — enforce the same ceiling there (equal allowed).
  if (orgRole !== undefined) {
    const over = await orgRoleInheritCeiling(a.sub, t.sub, newRoleSlug, before, new Set(Object.keys(appRoles)));
    if (over) return res.status(403).json({ error: 'app_role_above_level', item: { type: 'app_role', client: over } });
  }

  // --- apply atomically ---
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    if (orgRole !== undefined) {
      await c.query(
        `INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, $2)
         ON CONFLICT (user_sub) DO UPDATE SET org_role_slug = $2`,
        [t.sub, newRoleSlug]);
    }
    for (const [key, effect] of Object.entries(perms)) {
      if (effect === 'inherit') {
        await c.query('DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = $2', [t.sub, key]);
      } else {
        await c.query(
          `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, $2, $3)
           ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = $3`,
          [t.sub, key, effect]);
      }
    }
    for (const [clientId, raw] of Object.entries(appRoles)) {
      if (raw === 'inherit') {
        await c.query('DELETE FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = $2', [t.sub, clientId]);
      } else {
        await c.query(
          `INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, $2, $3)
           ON CONFLICT (user_sub, client_id) DO UPDATE SET app_role_id = $3, updated_at = now()`,
          [t.sub, clientId, raw]);
      }
    }
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }

  // --- effective diff -> app events (covers org-role side effects too) ---
  for (const cid of catalogSet) {
    const now = (await effectiveAppRole(t.sub, cid)).role_id;
    if (now !== before.get(cid)) pushRoleChange(cid, t.sub, now);
  }
  audit({
    actorSub: a.sub, actorLabel: a.label, targetSub: t.sub, targetLabel: targetLabel(t),
    action: 'user.access_change',
    detail: {
      ...(orgRole !== undefined ? { org_role: { from: t.role_slug, to: newRoleSlug } } : {}),
      ...(nPerms ? { permissions: perms } : {}),
      ...(nApps ? { app_roles: appRoles } : {}),
    },
  });
  res.status(204).end();
});

// POST /account/org/roles/:slug/access
// { permissions?: {key: grant|deny}, app_defaults?: {clientId: role_id|null|'inherit'} }
orgRouter.post('/account/org/roles/:slug/access', scoped, requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const slug = String(req.params.slug ?? '');
  const { rows: [role] } = await pool.query('SELECT slug, level FROM org_roles WHERE slug = $1', [slug]);
  if (!role) return res.status(404).json({ error: 'not_found' });
  if (role.level <= a.level) return res.status(403).json({ error: 'role_above_level' });
  const b = (req.body ?? {}) as Record<string, unknown>;
  const perms = b.permissions && typeof b.permissions === 'object' ? (b.permissions as Record<string, unknown>) : {};
  const appDefaults = b.app_defaults && typeof b.app_defaults === 'object' ? (b.app_defaults as Record<string, unknown>) : {};
  const nPerms = Object.keys(perms).length;
  const nApps = Object.keys(appDefaults).length;
  if (!nPerms && !nApps) return res.status(400).json({ error: 'no_changes' });
  if (nPerms > 100 || nApps > 50) return res.status(400).json({ error: 'too_many_changes' });
  if (nPerms && !a.granted.has('org.roles.edit.permissions.acctPortal')) {
    return permissionDenied(res, 'org.roles.edit.permissions.acctPortal');
  }
  if (nApps && !a.granted.has('org.roles.edit.permissions.app')) {
    return permissionDenied(res, 'org.roles.edit.permissions.app');
  }

  for (const [key, effect] of Object.entries(perms)) {
    if (!PERM_KEYS.has(key) || !['grant', 'deny'].includes(String(effect))) {
      return res.status(400).json({ error: 'invalid_request', item: { type: 'permission', key } });
    }
    if (!mayEditPerm(a.granted, key)) {
      return res.status(403).json({ error: 'permission_denied', permission: key, item: { type: 'permission', key } });
    }
  }
  const resolvedBefore = new Map<string, number | null>();
  const resolvedAfter = new Map<string, number | null>();
  for (const [clientId, raw] of Object.entries(appDefaults)) {
    const item = { type: 'app_default', client: clientId };
    const { rows: [cat] } = await pool.query('SELECT default_role_id FROM app_role_catalogs WHERE client_id = $1', [clientId]);
    if (!cat) return res.status(404).json({ error: 'not_found', item });
    if (!validBatchValue(raw)) return res.status(400).json({ error: 'invalid_request', item });
    if (typeof raw === 'number') {
      const { rows } = await pool.query('SELECT 1 FROM app_roles WHERE client_id = $1 AND role_id = $2', [clientId, raw]);
      if (!rows.length) return res.status(400).json({ error: 'unknown_app_role', item });
    }
    const actorLvl = await appRoleLevel(clientId, (await effectiveAppRole(a.sub, clientId)).role_id);
    const current = await orgDefaultFor(slug, clientId);
    const resulting = raw === 'inherit' ? cat.default_role_id : raw;
    if ((await appRoleLevel(clientId, current)) < actorLvl) return res.status(403).json({ error: 'app_role_above_level', item });
    // Role DEFINITION: the value set must be strictly below the actor (equal rejected).
    if ((await appRoleLevel(clientId, resulting)) <= actorLvl) return res.status(403).json({ error: 'app_role_above_level', item });
    resolvedBefore.set(clientId, current);
    resolvedAfter.set(clientId, resulting);
  }

  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    for (const [key, effect] of Object.entries(perms)) {
      await c.query(
        `INSERT INTO role_permissions (role_slug, perm_key, effect) VALUES ($1, $2, $3)
         ON CONFLICT (role_slug, perm_key) DO UPDATE SET effect = $3`,
        [slug, key, effect]);
    }
    for (const [clientId, raw] of Object.entries(appDefaults)) {
      if (raw === 'inherit') {
        await c.query('DELETE FROM org_role_app_defaults WHERE role_slug = $1 AND client_id = $2', [slug, clientId]);
      } else {
        await c.query(
          `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id) VALUES ($1, $2, $3)
           ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = $3, updated_at = now()`,
          [slug, clientId, raw]);
      }
    }
    await c.query('COMMIT');
  } catch (e) {
    await c.query('ROLLBACK');
    throw e;
  } finally {
    c.release();
  }

  // members without their own override follow the default -> notify per client
  for (const [clientId] of Object.entries(appDefaults)) {
    if (resolvedBefore.get(clientId) === resolvedAfter.get(clientId)) continue;
    const { rows: members } = await pool.query(
      `SELECT ur.user_sub FROM user_org_roles ur
        WHERE ur.org_role_slug = $1
          AND NOT EXISTS (SELECT 1 FROM user_app_role_overrides o WHERE o.user_sub = ur.user_sub AND o.client_id = $2)`,
      [slug, clientId]);
    for (const m of members) pushRoleChange(clientId, m.user_sub, resolvedAfter.get(clientId) ?? null);
  }
  audit({
    actorSub: a.sub, actorLabel: a.label, action: 'role.access_change',
    detail: { slug, ...(nPerms ? { permissions: perms } : {}), ...(nApps ? { app_defaults: appDefaults } : {}) },
  });
  res.status(204).end();
});

// --- Invitation codes (registration) -----------------------------------
// Live codes + consumed records in one list. Lifecycle (user design): consumed
// rows are PERMANENT (used_by uuid -> username via join); voided rows are
// deleted immediately; expired unused rows die in the hourly sweep.

// GET /account/org/invites?limit=&offset= — guard-matrix list scope: only
// codes whose creator is same-or-lower org level than the viewer (orphaned
// creators visible). Voided/expired rows linger until their clear_at (24h).
orgRouter.get('/account/org/invites', scoped, requirePerm('org.invites.view'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const limit = Math.min(Math.max(parseInt(qstr(req.query.limit) || '25', 10) || 25, 1), 200);
  const offset = Math.max(parseInt(qstr(req.query.offset) || '0', 10) || 0, 0);
  const scopeWhere = `ic.created_by IS NULL OR ci.sub IS NULL OR COALESCE(cr.level, ${INF_LEVEL}) >= $1`;
  const joins = `
       FROM invitation_codes ic
       LEFT JOIN identities ci ON ci.sub = ic.created_by AND ci.deleted_at IS NULL
       LEFT JOIN user_org_roles cur ON cur.user_sub = ci.sub
       LEFT JOIN org_roles cr ON cr.slug = cur.org_role_slug`;
  const [{ rows }, { rows: [cnt] }] = await Promise.all([
    pool.query(
      `SELECT ic.code, ic.created_by, ic.created_by_label, ic.created_at, ic.expires_at,
              ic.use_count, ic.used_by, ic.used_at, ic.voided_at,
              ic.invited_role_slug, ir.label AS invited_role_label,
              COALESCE(cr.level, ${INF_LEVEL}) AS creator_level,
              u.username AS used_username, u.display_name AS used_display_name
         ${joins}
         LEFT JOIN org_roles ir ON ir.slug = ic.invited_role_slug
         LEFT JOIN identities u ON u.sub = ic.used_by
        WHERE ${scopeWhere}
        ORDER BY (ic.used_by IS NOT NULL OR ic.voided_at IS NOT NULL) ASC, ic.created_at DESC
        LIMIT ${limit} OFFSET ${offset}`,
      [a.level],
    ),
    pool.query(`SELECT count(*)::int AS n ${joins} WHERE ${scopeWhere}`, [a.level]),
  ]);
  const canVoidOthers = a.granted.has('org.invites.void');
  res.json({
    total: cnt.n,
    invites: rows.map((r) => ({
      code: r.code,
      created_by_label: r.created_by_label,
      created_at: r.created_at,
      expires_at: r.expires_at,
      use_count: r.use_count,
      invited_role: r.invited_role_slug ? { slug: r.invited_role_slug, label: r.invited_role_label } : null,
      used: r.used_by != null,
      used_at: r.used_at,
      used_by: r.used_by,
      used_username: r.used_username ?? null,
      used_display_name: r.used_display_name ?? null,
      voided: r.voided_at != null,
      // Own un-consumed codes are ALWAYS voidable (user rule — no permission
      // needed); others' need org.invites.void + creator strictly below.
      can_void: r.used_by == null && r.voided_at == null &&
        (r.created_by === a.sub || (canVoidOthers && Number(r.creator_level) > a.level)),
    })),
  });
});

// POST /account/org/invites {validity_hours?, role_slug} — the invited role is
// STRICTLY below the creator's own level, so the lowest role can't invite at
// all even when granted the permission (user rule).
orgRouter.post('/account/org/invites', scoped, requirePerm('org.invites.create'), requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const body = (req.body ?? {}) as { validity_hours?: unknown; role_slug?: unknown };
  const hours = body.validity_hours === undefined ? 72 : Number(body.validity_hours);
  if (!Number.isInteger(hours) || hours < 1 || hours > 8760) {
    return res.status(422).json({ errors: { validity_hours: '1 to 8760 hours' } });
  }
  const slug = qstr(body.role_slug);
  const { rows: [role] } = await pool.query<{ slug: string; label: string; level: number }>(
    'SELECT slug, label, level FROM org_roles WHERE slug = $1', [slug],
  );
  if (!role || !(role.level > a.level)) {
    return res.status(422).json({ errors: { role_slug: 'Pick a role below your own' } });
  }

  let code = '';
  for (let i = 0; i < 5; i++) {
    code = generateInviteCode();
    try {
      // clear_at = expiry + 24h: an expired unused code stays visible for a
      // day before the sweeper removes it; consumption NULLs it (permanent).
      const { rows: [row] } = await pool.query(
        `INSERT INTO invitation_codes (code, created_by, created_by_label, invited_role_slug, expires_at, clear_at)
         VALUES ($1, $2, $3, $4, now() + make_interval(hours => $5),
                 now() + make_interval(hours => $5) + interval '24 hours')
         RETURNING expires_at`,
        [code, a.sub, a.label, role.slug, hours],
      );
      audit({
        actorSub: a.sub, actorLabel: a.label, action: 'invite.create',
        detail: { code, role: role.slug, hours },
      });
      return res.status(201).json({ code, expires_at: row.expires_at, invited_role: { slug: role.slug, label: role.label } });
    } catch (e) {
      if ((e as { code?: string }).code !== '23505') throw e; // collision -> retry
    }
  }
  res.status(500).json({ error: 'code_generation_failed' });
});

// DELETE /account/org/invites/:code — void. Own un-consumed code: always
// allowed (the sole invites exemption). Others': org.invites.void + creator
// strictly below. Consumed codes are immutable records -> 409.
orgRouter.delete('/account/org/invites/:code', scoped, requireFreshStepup, async (req: AuthedRequest, res) => {
  const a = await actorCtx(req);
  const code = qstr(req.params.code).toUpperCase();
  if (!CODE_RE.test(code)) return res.status(404).json({ error: 'not_found' });
  const { rows: [row] } = await pool.query(
    `SELECT ic.code, ic.created_by, ic.used_by, ic.voided_at, ic.pending_email,
            COALESCE(cr.level, ${INF_LEVEL}) AS creator_level
       FROM invitation_codes ic
       LEFT JOIN identities ci ON ci.sub = ic.created_by AND ci.deleted_at IS NULL
       LEFT JOIN user_org_roles cur ON cur.user_sub = ci.sub
       LEFT JOIN org_roles cr ON cr.slug = cur.org_role_slug
      WHERE ic.code = $1`,
    [code],
  );
  if (!row) return res.status(404).json({ error: 'not_found' });
  if (row.used_by != null) return res.status(409).json({ error: 'already_used' });
  if (row.voided_at != null) return res.status(409).json({ error: 'already_voided' });
  const own = row.created_by === a.sub;
  if (!own) {
    if (!a.granted.has('org.invites.void')) return permissionDenied(res, 'org.invites.void');
    if (!(Number(row.creator_level) > a.level)) {
      return res.status(403).json({ error: 'creator_not_below' });
    }
  }
  // Mark + keep for 24h (clear_at), kill the in-flight link; sweeper deletes.
  await voidInvite(code, row.pending_email);
  audit({ actorSub: a.sub, actorLabel: a.label, action: 'invite.void', detail: { code, own } });
  res.status(204).end();
});
