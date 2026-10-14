import type pg from 'pg';
import { verifyAccessToken, type AuthedRequest } from '../resourceAuth.js';
import { acceptedStrongStepup, stepupSatisfies, stepupStampFresh, stepupValidityMinutes } from '../oidc/stepupRules.js';
import { RoleAccessError } from './roleAdministration.js';

/** Recheck the same proof on the caller's connection, without caches or pool waits. */
export async function assertOrgRoleProof(db: pg.PoolClient, req: AuthedRequest): Promise<void> {
  const current = await verifyAccessToken(req, db);
  if (!current || current.sub !== req.auth?.sub) throw new RoleAccessError(401, { error: 'invalid_token' });
  if (!current.scopes.includes('profile')) throw new RoleAccessError(403, { error: 'insufficient_scope' });
  // Read fresh policy inside this transaction: a process-cache value may have
  // preceded a concurrent tightening of the step-up requirement/window.
  const { rows } = await db.query<{ key: string; value: string }>(
    'SELECT key,value FROM settings WHERE key=ANY($1::text[])', [['stepup_portal_required', 'stepup_validity_minutes']]);
  const settings = new Map(rows.map(row => [row.key, row.value]));
  if (settings.get('stepup_portal_required') !== 'true') return;
  const sid = typeof req.headers['x-stepup-sid'] === 'string' ? req.headers['x-stepup-sid'] : '';
  if (!sid) throw new RoleAccessError(403, { error: 'step_up_required' });
  const { rows: [session] } = await db.query<{ user_sub: string; stepup_at: string | null; stepup_method: string | null }>(
    'SELECT user_sub,EXTRACT(EPOCH FROM stepup_at)::text AS stepup_at,stepup_method FROM sessions WHERE sid=$1', [sid]);
  if (!session || session.user_sub !== current.sub) throw new RoleAccessError(403, { error: 'step_up_required' });
  const minutes = stepupValidityMinutes(settings.get('stepup_validity_minutes'));
  const stamp = session.stepup_at ? Number(session.stepup_at) : null;
  const fresh = stepupStampFresh(stamp, minutes);
  const { rows: [factors] } = await db.query<{ passkeys: number; totp: number }>(`SELECT
    (SELECT COUNT(*)::int FROM webauthn_credentials WHERE user_sub=$1) AS passkeys,
    (SELECT COUNT(*)::int FROM totp_credentials WHERE user_sub=$1 AND confirmed_at IS NOT NULL) AS totp`, [current.sub]);
  if (!stepupSatisfies(acceptedStrongStepup(factors.passkeys, factors.totp), session.stepup_method, fresh)) {
    throw new RoleAccessError(403, { error: 'step_up_required' });
  }
}
