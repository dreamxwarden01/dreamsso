import crypto from 'node:crypto';
import type pg from 'pg';
import type { AuthCode } from './codeStore.js';
import type { AccessStateSnapshot } from '../backchannel/accessState.js';
import type { mintIdToken, mintAccessToken } from './tokens.js';
import { scopesAllowed } from './scopes.js';

type IdClaims = Parameters<typeof mintIdToken>[0];
type AccessClaims = Parameters<typeof mintAccessToken>[0];
export interface RedemptionPreparation {
  windows: { idleHours: number; maxHours: number; transientMaxHours: number };
  siteName: string;
  mintIdToken(claims: IdClaims): Promise<string>;
  mintAccessToken(claims: AccessClaims): Promise<string>;
}
export interface CodeRedemptionDependencies {
  database: Pick<pg.Pool, 'connect'>;
  consumeCode(code: string): Promise<AuthCode | null>;
  // Resolve keys/settings before owning a DB connection: signing must not need
  // another pool slot while every concurrent redemption holds a transaction.
  prepare(): Promise<RedemptionPreparation>;
  readAccessStateSnapshot(db: pg.PoolClient, clientId: string, subjects: readonly string[]): Promise<AccessStateSnapshot>;
}
export class CodeRedemptionError extends Error {
  constructor(readonly status: 400 | 401 | 403 | 503, readonly code: string, readonly description?: string) { super(code); }
}
export interface CodeRedemptionInput { clientId: string; code: string; redirectUri: string; verifier: string }

/** Sign while holding the original session's row lock. A concurrent logout
 * either deletes first (redemption fails), or waits until issuance commits.
 * Identity-before-session ordering matches password/suspension revocations.
 */
export async function redeemAuthorizationCode(input: CodeRedemptionInput, deps: CodeRedemptionDependencies) {
  const ac = await deps.consumeCode(input.code);
  if (!ac) throw new CodeRedemptionError(400, 'invalid_grant', 'code invalid or expired');
  if (ac.clientId !== input.clientId) throw new CodeRedemptionError(400, 'invalid_grant', 'client mismatch');
  if (ac.redirectUri !== input.redirectUri) throw new CodeRedemptionError(400, 'invalid_grant', 'redirect_uri mismatch');
  if (!input.verifier || crypto.createHash('sha256').update(input.verifier).digest('base64url') !== ac.codeChallenge) {
    throw new CodeRedemptionError(400, 'invalid_grant', 'PKCE verification failed');
  }
  if (!ac.sid) throw new CodeRedemptionError(400, 'invalid_grant', 'session unavailable');
  const prepared = await deps.prepare();
  const db = await deps.database.connect();
  try {
    await db.query('BEGIN');
    await db.query("SET LOCAL lock_timeout='5s'");
    await db.query("SET LOCAL statement_timeout='15s'");
    await db.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
    const identity = await db.query("SELECT sub FROM identities WHERE sub=$1 AND status='active' AND deleted_at IS NULL FOR SHARE", [ac.userSub]);
    if (!identity.rows.length) throw new CodeRedemptionError(403, 'access_denied');
    const { rows: [session] } = await db.query<{ persistent: boolean; created_at: string; idle_valid: boolean; absolute_valid: boolean }>(
      `SELECT persistent,floor(EXTRACT(EPOCH FROM created_at))::text AS created_at,
        last_seen>clock_timestamp()-($3::double precision*interval '1 hour') AS idle_valid,
        created_at>clock_timestamp()-((CASE WHEN persistent THEN $4 ELSE $5 END)::double precision*interval '1 hour') AS absolute_valid
       FROM sessions WHERE sid=$1 AND user_sub=$2 FOR UPDATE`,
      [ac.sid, ac.userSub, prepared.windows.idleHours, prepared.windows.maxHours, prepared.windows.transientMaxHours]);
    if (!session || !session.idle_valid || !session.absolute_valid) throw new CodeRedemptionError(400, 'invalid_grant', 'session unavailable');
    // A registration change since /authorize cannot widen the consumed grant.
    const { rows: [client] } = await db.query<{ allowed_scopes: string[] }>(
      'SELECT allowed_scopes FROM oauth_clients WHERE client_id=$1 AND disabled_at IS NULL', [input.clientId]);
    if (!client) throw new CodeRedemptionError(401, 'invalid_client');
    if (!scopesAllowed(ac.scope, client.allowed_scopes)) throw new CodeRedemptionError(400, 'invalid_scope');

    // Integer seconds are required by RP TTLs; floor the DB epoch, never round
    // upward and advertise an expiry beyond the underlying session window.
    const extra: Record<string, unknown> = { site_name: prepared.siteName,
      sess_persistent: session.persistent,
      sess_exp: Number(session.created_at) + (session.persistent ? prepared.windows.maxHours : prepared.windows.transientMaxHours) * 3600 };
    const scopes = ac.scope.split(' ');
    if (scopes.includes('profile') || scopes.includes('email')) {
      const { rows: [profile] } = await db.query(
        'SELECT username, display_name, email, email_verified, avatar FROM identities WHERE sub = $1', [ac.userSub]);
      if (profile) {
        if (scopes.includes('profile')) {
          extra.name = profile.display_name;extra.preferred_username = profile.username;
          if (profile.avatar) extra.picture = profile.avatar;
        }
        if (scopes.includes('email')) { extra.email = profile.email;extra.email_verified = profile.email_verified; }
      }
    }
    const snapshot = await deps.readAccessStateSnapshot(db, input.clientId, [ac.userSub]);
    const state = snapshot.states[0];
    if (snapshot.states.length !== 1 || !state.allowed) throw new CodeRedemptionError(403, 'access_denied');
    if (state.rp.catalog_synced) {
      if (!snapshot.authority) throw new CodeRedemptionError(503, 'temporarily_unavailable');
      extra.app_role = state.rp.role_id;extra.app_role_epoch = snapshot.authority.epoch;extra.app_role_revision = snapshot.authority.revision;
    }
    await db.query('UPDATE sessions SET clients=array_append(clients,$2) WHERE sid=$1 AND NOT ($2=ANY(clients))', [ac.sid, input.clientId]);
    const id_token = await prepared.mintIdToken({ sub: ac.userSub, clientId: input.clientId, nonce: ac.nonce,
      acr: ac.acr, amr: ac.amr, authTime: ac.authTime, sid: ac.sid, extra });
    const access_token = await prepared.mintAccessToken({ sub: ac.userSub, clientId: input.clientId, scope: ac.scope });
    await db.query('COMMIT');
    return { access_token, token_type: 'Bearer', expires_in: 900, id_token, scope: ac.scope };
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { db.release(); }
}
