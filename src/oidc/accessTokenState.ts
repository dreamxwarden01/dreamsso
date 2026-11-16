import type pg from 'pg';

export type AccessTokenState = 'active' | 'account_inactive' | 'client_disabled' | 'session_gone';
export interface BearerIdentity { sub: string; clientId: string; sid: string }
export interface SessionWindows { idleHours: number; maxHours: number; transientMaxHours: number }

// The identity, enabled RP and original owned session share one statement
// snapshot. There is deliberately no process cache for revocation decisions.
export const ACCESS_TOKEN_STATE_SQL = `SELECT
  COALESCE(i.sub IS NOT NULL AND i.status='active' AND i.deleted_at IS NULL,false) AS account_active,
  COALESCE(c.client_id IS NOT NULL AND c.disabled_at IS NULL,false) AS client_enabled,
  COALESCE(s.sid IS NOT NULL
    AND s.last_seen>clock_timestamp()-($4::double precision*interval '1 hour')
    AND s.created_at>clock_timestamp()-((CASE WHEN s.persistent THEN $5 ELSE $6 END)::double precision*interval '1 hour'),false) AS session_active
 FROM (SELECT 1) anchor
 LEFT JOIN identities i ON i.sub=$1::uuid
 LEFT JOIN oauth_clients c ON c.client_id=$2
 LEFT JOIN sessions s ON s.sid=$3::uuid AND s.user_sub=$1::uuid`;

export async function readAccessTokenState(db: Pick<pg.PoolClient, 'query'>, auth: BearerIdentity, windows: SessionWindows): Promise<AccessTokenState> {
  const { rows: [state] } = await db.query<{ account_active: boolean; client_enabled: boolean; session_active: boolean }>(
    ACCESS_TOKEN_STATE_SQL, [auth.sub, auth.clientId, auth.sid, windows.idleHours, windows.maxHours, windows.transientMaxHours]);
  if (!state || typeof state.account_active !== 'boolean' || typeof state.client_enabled !== 'boolean' || typeof state.session_active !== 'boolean') {
    throw Error('Access token state unavailable.');
  }
  if (!state.account_active) return 'account_inactive';
  if (!state.client_enabled) return 'client_disabled';
  return state.session_active ? 'active' : 'session_gone';
}
