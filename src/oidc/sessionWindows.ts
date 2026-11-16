import type pg from 'pg';
import type { SessionWindows } from './accessTokenState.js';

const clampHours = (value: string | null | undefined, fallback: number, maximum: number) => {
  const parsed = parseInt(value ?? '', 10);
  return Number.isFinite(parsed) && parsed >= 1 && parsed <= maximum ? parsed : fallback;
};

/** Shared parsing for cached browser loaders and transaction-owned bearer reads. */
export function resolveSessionWindows([idle, maximum, transient]: readonly (string | null | undefined)[]): SessionWindows {
  const maxHours = clampHours(maximum, 168, 8760);
  return { idleHours: Math.min(clampHours(idle, 72, 2160), maxHours), maxHours,
    transientMaxHours: Math.min(clampHours(transient, 24, 8760), maxHours) };
}

/** No runtime configuration or pool acquisition: callers provide the connection. */
export async function readSessionWindows(db: Pick<pg.PoolClient, 'query'>): Promise<SessionWindows> {
  const keys = ['session_idle_hours', 'session_max_hours', 'session_transient_max_hours'];
  const { rows } = await db.query<{ key: string; value: string | null }>('SELECT key,value FROM settings WHERE key=ANY($1::text[])', [keys]);
  const values = new Map(rows.map(row => [row.key, row.value]));
  return resolveSessionWindows(keys.map(key => values.get(key)));
}
