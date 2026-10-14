import type pg from 'pg';
import { pool } from '../db.js';
import { insertEvents } from '../events/outboxStore.js';

const ROLE_WRITE_LOCK = 1_145_624_915;
export interface RoleSyncState {
  client_id: string;
  catalog_mode: 'legacy' | 'revisioned';
  catalog_epoch: string | null;
  catalog_revision: string | null;
  catalog_digest: Buffer | null;
  last_sync_iat: string;
  authority_epoch: string;
  authority_revision: string;
}

/** Caller already owns a transaction; all role writers share its lock and budgets. */
export async function lockRoleWrites(db: pg.PoolClient): Promise<void> {
  await db.query("SET LOCAL lock_timeout='5s'");
  await db.query("SET LOCAL statement_timeout='15s'");
  await db.query('SELECT pg_advisory_xact_lock($1)', [ROLE_WRITE_LOCK]);
}

/** Serialize role writers, including a first catalog racing a membership change. */
export async function withRoleTransaction<T>(work: (db: pg.PoolClient) => Promise<T>, database: pg.Pool = pool): Promise<T> {
  const db = await database.connect();
  try {
    await db.query('BEGIN');
    await lockRoleWrites(db);
    const result = await work(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally {
    db.release();
  }
}

export async function ensureRoleSyncState(db: pg.PoolClient, clientId: string): Promise<RoleSyncState> {
  await db.query(`INSERT INTO app_role_sync_state(client_id,last_sync_iat)
    SELECT c.client_id,COALESCE(cat.last_sync_iat,0) FROM oauth_clients c
    LEFT JOIN app_role_catalogs cat USING(client_id) WHERE c.client_id=$1
    ON CONFLICT(client_id) DO NOTHING`, [clientId]);
  const { rows: [state] } = await db.query<RoleSyncState>(`SELECT client_id,catalog_mode,catalog_epoch,
    catalog_revision::text,catalog_digest,last_sync_iat::text,authority_epoch,authority_revision::text
    FROM app_role_sync_state WHERE client_id=$1 FOR UPDATE`, [clientId]);
  if (!state) throw new Error('Role authority client is unavailable.');
  return state;
}

interface EffectiveRow {
  user_sub: string;
  role_id: number | null;
  managed: boolean;
  known: boolean;
  previous_role: number | null;
  previous_managed: boolean | null;
}

/** The state mutation, authority revision, ledger and delivery intent share one transaction. */
export async function publishRoleChanges(db: pg.PoolClient, clientIds: string[], subjects?: readonly string[] | null,
  options: { force?: boolean; forceSubjects?: readonly string[] } = {}): Promise<number> {
  let count = 0;
  const forcedSubjects = new Set(options.forceSubjects ?? []);
  for (const clientId of [...new Set(clientIds)].sort()) {
    const state = await ensureRoleSyncState(db, clientId);
    const { rows } = await db.query<EffectiveRow>(`WITH effective AS(
      SELECT i.sub AS user_sub,CASE WHEN ov.user_sub IS NOT NULL THEN ov.app_role_id
        WHEN od.role_slug IS NOT NULL THEN od.app_role_id ELSE cat.default_role_id END AS raw_role,
        cat.client_id IS NOT NULL AS managed
      FROM identities i JOIN app_role_catalogs cat ON cat.client_id=$1
      LEFT JOIN user_app_role_overrides ov ON ov.user_sub=i.sub AND ov.client_id=$1
      LEFT JOIN user_org_roles ur ON ur.user_sub=i.sub
      LEFT JOIN org_role_app_defaults od ON od.role_slug=ur.org_role_slug AND od.client_id=$1
      WHERE i.deleted_at IS NULL AND ($2::uuid[] IS NULL OR i.sub=ANY($2::uuid[])))
      SELECT e.user_sub,r.role_id,e.managed,p.user_sub IS NOT NULL AS known,
        p.role_id AS previous_role,p.managed AS previous_managed
      FROM effective e LEFT JOIN app_roles r ON r.client_id=$1 AND r.role_id=e.raw_role
      LEFT JOIN app_role_effective p ON p.client_id=$1 AND p.user_sub=e.user_sub
      ORDER BY e.user_sub`, [clientId, subjects ? [...new Set(subjects)] : null]);
    const changed = rows.filter(row => options.force || forcedSubjects.has(row.user_sub)
      || !row.known || row.role_id !== row.previous_role || row.managed !== row.previous_managed);
    if (!changed.length) continue;
    const { rows: [advanced] } = await db.query<{ revision: string }>(`UPDATE app_role_sync_state
      SET authority_revision=authority_revision+1 WHERE client_id=$1 AND authority_revision<9223372036854775807
      RETURNING authority_revision::text AS revision`, [clientId]);
    if (!advanced) throw new Error('Role authority revision is exhausted.');
    for (let offset = 0; offset < changed.length; offset += 100) {
      const part = changed.slice(offset, offset + 100);
      await insertEvents(db, clientId, part.map(row => ({ type: 'account.roles_change', version: advanced.revision,
        payload: { sub: row.user_sub, role_id: row.role_id, authority_epoch: state.authority_epoch, authority_revision: advanced.revision } })));
      await db.query(`INSERT INTO app_role_effective(client_id,user_sub,role_id,managed,authority_revision)
        SELECT $1,v.user_sub,v.role_id,v.managed,$2::bigint
        FROM jsonb_to_recordset($3::jsonb) AS v(user_sub uuid,role_id integer,managed boolean)
        ON CONFLICT(client_id,user_sub) DO UPDATE SET role_id=excluded.role_id,managed=excluded.managed,
          authority_revision=excluded.authority_revision`, [clientId, advanced.revision,
        JSON.stringify(part.map(row => ({ user_sub: row.user_sub, role_id: row.role_id, managed: row.managed })))]);
    }
    count += changed.length;
  }
  return count;
}
