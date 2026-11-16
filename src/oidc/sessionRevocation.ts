import type pg from 'pg';
import { insertEvents, lockEventDestinations } from '../events/outboxStore.js';

export type SessionSelection =
  | { subject: string; sid?: string; exceptSid?: string }
  | { expired: { idleBefore: Date; persistentBefore: Date; transientBefore: Date } };
export interface RevokedSession { user_sub: string; sid: string; clients: string[] | null }

/** Delete sessions and retain their exact logout recipients in the same transaction. */
export async function revokeSessions(db: pg.PoolClient, selection: SessionSelection): Promise<number> {
  let where: string, values: unknown[];
  if ('expired' in selection) {
    const e = selection.expired;
    values = [e.idleBefore, e.persistentBefore, e.transientBefore];
    if (values.some(value => !(value instanceof Date) || !Number.isFinite(value.getTime()))) throw new Error('invalid_revocation_selection');
    where = 'last_seen < $1 OR created_at < (CASE WHEN persistent THEN $2::timestamptz ELSE $3::timestamptz END)';
  } else {
    const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuid.test(selection.subject) || ('sid' in selection && !uuid.test(selection.sid ?? ''))
      || ('exceptSid' in selection && !uuid.test(selection.exceptSid ?? ''))
      || ('sid' in selection && 'exceptSid' in selection)) throw new Error('invalid_revocation_selection');
    where = 'user_sub=$1'; values = [selection.subject];
    if (selection.sid) { where += ' AND sid=$2'; values.push(selection.sid); }
    if (selection.exceptSid) { where += ' AND sid<>$2'; values.push(selection.exceptSid); }
  }
  // Use the same row order as status changes, including multi-subject expiry
  // sweeps. A materialized locked selection prevents competing predicates from
  // acquiring the same master rows in opposite physical/index scan orders.
  const { rows } = await db.query<RevokedSession>(`WITH selected AS MATERIALIZED (
    SELECT sid FROM sessions WHERE ${where} ORDER BY sid FOR UPDATE)
    DELETE FROM sessions s USING selected x WHERE s.sid=x.sid RETURNING s.user_sub,s.sid,s.clients`, values);
  const recipients = [...new Set(rows.flatMap(row => row.clients ?? []))].sort();
  if (!recipients.length) return rows.length;
  // A removed registration cannot receive an event. Retain disabled destinations
  // that still exist; don't make an old clients[] entry prevent master logout.
  const { rows: registered } = await db.query<{ client_id: string }>(
    'SELECT client_id FROM oauth_clients WHERE client_id=ANY($1::text[]) ORDER BY client_id FOR KEY SHARE', [recipients]);
  await lockEventDestinations(db, registered.map(row => row.client_id));
  for (const { client_id } of registered) {
    const events = rows.filter(row => row.clients?.includes(client_id))
      .map(row => ({ type: 'logout', payload: { sub: row.user_sub, sid: row.sid } }));
    await insertEvents(db, client_id, events);
  }
  return rows.length;
}

/** Identity changes and logout intent can join the caller's bounded transaction. */
export async function withRevocationTransaction<T>(database: Pick<pg.Pool, 'connect'>,
  work: (db: pg.PoolClient) => Promise<T>): Promise<T> {
  const db = await database.connect();
  try {
    await db.query('BEGIN');
    await db.query("SET LOCAL lock_timeout='5s'");
    await db.query("SET LOCAL statement_timeout='15s'");
    await db.query("SET LOCAL idle_in_transaction_session_timeout='10s'");
    const result = await work(db);
    await db.query('COMMIT');
    return result;
  } catch (error) {
    await db.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { db.release(); }
}
