import type pg from 'pg';
import { pool } from '../db.js';
import { kickDrain } from '../events.js';
import { revokeSessions, withRevocationTransaction, type SessionSelection } from './sessionRevocation.js';

export { revokeSessions } from './sessionRevocation.js';

export async function withSessionRevocation<T>(work: (db: pg.PoolClient) => Promise<T>): Promise<T> {
  const result = await withRevocationTransaction(pool, work);
  // Delivery begins only after commit. A missed wakeup is recovered by the pump.
  kickDrain();
  return result;
}

export function revokeSessionSet(selection: SessionSelection): Promise<number> {
  return withSessionRevocation(db => revokeSessions(db, selection));
}
