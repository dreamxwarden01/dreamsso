import type pg from 'pg';
import { publishRoleChanges } from './roleChanges.js';
import { lockEventDestinations } from '../events/outboxStore.js';

export type AccountStatusMutation = 'active' | 'disabled' | 'locked' | 'deleted';
export class AccountStatusError extends Error {
  constructor(readonly code: 'invalid_status' | 'account_unavailable') { super(code); }
}

/**
 * Caller owns withRoleTransaction (including its role-writer lock), authorization,
 * any session revocation and audit. Status, authority ledger and outbox commit
 * together. A soft-deleted identity cannot be restored through this operation.
 */
export async function changeAccountStatus(db: pg.PoolClient, subject: string, status: AccountStatusMutation, beforePublish?: (db: pg.PoolClient) => Promise<void>): Promise<{ changed: boolean; published: number }> {
  if (!['active','disabled','locked','deleted'].includes(status)) throw new AccountStatusError('invalid_status');
  const current = (await db.query('SELECT status,deleted_at FROM identities WHERE sub=$1 FOR UPDATE', [subject])).rows[0];
  if (!current || current.deleted_at !== null && status !== 'deleted') throw new AccountStatusError('account_unavailable');
  const changed = status === 'deleted' ? current.deleted_at === null : current.status !== status;
  if (changed) {
    if (status === 'deleted') await db.query('UPDATE identities SET deleted_at=now() WHERE sub=$1', [subject]);
    else await db.query('UPDATE identities SET status=$2 WHERE sub=$1', [subject,status]);
  }
  // Unmanaged clients have no role authority snapshot and should not receive a
  // fabricated role/status version. Keep this the same catalog-managed set used
  // by the ordinary role publisher, including disabled registered destinations.
  const clients = (await db.query('SELECT client_id FROM app_role_catalogs ORDER BY client_id')).rows.map(row => String(row.client_id));
  // Lock master rows before destinations, as ordinary logout does. Issuance
  // requires an identity share lock, so no new recipient can be appended while
  // this transaction owns the identity update lock. Acquire the UNION once:
  // individually sorting logout recipients and catalog recipients can deadlock.
  const sessions = beforePublish ? (await db.query<{ clients: string[] | null }>(
    'SELECT clients FROM sessions WHERE user_sub=$1 ORDER BY sid FOR UPDATE', [subject])).rows : [];
  const recipients = [...new Set([...clients, ...sessions.flatMap(row => row.clients ?? [])])];
  if (recipients.length) {
    const registered = (await db.query<{ client_id: string }>(
      'SELECT client_id FROM oauth_clients WHERE client_id=ANY($1::text[]) ORDER BY client_id FOR KEY SHARE', [recipients])).rows;
    await lockEventDestinations(db, registered.map(row => row.client_id));
  }
  if (beforePublish) await beforePublish(db);
  const published = await publishRoleChanges(db, clients, [subject]);
  return { changed, published };
}
