import type pg from 'pg';
import { insertEvents, lockEventDestinations, MAX_ATTEMPTS, type EventQuery } from './outboxStore.js';
import { publishRoleChanges } from '../rbac/roleChanges.js';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const SUPERSEDED = 'superseded_by_reconcile';
const OUTCOMES = new Set(['delivered','http_rejected','delivery_failed','signing_failed','event_too_large','destination_unavailable','paused','recovered']);
export class ClientDeliveryError extends Error {
  constructor(readonly status: number, readonly code: string) { super(code); }
}
interface Client { client_id: string; disabled_at: Date | null; events_uri: string | null; is_system: boolean }
export interface RecoveryResult { logout_requeued: number; role_snapshots: number; role_superseded: number; other_retained: number }
function count(value: unknown): number {
  const n = Number(value);
  if (!Number.isSafeInteger(n) || n < 0) throw new Error('delivery_count_unavailable');
  return n;
}
async function clientForUpdate(db: pg.PoolClient, id: string): Promise<Client> {
  // NO KEY UPDATE remains compatible with outbox producers' FK key-share locks.
  const { rows: [client] } = await db.query<Client>(
    'SELECT client_id,disabled_at,events_uri,is_system FROM oauth_clients WHERE client_id=$1 FOR NO KEY UPDATE', [id]);
  if (!client) throw new ClientDeliveryError(404, 'not_found');
  return client;
}
const endpointReady = (client: Client) => !!client.events_uri?.trim();

/** Aggregate metadata only: no user identities, payloads, URLs or proof material. */
export async function readClientDelivery(db: EventQuery, clientId: string) {
  const { rows: [row] } = await db.query(`SELECT c.disabled_at,c.events_uri,
      d.last_outcome_code,d.last_outcome_at,
      totals.pending,totals.dead,totals.delivered
    FROM oauth_clients c LEFT JOIN event_destinations d USING(client_id)
    LEFT JOIN LATERAL (SELECT
      count(*) FILTER(WHERE status='pending') AS pending,
      count(*) FILTER(WHERE status='dead' AND last_error_code IS DISTINCT FROM $2) AS dead,
      count(*) FILTER(WHERE status='delivered') AS delivered
      FROM event_outbox WHERE target_client_id=c.client_id) totals ON true
    WHERE c.client_id=$1`, [clientId, SUPERSEDED]);
  if (!row) throw new ClientDeliveryError(404, 'not_found');
  const state = row.disabled_at ? 'paused' : row.events_uri?.trim() ? 'ready' : 'unconfigured';
  const pending = count(row.pending);
  return {
    state,
    counts: { pending: state === 'ready' ? pending : 0, paused: state === 'ready' ? 0 : pending,
      dead: count(row.dead), delivered: count(row.delivered) },
    last_outcome: row.last_outcome_code ? {
      code: OUTCOMES.has(row.last_outcome_code) ? row.last_outcome_code : 'unknown_error',
      at: row.last_outcome_at ? new Date(row.last_outcome_at).toISOString() : null,
    } : null,
    can_recover: state === 'ready',
  };
}

/** Caller owns the role-write transaction. Reconcile truth, not historical grants. */
async function reconcileClientDelivery(db: pg.PoolClient, client: Client): Promise<RecoveryResult> {
  await lockEventDestinations(db, [client.client_id]);
  // Fence old worker settlement. A request already on the wire cannot be unsent;
  // the fresh role revision still orders any later replay at the receiver.
  await db.query(`UPDATE event_destinations SET lease_token=NULL,lease_until=NULL,
    failures=0,next_attempt_at=now() WHERE client_id=$1`, [client.client_id]);
  const { rows: [catalog] } = await db.query('SELECT client_id FROM app_role_catalogs WHERE client_id=$1', [client.client_id]);
  const { rows: [priorRoles] } = await db.query(`SELECT count(*) AS n FROM event_outbox
    WHERE target_client_id=$1 AND kind='account.roles_change' AND status IN ('pending','dead')
      AND last_error_code IS DISTINCT FROM $2`, [client.client_id, SUPERSEDED]);
  // A missing previously-managed catalog is a recovery problem, not permission
  // to replay old grants or invent a new authority lineage.
  if (!catalog && count(priorRoles.n)) throw new ClientDeliveryError(409, 'role_catalog_unavailable');

  const { rowCount: superseded } = await db.query(`UPDATE event_outbox SET status='dead',last_error_code=$2
    WHERE target_client_id=$1 AND kind='account.roles_change' AND status IN ('pending','dead')
      AND last_error_code IS DISTINCT FROM $2`, [client.client_id, SUPERSEDED]);
  await db.query(`UPDATE event_outbox SET status='dead',last_error_code='invalid_logout_payload'
    WHERE target_client_id=$1 AND kind='logout' AND status='pending' AND NOT COALESCE(
      jsonb_typeof(payload->'sub')='string' AND jsonb_typeof(payload->'sid')='string'
      AND payload->>'sub' ~* $2 AND payload->>'sid' ~* $2,false)`, [client.client_id, UUID.source]);
  // Give previously exhausted logout facts a small renewed budget, so a
  // deterministic rejection cannot block fresh snapshots for another 50 tries.
  // Ordinary pending facts keep the full budget; IDs, payloads and FIFO stay put.
  const { rowCount: logouts } = await db.query(`UPDATE event_outbox SET status='pending',
    attempts=CASE WHEN status='dead' THEN $3::int ELSE 0 END,
    next_attempt_at=now(),last_error_code=NULL WHERE target_client_id=$1 AND kind='logout'
      AND status IN ('pending','dead') AND jsonb_typeof(payload->'sub')='string'
      AND jsonb_typeof(payload->'sid')='string'
      AND payload->>'sub' ~* $2 AND payload->>'sid' ~* $2`, [client.client_id, UUID.source, MAX_ATTEMPTS - 3]);
  // Refresh known display metadata from current storage, not from old payloads.
  // Restrict profile reconciliation to subjects already in this client's queue.
  const profiles = (await db.query<{ sub: string }>(`SELECT DISTINCT lower(payload->>'sub') AS sub
    FROM event_outbox WHERE target_client_id=$1 AND kind='account.profile_change'
      AND status IN ('pending','dead') AND last_error_code IS DISTINCT FROM $3
      AND jsonb_typeof(payload->'sub')='string' AND payload->>'sub' ~* $2`, [client.client_id, UUID.source, SUPERSEDED])).rows;
  const metadata = [];
  if (profiles.length) {
    const subjects = profiles.map(row => row.sub);
    const current = (await db.query<{ sub: string; avatar: string | null }>(
      'SELECT sub::text,avatar FROM identities WHERE sub=ANY($1::uuid[]) AND deleted_at IS NULL', [subjects])).rows;
    const avatars = new Map(current.map(row => [row.sub, row.avatar]));
    await db.query(`UPDATE event_outbox SET status='dead',last_error_code=$3 WHERE target_client_id=$1
      AND kind='account.profile_change' AND status IN ('pending','dead')
      AND lower(payload->>'sub')=ANY($2::text[])`, [client.client_id, subjects, SUPERSEDED]);
    metadata.push(...subjects.map(sub => ({ type: 'account.profile_change', payload: { sub, avatar: avatars.get(sub) ?? null } })));
  }
  const settings = await db.query(`UPDATE event_outbox SET status='dead',last_error_code=$2
    WHERE target_client_id=$1 AND kind='org.settings' AND status IN ('pending','dead')
      AND last_error_code IS DISTINCT FROM $2 RETURNING id`, [client.client_id, SUPERSEDED]);
  if (settings.rows.length) {
    const name = (await db.query<{ value: string }>("SELECT value FROM settings WHERE key='site_name'")).rows[0]?.value ?? 'DreamSSO';
    metadata.push({ type: 'org.settings', payload: { site_name: name } });
  }
  await db.query(`UPDATE event_outbox SET status='dead',last_error_code=$2
    WHERE target_client_id=$1 AND kind='roles.sync_request' AND status IN ('pending','dead')`, [client.client_id, SUPERSEDED]);
  // Pending non-role notifications retain FIFO intent and can retry immediately;
  // unsupported/malformed dead letters are not blindly resurrected.
  await db.query(`UPDATE event_outbox SET attempts=0,next_attempt_at=now(),last_error_code=NULL
    WHERE target_client_id=$1 AND status='pending' AND kind NOT IN ('account.roles_change','logout')`, [client.client_id]);
  const snapshots = catalog ? await publishRoleChanges(db, [client.client_id], null, { force: true }) : 0;
  if (metadata.length) await insertEvents(db, client.client_id, metadata);
  if (!client.is_system) await insertEvents(db, client.client_id, [{ type: 'roles.sync_request', payload: {} }]);
  const { rows: [remaining] } = await db.query(`SELECT count(*) AS n FROM event_outbox
    WHERE target_client_id=$1 AND status='dead' AND last_error_code IS DISTINCT FROM $2`, [client.client_id, SUPERSEDED]);
  await db.query(`UPDATE event_destinations SET last_outcome_code='recovered',last_outcome_at=clock_timestamp(),
    last_recovered_at=clock_timestamp(),next_attempt_at=now() WHERE client_id=$1`, [client.client_id]);
  return { logout_requeued: logouts ?? 0, role_snapshots: snapshots, role_superseded: superseded ?? 0,
    other_retained: count(remaining.n) };
}

/** Duplicate requests return their committed result without reissuing grants. */
export async function recoverClientDelivery(db: pg.PoolClient, clientId: string, actor: string, requestId: string): Promise<RecoveryResult> {
  if (!UUID.test(actor) || !UUID.test(requestId)) throw new ClientDeliveryError(422, 'invalid_recovery_request');
  const client = await clientForUpdate(db, clientId);
  const { rows: [prior] } = await db.query<{ requested_by: string; result: RecoveryResult }>(
    'SELECT requested_by,result FROM event_recoveries WHERE client_id=$1 AND request_id=$2', [clientId, requestId]);
  if (prior) {
    if (prior.requested_by !== actor.toLowerCase()) throw new ClientDeliveryError(409, 'recovery_context_mismatch');
    return prior.result;
  }
  if (client.disabled_at) throw new ClientDeliveryError(409, 'client_disabled');
  if (!endpointReady(client)) throw new ClientDeliveryError(409, 'no_events_endpoint');
  const result = await reconcileClientDelivery(db, client);
  await db.query('INSERT INTO event_recoveries(client_id,request_id,requested_by,result) VALUES($1,$2,$3,$4)',
    [clientId, requestId, actor, JSON.stringify(result)]);
  return result;
}

/** Enable is an idempotent lifecycle operation; queued recovery shares its commit. */
export async function setClientEnabled(db: pg.PoolClient, clientId: string, enabled: boolean): Promise<void> {
  const client = await clientForUpdate(db, clientId);
  if (!enabled && client.is_system) throw new ClientDeliveryError(409, 'system_client');
  if (enabled === !client.disabled_at) return;
  await lockEventDestinations(db, [clientId]);
  await db.query('UPDATE oauth_clients SET disabled_at=CASE WHEN $2 THEN NULL ELSE now() END WHERE client_id=$1', [clientId, enabled]);
  await db.query(`UPDATE event_destinations SET lease_token=NULL,lease_until=NULL,
    next_attempt_at=now() WHERE client_id=$1`, [clientId]);
  if (enabled && endpointReady(client)) await reconcileClientDelivery(db, { ...client, disabled_at: null });
}

/** Used after a saved endpoint changes, on the same client/role-write transaction. */
export async function reconcileChangedEndpoint(db: pg.PoolClient, clientId: string): Promise<void> {
  const client = await clientForUpdate(db, clientId);
  await lockEventDestinations(db, [clientId]);
  await db.query('UPDATE event_destinations SET lease_token=NULL,lease_until=NULL,next_attempt_at=now() WHERE client_id=$1', [clientId]);
  if (!client.disabled_at && endpointReady(client)) await reconcileClientDelivery(db, client);
}
