import crypto from 'node:crypto';
import type pg from 'pg';

// Dependencies are explicit: this module imports no application pool or Redis.
export interface EventQuery {
  query(sql: string, values?: unknown[]): Promise<{ rows: Record<string, any>[]; rowCount?: number | null }>;
}
export interface OutboundEvent {
  type: string;
  payload: Record<string, unknown>;
  version?: string;
  id?: string;
}
export interface WireEvent { id: string; type: string; payload: Record<string, unknown> }
export const BATCH_MAX = 100;
export const EVENT_BYTES_MAX = 64 * 1024;
export const LEGACY_MEMBER_BYTES_MAX = 256 * 1024;
export const MAX_ATTEMPTS = 50;
export const LEASE_MS = 30_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const MAX_BIGINT = 9_223_372_036_854_775_807n;

export class OutboxError extends Error {
  constructor(readonly code: string) { super(code); }
}
const objectPayload = (v: unknown): v is Record<string, unknown> =>
  v !== null && typeof v === 'object' && !Array.isArray(v);
export const eventBytes = (events: readonly WireEvent[]): number => Buffer.byteLength(JSON.stringify(events), 'utf8');

function normalizedEvent(event: OutboundEvent): WireEvent & { version: string } {
  const id = event.id ?? crypto.randomUUID();
  const version = event.version ?? '0';
  if (typeof id !== 'string' || !UUID.test(id) || typeof event.type !== 'string' || !event.type || event.type.length > 200 ||
      !objectPayload(event.payload) || typeof version !== 'string' || !/^(0|[1-9][0-9]{0,18})$/.test(version) || BigInt(version) > MAX_BIGINT) {
    throw new OutboxError('invalid_event');
  }
  // Freeze JSON before any await; callers cannot mutate an in-flight enqueue.
  let payload: Record<string, unknown>;
  try { payload = JSON.parse(JSON.stringify(event.payload)); } catch { throw new OutboxError('invalid_event'); }
  if (!objectPayload(payload)) throw new OutboxError('invalid_event');
  const wire = { id, type: event.type, payload };
  if (eventBytes([wire]) > EVENT_BYTES_MAX) throw new OutboxError('event_too_large');
  return { ...wire, version };
}

// Caller owns the transaction. A conflicting ID never overwrites stored bytes.
export async function insertEvents(db: EventQuery, clientId: string, events: readonly OutboundEvent[]): Promise<string[]> {
  const normalized = events.map(normalizedEvent);
  if (normalized.length) await lockDestination(db, clientId);
  for (const event of normalized) {
    const values = [event.id, event.type, clientId, JSON.stringify(event.payload), event.version];
    const inserted = await db.query(
      `INSERT INTO event_outbox (id,kind,target_client_id,payload,version)
       VALUES ($1,$2,$3,$4::jsonb,$5::bigint) ON CONFLICT (id) DO NOTHING RETURNING id`, values);
    if (!inserted.rows.length) {
      const existing = await db.query(
        `SELECT id FROM event_outbox WHERE id=$1 AND kind=$2 AND target_client_id=$3
           AND payload=$4::jsonb AND version=$5::bigint`, values);
      if (!existing.rows.length) throw new OutboxError('event_id_conflict');
    }
  }
  return normalized.map(e => e.id);
}

async function lockDestination(db: EventQuery, clientId: string): Promise<void> {
  await db.query(`INSERT INTO event_destinations (client_id) VALUES ($1) ON CONFLICT (client_id) DO NOTHING`, [clientId]);
  // Allocate sequence only after obtaining this lock, so commit order for one
  // destination cannot invert two producers or race a worker's visible prefix.
  await db.query('SELECT client_id FROM event_destinations WHERE client_id=$1 FOR UPDATE', [clientId]);
}

export interface PendingRow extends WireEvent { attempts: number; due: boolean }
export interface DestinationClaim {
  clientId: string; token: string; uri: string | null; disabled: boolean; failures: number; events: PendingRow[];
}
export type Settlement = { kind: 'delivered' } | { kind: 'retry'; code: string; delayMs: number } | { kind: 'dead'; code: string };
export interface DeliveryStore {
  destinations(limit: number): Promise<string[]>;
  claim(clientId: string): Promise<DestinationClaim | null>;
  renew(claim: DestinationClaim): Promise<boolean>;
  settle(claim: DestinationClaim, ids: readonly string[], outcome: Settlement): Promise<boolean>;
}

export class PostgresOutboxStore implements DeliveryStore {
  constructor(private readonly database: pg.Pool) {}

  async destinations(limit = 32): Promise<string[]> {
    const { rows } = await this.database.query(
      `SELECT d.client_id FROM event_destinations d
       WHERE d.next_attempt_at<=now() AND (d.lease_until IS NULL OR d.lease_until<=clock_timestamp())
         AND EXISTS (SELECT 1 FROM event_outbox e WHERE e.target_client_id=d.client_id AND e.status='pending')
       ORDER BY d.next_attempt_at,d.client_id LIMIT $1`, [Math.min(Math.max(limit, 1), 64)]);
    return rows.map(r => r.client_id as string);
  }

  async claim(clientId: string): Promise<DestinationClaim | null> {
    const db = await this.database.connect();
    try {
      await db.query('BEGIN');
      await db.query("SET LOCAL lock_timeout='5s'");
      await db.query("SET LOCAL statement_timeout='15s'");
      const token = crypto.randomUUID();
      const { rows: [destination] } = await db.query(
        `UPDATE event_destinations SET lease_token=$2,lease_until=clock_timestamp()+($3::int*interval '1 millisecond')
         WHERE client_id=$1 AND next_attempt_at<=now() AND (lease_until IS NULL OR lease_until<=clock_timestamp())
         RETURNING failures`, [clientId, token, LEASE_MS]);
      if (!destination) { await db.query('COMMIT'); return null; }
      const { rows: [client] } = await db.query('SELECT events_uri,disabled_at FROM oauth_clients WHERE client_id=$1', [clientId]);
      const { rows } = await db.query(
        `SELECT id,kind AS type,payload,attempts,next_attempt_at<=now() AS due
         FROM event_outbox WHERE target_client_id=$1 AND status='pending'
         ORDER BY sequence LIMIT $2`, [clientId, BATCH_MAX]);
      if (!rows.length || !rows[0].due) {
        await this.release(db, clientId, token, Number(destination.failures));
        await db.query('COMMIT');
        return null;
      }
      await db.query('COMMIT');
      return { clientId, token, uri: client?.events_uri ?? null, disabled: !client || client.disabled_at !== null,
        failures: Number(destination.failures), events: rows as PendingRow[] };
    } catch (e) { await db.query('ROLLBACK').catch(() => {}); throw e; }
    finally { db.release(); }
  }

  async renew(claim: DestinationClaim): Promise<boolean> {
    // Changed endpoints wait for a fresh claim. An expired lease cannot revive.
    const { rowCount } = await this.database.query(
      `UPDATE event_destinations d SET lease_until=clock_timestamp()+($3::int*interval '1 millisecond')
       WHERE d.client_id=$1 AND d.lease_token=$2 AND d.lease_until>clock_timestamp()
         AND EXISTS (SELECT 1 FROM oauth_clients c WHERE c.client_id=d.client_id
           AND c.disabled_at IS NULL AND c.events_uri=$4)`,
      [claim.clientId, claim.token, LEASE_MS, claim.uri]);
    return rowCount === 1;
  }

  async settle(claim: DestinationClaim, ids: readonly string[], outcome: Settlement): Promise<boolean> {
    const db = await this.database.connect();
    try {
      await db.query('BEGIN');
      await db.query("SET LOCAL lock_timeout='5s'");
      await db.query("SET LOCAL statement_timeout='15s'");
      const { rows } = await db.query(
        `SELECT client_id FROM event_destinations WHERE client_id=$1 AND lease_token=$2 AND lease_until>clock_timestamp() FOR UPDATE`,
        [claim.clientId, claim.token]);
      if (!rows.length) { await db.query('ROLLBACK'); return false; }
      if (outcome.kind === 'delivered') {
        await db.query(
          `UPDATE event_outbox SET status='delivered',delivered_at=now(),last_error_code=NULL
           WHERE target_client_id=$1 AND id=ANY($2::uuid[]) AND status='pending'`, [claim.clientId, [...ids]]);
      } else if (outcome.kind === 'dead') {
        await db.query(
          `UPDATE event_outbox SET status='dead',last_error_code=$3
           WHERE target_client_id=$1 AND id=ANY($2::uuid[]) AND status='pending'`, [claim.clientId, [...ids], outcome.code]);
      } else {
        await db.query(
          `UPDATE event_outbox SET attempts=attempts+1,
             status=CASE WHEN attempts+1 >= $3 THEN 'dead' ELSE 'pending' END,
             next_attempt_at=now()+($4::int*interval '1 millisecond'),last_error_code=$5
           WHERE target_client_id=$1 AND id=ANY($2::uuid[]) AND status='pending'`,
          [claim.clientId, [...ids], MAX_ATTEMPTS, outcome.delayMs, outcome.code]);
      }
      await this.release(db, claim.clientId, claim.token, outcome.kind === 'retry' ? Math.min(claim.failures + 1, MAX_ATTEMPTS) : 0);
      await db.query('COMMIT');
      return true;
    } catch (e) { await db.query('ROLLBACK').catch(() => {}); throw e; }
    finally { db.release(); }
  }

  private async release(db: pg.PoolClient, clientId: string, token: string, failures: number): Promise<void> {
    await db.query(
      `UPDATE event_destinations SET lease_token=NULL,lease_until=NULL,failures=$3,
         next_attempt_at=COALESCE((SELECT next_attempt_at FROM event_outbox
           WHERE target_client_id=$1 AND status='pending' ORDER BY sequence LIMIT 1),now())
       WHERE client_id=$1 AND lease_token=$2`, [clientId, token, failures]);
  }
}

export const backoffMs = (failures: number, random = Math.random): number =>
  Math.min(60_000 * 2 ** Math.min(Math.max(0, failures - 1), 6), 3_600_000) + Math.floor(random() * 15_000);

export interface DeliveryDependencies {
  store: DeliveryStore;
  sign(clientId: string, events: readonly WireEvent[]): Promise<string>;
  send(uri: string, token: string): Promise<number>;
  random?: () => number;
  report?(code: string): void;
}
export function boundedBatch(rows: readonly PendingRow[]): WireEvent[] {
  const batch: WireEvent[] = [];
  // A rejected batch does not identify its bad member. Retry the oldest row
  // alone so an invalid event cannot exhaust every healthy neighbor's budget.
  const limit = (rows[0]?.attempts ?? 0) > 0 ? 1 : BATCH_MAX;
  for (const row of rows.slice(0, limit)) {
    if (!row.due) break; // Never bypass a delayed predecessor.
    const event = { id: row.id, type: row.type, payload: row.payload };
    if (eventBytes([...batch, event]) > EVENT_BYTES_MAX) break;
    batch.push(event);
  }
  return batch;
}

export async function deliverDestination(deps: DeliveryDependencies, clientId: string): Promise<boolean> {
  const claim = await deps.store.claim(clientId);
  if (!claim) return false;
  const batch = boundedBatch(claim.events);
  if (!batch.length) {
    if (claim.events[0]?.due) await deps.store.settle(claim, [claim.events[0].id], { kind: 'dead', code: 'event_too_large' });
    return false;
  }
  const ids = batch.map(e => e.id);
  if (!claim.uri || claim.disabled) {
    await deps.store.settle(claim, ids, { kind: 'dead', code: 'destination_unavailable' });
    return false;
  }
  let token: string;
  try { token = await deps.sign(clientId, batch); }
  catch {
    await deps.store.settle(claim, ids, { kind: 'retry', code: 'signing_failed', delayMs: backoffMs(claim.failures + 1, deps.random) });
    return false;
  }
  if (!(await deps.store.renew(claim))) return false;
  let outcome: Settlement;
  try {
    const status = await deps.send(claim.uri, token);
    // All registered receiver implementations acknowledge completed events with
    // 204. A 200 HTML edge response is not proof that an application received it.
    outcome = status === 204 ? { kind: 'delivered' }
      : { kind: 'retry', code: 'http_rejected', delayMs: backoffMs(claim.failures + 1, deps.random) };
  } catch {
    outcome = { kind: 'retry', code: 'delivery_failed', delayMs: backoffMs(claim.failures + 1, deps.random) };
  }
  // A lease cannot fence an HTTP request already in flight. Late completion
  // cannot settle another owner's rows; repeated deliveries keep the same ID.
  const settled = await deps.store.settle(claim, ids, outcome);
  if (!settled) deps.report?.('lease_lost');
  return settled && outcome.kind === 'delivered';
}

export const SUCCESS_CLAIMS_PER_PASS = 8;
export async function drainDestination(deps: DeliveryDependencies, clientId: string): Promise<void> {
  // Recover isolated healthy heads immediately after an outage, without
  // putting them back in poison batches or monopolizing this worker forever.
  for (let i = 0; i < SUCCESS_CLAIMS_PER_PASS; i++) {
    if (!(await deliverDestination(deps, clientId))) break;
  }
}

export interface LegacyEvent extends WireEvent {
  attempts: number; createdAt: Date; dueAt: Date; member: string; score: number;
}
export function parseLegacyEvent(member: string, rawScore: string): LegacyEvent {
  if (Buffer.byteLength(member, 'utf8') > LEGACY_MEMBER_BYTES_MAX) throw new OutboxError('legacy_member_too_large');
  let value: Record<string, unknown>;
  try { value = JSON.parse(member); } catch { throw new OutboxError('legacy_member_invalid'); }
  const score = Number(rawScore);
  if (!objectPayload(value) || typeof value.id !== 'string' || !UUID.test(value.id) ||
      typeof value.type !== 'string' || !value.type || value.type.length > 200 || !objectPayload(value.payload) ||
      !Number.isSafeInteger(value.attempts) || Number(value.attempts) < 0 || Number(value.attempts) > 2147483647 ||
      !Number.isSafeInteger(value.created_at) || Number(value.created_at) < 0 ||
      !Number.isFinite(score) || score < 0 || !Number.isFinite(new Date(score).getTime()) ||
      !Number.isFinite(new Date(Number(value.created_at)).getTime())) throw new OutboxError('legacy_member_invalid');
  if (value.type !== 'account.roles_change' && eventBytes([{ id: value.id, type: value.type, payload: value.payload }]) > EVENT_BYTES_MAX) {
    throw new OutboxError('legacy_event_too_large');
  }
  return { id: value.id, type: value.type, payload: value.payload, attempts: Number(value.attempts),
    createdAt: new Date(Number(value.created_at)), dueAt: new Date(score), member, score };
}

// The caller also persists a fresh role replacement before committing. The
// original role payload and Redis bytes remain a terminal migration receipt.
export async function insertLegacyEvent(db: EventQuery, clientId: string, event: LegacyEvent): Promise<boolean> {
  await lockDestination(db, clientId);
  const replaced = event.type === 'account.roles_change';
  const values = [event.id, event.type, clientId, JSON.stringify(event.payload), event.attempts,
    event.dueAt, event.createdAt, replaced ? 'dead' : 'pending', replaced ? 'legacy_role_replaced' : null, event.member, event.score];
  const { rows } = await db.query(
    `INSERT INTO event_outbox (id,kind,target_client_id,payload,attempts,next_attempt_at,created_at,status,last_error_code,legacy_redis_member,legacy_redis_score)
     VALUES ($1,$2,$3,$4::jsonb,$5,$6,$7,$8,$9,$10,$11) ON CONFLICT (id) DO NOTHING RETURNING id`, values);
  if (!rows.length) {
    const { rows: existing } = await db.query(
      `SELECT id,status FROM event_outbox WHERE id=$1 AND kind=$2 AND target_client_id=$3 AND payload=$4::jsonb FOR UPDATE`, values.slice(0, 4));
    if (!existing.length) throw new OutboxError('legacy_id_conflict');
    if (replaced && existing[0].status === 'pending') {
      await db.query(`UPDATE event_outbox SET status='dead',last_error_code='legacy_role_replaced',
        legacy_redis_member=COALESCE(legacy_redis_member,$2),legacy_redis_score=COALESCE(legacy_redis_score,$3) WHERE id=$1`,
      [event.id, event.member, event.score]);
      return true;
    }
    return false;
  }
  return true;
}

export interface LegacyRedis {
  scan(cursor: string, ...args: string[]): Promise<[string, string[]]>;
  sscan(key: string, cursor: string, ...args: string[]): Promise<[string, string[]]>;
  zscan(key: string, cursor: string, ...args: string[]): Promise<[string, string[]]>;
  zrem(key: string, member: string): Promise<number>;
}
export function createLegacyImporter(deps: {
  redis: LegacyRedis;
  persist(clientId: string, event: LegacyEvent): Promise<void>;
  report(code: string, digest: string): void;
}): () => Promise<void> {
  let keyCursor = '0';
  let setCursor = '0';
  const pendingKeys = new Set<string>();
  const memberCursors = new Map<string, string>();
  let busy = false;
  return async () => {
    if (busy) return;
    busy = true;
    try {
      const keys = await deps.redis.scan(keyCursor, 'MATCH', 'events:out:*', 'COUNT', '16');
      keyCursor = keys[0];
      for (const key of keys[1]) pendingKeys.add(key);
      const destinations = await deps.redis.sscan('events:out-dests', setCursor, 'COUNT', '16');
      setCursor = destinations[0];
      for (const id of destinations[1]) pendingKeys.add(`events:out:${id}`);
      for (const key of [...pendingKeys].slice(0, 16)) {
        pendingKeys.delete(key);
        const clientId = key.slice('events:out:'.length);
        const [cursor, members] = await deps.redis.zscan(key, memberCursors.get(key) ?? '0', 'COUNT', '100');
        memberCursors.set(key, cursor);
        if (cursor !== '0') pendingKeys.add(key);
        // COUNT is a hint: consume the complete page, including compact sets
        // that return slightly more than 100, rather than dropping a tail.
        for (let i = 0; i < members.length; i += 2) {
          const member = members[i];
          try {
            const event = parseLegacyEvent(member, members[i + 1]);
            await deps.persist(clientId, event); // Committed before it returns.
            await deps.redis.zrem(key, member);
          } catch (error) {
            deps.report(error instanceof OutboxError ? error.code : 'legacy_import_failed',
              crypto.createHash('sha256').update(member).digest('hex'));
          }
        }
        if (cursor === '0') memberCursors.delete(key);
      }
    } finally { busy = false; }
  };
}
