import crypto from 'node:crypto';
import { SignJWT } from 'jose';
import { pool } from './db.js';
import { redis } from './redis.js';
import { getSigningKey } from './keys.js';
import { s2sFetch } from './s2sFetch.js';
import { config } from './config.js';

// Outbound event pump (SSO -> RP). Hybrid store, per the channel design:
//   Redis  events:out:<client_id>  zset — the PENDING queue; score = due time,
//          so retry_after is just the member's score. events:out-dests tracks
//          which destinations may have work.
//   DB     event_outbox — the delivered/dead ARCHIVE (admin visibility +
//          audit; delivered rows pruned after 30 days).
// Delivery: one signed-JWT envelope per destination carrying events[] (batch).
// Triggers: 2s debounce after the first enqueue, a 60s sweep (which IS the
// retry mechanism — failed events just get a future score), and a boot drain.
// Loss model: an event enqueued after its DB commit can be lost in a crash
// window / Redis restart; every type on this channel is self-healing (logout
// is bounded by RP session TTLs, role sync is full-state + boot sync).

const DEBOUNCE_MS = 2000;
const SWEEP_MS = 60_000;
const BATCH_MAX = 100;
const MAX_ATTEMPTS = 50; // ~2 days at the backoff cap -> dead-letter
const COALESCE_TYPES = new Set(['roles.sync_request']); // only the latest matters

const outKey = (clientId: string) => `events:out:${clientId}`;
const DESTS_KEY = 'events:out-dests';

export interface OutboundEvent {
  type: string;
  payload: Record<string, unknown>;
}
interface PendingEvent extends OutboundEvent {
  id: string;
  attempts: number;
  created_at: number;
}

export async function enqueueEvents(clientId: string, events: OutboundEvent[]): Promise<void> {
  const key = outKey(clientId);
  const now = Date.now();
  for (const e of events) {
    if (COALESCE_TYPES.has(e.type)) {
      for (const m of await redis.zrange(key, 0, -1)) {
        try {
          if ((JSON.parse(m) as PendingEvent).type === e.type) await redis.zrem(key, m);
        } catch {
          await redis.zrem(key, m);
        }
      }
    }
    const pending: PendingEvent = { id: crypto.randomUUID(), type: e.type, payload: e.payload, attempts: 0, created_at: now };
    await redis.zadd(key, now, JSON.stringify(pending));
  }
  await redis.sadd(DESTS_KEY, clientId);
  kickDrain();
}

// One in-process debounce timer: the first enqueue arms it; everything that
// lands within the 2s window rides the same drain.
let debounce: NodeJS.Timeout | null = null;
export function kickDrain(): void {
  if (debounce) return;
  debounce = setTimeout(() => {
    debounce = null;
    drainAll().catch((e) => console.warn('event drain failed:', (e as Error).message));
  }, DEBOUNCE_MS);
  debounce.unref?.();
}

const backoffMs = (attempts: number) =>
  Math.min(60_000 * 2 ** Math.max(0, attempts - 1), 3_600_000) + Math.floor(Math.random() * 15_000);

export async function drainAll(): Promise<void> {
  const dests: string[] = await redis.smembers(DESTS_KEY);
  await Promise.allSettled(dests.map((d) => drainDest(d)));
}

async function archive(clientId: string, ev: PendingEvent, status: 'delivered' | 'dead'): Promise<void> {
  await pool.query(
    `INSERT INTO event_outbox (id, kind, target_client_id, payload, status, attempts, next_attempt_at, delivered_at)
       VALUES ($1, $2, $3, $4, $5, $6, now(), CASE WHEN $5 = 'delivered' THEN now() END)
     ON CONFLICT (id) DO UPDATE
       SET status = EXCLUDED.status, attempts = EXCLUDED.attempts, delivered_at = EXCLUDED.delivered_at`,
    [ev.id, ev.type, clientId, JSON.stringify(ev.payload), status, ev.attempts],
  ).catch((e) => console.warn('event archive failed:', (e as Error).message));
}

async function drainDest(clientId: string): Promise<void> {
  const key = outKey(clientId);
  const members = await redis.zrangebyscore(key, 0, Date.now(), 'LIMIT', 0, BATCH_MAX);
  if (!members.length) {
    if ((await redis.zcard(key)) === 0) await redis.srem(DESTS_KEY, clientId);
    return;
  }
  const parsed: { m: string; ev: PendingEvent }[] = [];
  for (const m of members) {
    try {
      parsed.push({ m, ev: JSON.parse(m) as PendingEvent });
    } catch {
      await redis.zrem(key, m); // corrupt member — drop
    }
  }
  if (!parsed.length) return;

  const { rows: [client] } = await pool.query<{ events_uri: string | null; disabled_at: string | null }>(
    'SELECT events_uri, disabled_at FROM oauth_clients WHERE client_id = $1',
    [clientId],
  );
  if (!client || !client.events_uri || client.disabled_at) {
    // Nowhere to deliver — dead-letter (visible in the archive), don't spin.
    for (const { m, ev } of parsed) {
      await redis.zrem(key, m);
      await archive(clientId, ev, 'dead');
    }
    return;
  }

  const { kid, privateKey } = await getSigningKey();
  const now = Math.floor(Date.now() / 1000);
  const token = await new SignJWT({
    events: parsed.map(({ ev }) => ({ id: ev.id, type: ev.type, payload: ev.payload })),
  })
    .setProtectedHeader({ alg: 'EdDSA', kid, typ: 'events+jwt' })
    .setIssuer(config.issuer)
    .setAudience(clientId)
    .setIssuedAt(now)
    .setExpirationTime(now + 120)
    .setJti(crypto.randomUUID())
    .sign(privateKey);

  let ok = false;
  try {
    // s2sFetch presents the mTLS client certificate when enforcement is on.
    const r = await s2sFetch(client.events_uri, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ event_token: token }),
      signal: AbortSignal.timeout(5000),
    });
    ok = r.ok;
    if (!ok) console.warn(`events -> ${clientId}: HTTP ${r.status}`);
  } catch (e) {
    console.warn(`events -> ${clientId} failed:`, (e as Error).message);
  }

  for (const { m, ev } of parsed) {
    await redis.zrem(key, m);
    if (ok) {
      await archive(clientId, ev, 'delivered');
    } else {
      ev.attempts += 1;
      if (ev.attempts >= MAX_ATTEMPTS) {
        await archive(clientId, ev, 'dead');
      } else {
        await redis.zadd(key, Date.now() + backoffMs(ev.attempts), JSON.stringify(ev));
      }
    }
  }
  // More already due (batch overflow)? Keep going.
  if (ok && (await redis.zcount(key, 0, Date.now())) > 0) return drainDest(clientId);
}

async function cleanupArchive(): Promise<void> {
  await pool.query(`DELETE FROM event_outbox WHERE status = 'delivered' AND delivered_at < now() - interval '30 days'`);
  await pool.query(`DELETE FROM processed_events WHERE processed_at < now() - interval '7 days'`);
}

// Boot drain (catches everything accumulated while down) + the 60s retry
// sweep + hourly archive pruning. Called once from server main().
export function startEventPump(): void {
  drainAll().catch((e) => console.warn('event boot drain failed:', (e as Error).message));
  setInterval(() => {
    drainAll().catch((e) => console.warn('event sweep failed:', (e as Error).message));
  }, SWEEP_MS).unref();
  setInterval(() => {
    cleanupArchive().catch((e) => console.warn('event archive cleanup failed:', (e as Error).message));
  }, 3_600_000).unref();
}
