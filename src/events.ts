import crypto from 'node:crypto';
import { SignJWT } from 'jose';
import { pool } from './db.js';
import { redis } from './redis.js';
import { getSigningKey } from './keys.js';
import { s2sFetch } from './s2sFetch.js';
import { config } from './config.js';
import {
  createLegacyImporter, drainDestination, insertEvents, insertLegacyEvent,
  OutboxError, PostgresOutboxStore, type OutboundEvent, type LegacyRedis,
} from './events/outboxStore.js';
export type { OutboundEvent } from './events/outboxStore.js';

// PostgreSQL owns pending events and retry outcomes. Redis is read only during
// legacy import; all new enqueues are durable before their caller returns.
// Domain mutations need insertEvents on their own transaction. This standalone
// wrapper does not make unrelated logout/avatar/settings mutations atomic.
export async function enqueueEvents(clientId: string, events: OutboundEvent[]): Promise<void> {
  const db = await pool.connect();
  try {
    await db.query('BEGIN');
    await insertEvents(db, clientId, events);
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK').catch(() => {}); throw error; }
  finally { db.release(); }
  kickDrain();
}

const DEBOUNCE_MS = 2000;
const SWEEP_MS = 60_000;
let debounce: NodeJS.Timeout | null = null;
let draining = false;
let started = false;
const report = (code: string): void => { console.warn(`event pump: ${code}`); };

export function kickDrain(): void {
  if (debounce) return;
  debounce = setTimeout(() => {
    debounce = null;
    drainAll().catch(() => report('drain_failed'));
  }, DEBOUNCE_MS);
  debounce.unref?.();
}

export async function drainAll(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    const store = new PostgresOutboxStore(pool);
    const destinations = await store.destinations(32);
    for (let i = 0; i < destinations.length; i += 4) {
      const results = await Promise.allSettled(destinations.slice(i, i + 4).map(clientId => drainDestination({
        store,
        async sign(destination, events) {
          const { kid, privateKey } = await getSigningKey();
          const now = Math.floor(Date.now() / 1000);
          return new SignJWT({ events }).setProtectedHeader({ alg: 'EdDSA', kid, typ: 'events+jwt' })
            .setIssuer(config.issuer).setAudience(destination).setIssuedAt(now)
            .setExpirationTime(now + 120).setJti(crypto.randomUUID()).sign(privateKey);
        },
        async send(uri, token) {
          const response = await s2sFetch(uri, {
            method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
            body: new URLSearchParams({ event_token: token }), signal: AbortSignal.timeout(5000),
          });
          await response.body?.cancel().catch(() => {});
          return response.status;
        },
        report,
      }, clientId)));
      if (results.some(r => r.status === 'rejected')) report('destination_failed');
    }
    // Backoff and active leases are filtered in SQL, so successful overflow
    // continues after debounce without spinning on failed destinations.
    if ((await store.destinations(1)).length) kickDrain();
  } finally { draining = false; }
}

const legacyRedis: LegacyRedis = {
  // Read the live Redis binding on each call, including installer reconnects.
  scan: (cursor, ...args) => redis.scan(cursor, ...args as ['MATCH', string, 'COUNT', string]),
  sscan: (key, cursor, ...args) => redis.sscan(key, cursor, ...args as ['COUNT', string]),
  zscan: (key, cursor, ...args) => redis.zscan(key, cursor, ...args as ['COUNT', string]),
  zrem: (key, member) => redis.zrem(key, member),
};
const importLegacy = createLegacyImporter({
  redis: legacyRedis,
  async persist(clientId, event) {
    const { withRoleTransaction, publishRoleChanges } = await import('./rbac/roleChanges.js');
    await withRoleTransaction(async db => {
      const inserted = await insertLegacyEvent(db, clientId, event);
      if (inserted && event.type === 'account.roles_change') {
        const sub = event.payload.sub;
        if (typeof sub !== 'string' || !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(sub)) {
          throw new OutboxError('legacy_role_subject_invalid');
        }
        if (await publishRoleChanges(db, [clientId], [sub], { force: true }) !== 1) {
          throw new OutboxError('legacy_role_unavailable');
        }
      }
    });
  },
  report(code, digest) { console.warn(`event import: ${code} member_sha256=${digest}`); },
});

async function cleanupArchive(): Promise<void> {
  await pool.query(`DELETE FROM event_outbox WHERE id IN (
    SELECT id FROM event_outbox WHERE status='delivered' AND delivered_at<now()-interval '30 days' LIMIT 1000)`);
  await pool.query(`DELETE FROM processed_events WHERE (source,id) IN (
    SELECT source,id FROM processed_events WHERE processed_at<now()-interval '7 days' LIMIT 1000)`);
}

export function startEventPump(): void {
  if (started) return;
  started = true;
  const sweep = (): void => {
    drainAll().catch(() => report('sweep_failed'));
    // Redis availability cannot block current DB delivery. Exact old members
    // are removed only after their database transaction commits.
    importLegacy().then(kickDrain).catch(() => report('legacy_import_unavailable'));
  };
  sweep();
  setInterval(sweep, SWEEP_MS).unref();
  setInterval(() => { cleanupArchive().catch(() => report('cleanup_failed')); }, 3_600_000).unref();
}
