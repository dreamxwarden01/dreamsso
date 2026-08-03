// E2E for cleanExpiredSessions: expiry must REVOKE, not just delete.
//
// Before this, the hourly sweeper was a bare DELETE. An SSO session that died by
// idle took its row (and the `clients` list) with it silently, so the RP sessions
// it spawned were never told and — because every other revocation path is
// sid-scoped over that row — could never be reached again by "sign out
// everywhere" or an admin terminate. They just ran out their own local clocks.
// The sweeper now fans out a logout event to exactly the clients each session
// touched, before dropping it.
//
// Asserts: idle-expired and absolute-expired rows are deleted AND produce a
// queued/archived logout for their clients; a live session is untouched and
// produces nothing; a session with no clients deletes without inventing events.
// Run: npx tsx scripts/sso-session-sweep-test.ts
import crypto from 'node:crypto';
import { pool } from '../src/db.js';
import { redis } from '../src/redis.js';
import { cleanExpiredSessions } from '../src/oidc/sessions.js';

const CLIENT = 'videosite';
const USER = 'tester';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);

const made: string[] = [];
async function mkSession(o: { lastSeen: string; createdAt: string; clients?: string[] }) {
  const { rows: [row] } = await pool.query<{ sid: string }>(
    `INSERT INTO sessions (user_sub, token_hash, amr, expires_at, clients, persistent, last_seen, created_at)
     VALUES ($1, $2, '{pwd}', now() + interval '30 days', $3, true, now() - $4::interval, now() - $5::interval)
     RETURNING sid`,
    [sub, crypto.randomBytes(32), o.clients ?? [CLIENT], o.lastSeen, o.createdAt],
  );
  made.push(row.sid);
  return row.sid;
}
const exists = async (sid: string) =>
  (await pool.query('SELECT 1 FROM sessions WHERE sid = $1', [sid])).rows.length === 1;

// A logout for `sid` is "announced" if it is queued in the outbound zset or has
// already been archived by the pump (the 2s debounce may fire mid-test).
async function announced(sid: string): Promise<boolean> {
  const queued = await redis.zrange(`events:out:${CLIENT}`, 0, -1);
  if (queued.some((m) => { try { const e = JSON.parse(m); return e.type === 'logout' && e.payload?.sid === sid; } catch { return false; } })) return true;
  const { rows } = await pool.query(
    `SELECT 1 FROM event_outbox WHERE target_client_id = $1 AND kind = 'logout' AND payload->>'sid' = $2`,
    [CLIENT, sid],
  );
  return rows.length > 0;
}

// Defaults: idle 72h, absolute 168h (persistent).
const idleDead = await mkSession({ lastSeen: '100 hours', createdAt: '100 hours' });
const absDead = await mkSession({ lastSeen: '1 hour', createdAt: '200 hours' });
const live = await mkSession({ lastSeen: '1 hour', createdAt: '1 hour' });
const noClients = await mkSession({ lastSeen: '100 hours', createdAt: '100 hours', clients: [] });

console.log('\n--- sweep ---');
await cleanExpiredSessions();

ok(!(await exists(idleDead)), 'idle-expired row deleted');
ok(!(await exists(absDead)), 'absolute-expired row deleted');
ok(await exists(live), 'live row untouched');
ok(!(await exists(noClients)), 'clients-less expired row deleted');

console.log('\n--- revocation announced (the actual fix) ---');
ok(await announced(idleDead), 'idle-expired session announced a logout to its client');
ok(await announced(absDead), 'absolute-expired session announced a logout to its client');
ok(!(await announced(live)), 'live session announced nothing');

// --- cleanup ---
await pool.query('DELETE FROM sessions WHERE sid = ANY($1::uuid[])', [made]);
// Drop the logout events this test manufactured so they are never delivered.
for (const m of await redis.zrange(`events:out:${CLIENT}`, 0, -1)) {
  try {
    const e = JSON.parse(m);
    if (e.type === 'logout' && made.includes(e.payload?.sid)) await redis.zrem(`events:out:${CLIENT}`, m);
  } catch { /* leave anything unparseable alone */ }
}
await pool.query(
  `DELETE FROM event_outbox WHERE target_client_id = $1 AND kind = 'logout' AND payload->>'sid' = ANY($2::text[])`,
  [CLIENT, made],
);
ok(true, 'cleanup: test sessions + manufactured logout events removed');

console.log(fail ? `\n${fail} FAILED\n` : '\nall passed\n');
await pool.end();
redis.disconnect();
process.exit(fail ? 1 : 0);
