// E2E for the session validity model (videosite-style, settings-driven, HOURS):
//   72h idle / 168h absolute defaults; windows enforced dynamically in loadSession
//   idle-expired + absolute-expired sessions fall back to interactive /login
//   settings changes apply to LIVE sessions immediately
//   last_seen write-coalescing (60s in-process throttle)
//   cookie carries the absolute Max-Age; cleanup prunes expired rows
// Snapshots/restores the raw settings rows it touches. Run: npx tsx scripts/sso-session-ttl-test.ts
import crypto from 'node:crypto';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const authzUrl = () => {
  const p = pkce();
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: p.c, code_challenge_method: 'S256',
  }).toString();
  return u.toString();
};
const rawSetCookie = (r: Response) =>
  (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session=')) ?? '';

// settings snapshot/restore (raw rows — never nuke shared state)
const TOUCHED = ['session_idle_hours', 'session_max_hours'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [TOUCHED]);
const setDb = async (key: string, value: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [key]);
  if (value != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [key, value]);
};
const settle = () => new Promise((r) => setTimeout(r, 5500)); // outwait the 5s settings cache

async function login(): Promise<{ cookie: string; sid: string; raw: string }> {
  let r = await fetch(authzUrl(), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  // Answer "Stay signed in?" YES -> persistent session + expiring cookie (this
  // suite is about the persistent 168h window / cookie expiry).
  const transientCookie = rawSetCookie(r).split(';')[0];
  r = await answerKmsi(SSO, r, txn, csrf, { choice: 'yes', cookie: transientCookie });
  const raw = rawSetCookie(r);
  const cookie = raw.split(';')[0];
  const token = cookie.split('=')[1];
  const hash = crypto.createHash('sha256').update(token).digest();
  const { rows } = await pool.query<{ sid: string }>('SELECT sid FROM sessions WHERE token_hash = $1', [hash]);
  return { cookie, sid: rows[0].sid, raw };
}
// Does /authorize silently reuse the session (302 with code) or bounce to /login?
async function reuse(cookie: string): Promise<'silent' | 'login'> {
  const r = await fetch(authzUrl(), { redirect: 'manual', headers: { cookie } });
  const loc = r.headers.get('location') || '';
  return loc.startsWith(REDIRECT) ? 'silent' : 'login';
}

try {
  // defaults in effect
  await setDb('session_idle_hours', null);
  await setDb('session_max_hours', null);
  await settle();

  // 1. cookie Max-Age ≈ 7d absolute
  const a = await login();
  const exp = /expires=([^;]+)/i.exec(a.raw)?.[1];
  const days = exp ? (new Date(exp).getTime() - Date.now()) / 86_400_000 : 0;
  ok(days > 6.9 && days < 7.1, '1. cookie expiry ≈ 168h (absolute cap)', `(${days.toFixed(2)}d)`);
  ok((await reuse(a.cookie)) === 'silent', '1a. fresh session -> silent reuse');

  // 2. idle expiry: last_seen 96h ago (< 168h absolute, > 72h idle)
  await pool.query(`UPDATE sessions SET last_seen = now() - interval '4 days' WHERE sid = $1`, [a.sid]);
  ok((await reuse(a.cookie)) === 'login', '2. idle-expired (96h > 72h) -> interactive login');

  // 3. absolute expiry: fresh activity but created 8d ago
  const b = await login();
  await pool.query(
    `UPDATE sessions SET created_at = now() - interval '8 days', last_seen = now() WHERE sid = $1`, [b.sid]);
  ok((await reuse(b.cookie)) === 'login', '3. absolute-expired (192h > 168h) -> interactive login');

  // 4. settings apply to LIVE sessions: tighten idle to 24h, session idle 48h
  const c = await login();
  await pool.query(`UPDATE sessions SET last_seen = now() - interval '2 days' WHERE sid = $1`, [c.sid]);
  ok((await reuse(c.cookie)) === 'silent', '4. 48h-idle session valid under 72h window');
  await setDb('session_idle_hours', '24');
  await settle();
  await pool.query(`UPDATE sessions SET last_seen = now() - interval '2 days' WHERE sid = $1`, [c.sid]);
  ok((await reuse(c.cookie)) === 'login', '4a. tightened to 24h -> same session now rejected');
  await setDb('session_idle_hours', null);
  await settle();

  // 5. last_seen write-coalescing: a touch within 60s of the previous one is skipped
  const d = await login();
  ok((await reuse(d.cookie)) === 'silent', '5. touch #1 (updates last_seen)');
  await pool.query(`UPDATE sessions SET last_seen = now() - interval '10 minutes' WHERE sid = $1`, [d.sid]);
  await reuse(d.cookie); // touch #2 within 60s -> throttled, no write
  const { rows: [ls] } = await pool.query<{ age: number }>(
    `SELECT EXTRACT(EPOCH FROM (now() - last_seen))::int AS age FROM sessions WHERE sid = $1`, [d.sid]);
  ok(ls.age > 500, '5a. second touch within 60s coalesced (no DB write)', `(last_seen ${ls.age}s old)`);

  // 6. cleanup prunes rows past the windows
  await pool.query(`UPDATE sessions SET last_seen = now() - interval '30 days' WHERE sid = $1`, [d.sid]);
  const { cleanExpiredSessions } = await import('../src/oidc/sessions.js');
  await cleanExpiredSessions();
  const { rows: gone } = await pool.query('SELECT 1 FROM sessions WHERE sid = $1', [d.sid]);
  ok(gone.length === 0, '6. cleanup removed the idle-dead row');

  // tidy the test sessions
  await pool.query('DELETE FROM sessions WHERE sid = ANY($1)', [[a.sid, b.sid, c.sid]]);
} finally {
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [TOUCHED]);
  for (const row of origRows) {
    await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  }
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
