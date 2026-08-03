// E2E for the RP half of activity reporting, driven through a REAL videosite
// login (which also exercises the refactored exchangeCode/signClientAssertion).
//
// Proves the whole loop: browsing videosite keeps the SSO session's idle window
// alive, and does so at most once per coalescing window rather than per request.
//
//   1. log in to videosite via OIDC          -> app session bound to an SSO sid
//   2. first request                         -> report fires
//   3. backdate the SSO session's last_seen
//   4. request INSIDE the window             -> must NOT report (coalescing)
//   5. drop the window key, request again    -> reports, last_seen back to ~now
//
// Run: npx tsx scripts/sso-activity-rp-test.ts
import { execFileSync } from 'node:child_process';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const VS = 'https://stream-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const jar: Record<string, string> = {};
const absorb = (res: Response) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
};
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');

async function videositeLogin(): Promise<boolean> {
  for (const k of Object.keys(jar)) delete jar[k];
  let r = await fetch(VS + '/auth/login', { redirect: 'manual' });
  absorb(r);
  const authorize = r.headers.get('location')!;
  r = await fetch(authorize, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf);
  const cb = new URL(r.headers.get('location')!);
  r = await fetch(`${VS}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code')!)}&state=${encodeURIComponent(cb.searchParams.get('state')!)}`,
    { redirect: 'manual', headers: { cookie: cookie() } });
  absorb(r);
  return !!jar.sid;
}

const hit = () => fetch(VS + '/api/me', { headers: { cookie: cookie() } });
const redisDel = (key: string) =>
  execFileSync('docker', ['exec', 'dreamsso-redis-1', 'redis-cli', '-n', '1', 'DEL', key]).toString().trim();

const lastSeenOf = async (sid: string) => (await pool.query<{ last_seen: Date }>(
  'SELECT last_seen FROM sessions WHERE sid = $1', [sid])).rows[0]?.last_seen;
const backdate = (sid: string, interval: string) =>
  pool.query(`UPDATE sessions SET last_seen = now() - $2::interval WHERE sid = $1`, [sid, interval]);

console.log('\n--- login (exercises exchangeCode + signClientAssertion) ---');
ok(await videositeLogin(), 'videosite OIDC login succeeded (sid cookie set)');
if (!jar.sid) { console.log('\ncannot continue without a session\n'); await pool.end(); process.exit(1); }
const appSid = jar.sid;

// The SSO session this login bound to (most recent for tester that lists videosite).
const { rows: [sess] } = await pool.query<{ sid: string }>(
  `SELECT s.sid FROM sessions s JOIN identities i ON i.sub = s.user_sub
    WHERE i.username = $1 AND 'videosite' = ANY(s.clients)
    ORDER BY s.created_at DESC LIMIT 1`, [USER]);
ok(!!sess, 'SSO session found and lists videosite in clients[]');
const ssoSid = sess.sid;

console.log('\n--- sso_sid reached the app session ---');
const cached = execFileSync('docker',
  ['exec', 'dreamsso-redis-1', 'redis-cli', '-n', '1', 'HGET', `videosite:session:user:${appSid}`, 'sso_sid'])
  .toString().trim();
ok(cached === ssoSid, 'videosite cached sso_sid matches the SSO session', cached || '(empty)');

console.log('\n--- reporting ---');
await hit();                       // first request after login -> report fires
await new Promise((r) => setTimeout(r, 1200)); // fire-and-forget; let it land
await backdate(ssoSid, '2 hours');
const stale = await lastSeenOf(ssoSid);

// Inside the 5-minute window: must NOT report.
await hit();
await new Promise((r) => setTimeout(r, 1200));
const afterCoalesced = await lastSeenOf(ssoSid);
ok(afterCoalesced!.getTime() === stale!.getTime(),
  'a request inside the window does NOT report (coalesced)', afterCoalesced?.toISOString());

// Drop the window key -> next request reports for real.
redisDel(`videosite:sso:activity:${appSid}`);
await hit();
await new Promise((r) => setTimeout(r, 1500));
const revived = await lastSeenOf(ssoSid);
ok(revived!.getTime() > stale!.getTime(), 'after the window, browsing videosite advances the SSO last_seen',
  `${stale?.toISOString()} -> ${revived?.toISOString()}`);
ok(Math.abs(revived!.getTime() - Date.now()) < 60_000, 'last_seen is ~now (idle window is genuinely shared)');

// The payoff: an SSO session that vanished (idle-swept before the sweeper learned
// to announce, or revoked while we were unreachable) used to strand the RP
// session forever — nothing was left to fan out from. Now the next report gets a
// signed 410 and the RP hangs up on itself. Destroys the session, so it runs last.
// NB: /api/me is deliberately public — it answers 200 {user:null} when signed
// out — so identity is read from the body, not the status code.
const whoami = async () => (await (await hit()).json()).user;
console.log('\n--- revocation backstop: SSO session gone -> RP terminates itself ---');
ok((await whoami()) !== null, 'still signed in before the SSO session disappears');
await pool.query('DELETE FROM sessions WHERE sid = $1', [ssoSid]);
redisDel(`videosite:sso:activity:${appSid}`);
await hit();                                   // reports -> 410 + signed verdict
await new Promise((r) => setTimeout(r, 1500)); // fire-and-forget; let it terminate
ok((await whoami()) === null, 'RP session terminated after a verified 410');
const leftover = execFileSync('docker',
  ['exec', 'dreamsso-redis-1', 'redis-cli', '-n', '1', 'EXISTS', `videosite:session:user:${appSid}`])
  .toString().trim();
ok(leftover === '0', 'app session cleared from Redis too', `EXISTS=${leftover}`);

console.log(fail ? `\n${fail} FAILED\n` : '\nall passed\n');
await pool.end();
process.exit(fail ? 1 : 0);
