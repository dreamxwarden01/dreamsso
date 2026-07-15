// E2E for org management slice 1 (dashboard + audit log + wildcard perms):
//   matchPerm semantics (*, **, terminal-only **, invalid patterns)
//   /account/org/dashboard: permission gate, counts, roles (level asc, is_system,
//     default_org_role), app catalogs, recent activity only with org.logs.view
//   /account/org/logs: keyset pagination (created_at,id), UTC ISO timestamps,
//     include_cleared, clear = soft (cleared_by/at) + itself audited
//   step-up re-check on mutations when stepup_portal_required is on
//     (403 step_up_required without a fresh x-stepup-sid)
// Uses tester via Bearer token; snapshots/restores everything it touches.
// Run: npx tsx scripts/sso-org-test.ts
import { SignJWT, importJWK } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { pool } from '../src/db.js';
import { matchPerm } from '../src/rbac/index.js';
import { answerKmsi, FORM } from './lib/kmsi.mjs';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const KEY = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url), 'utf8')));
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const cookieOf = (r: Response) =>
  (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='))?.split(';')[0] ?? null;

// --- login -> {access_token, cookie, sid} ---
async function login() {
  const v = crypto.randomBytes(32).toString('base64url');
  const chal = crypto.createHash('sha256').update(v).digest('base64url');
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: chal, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  const cookie = cookieOf(r)!;
  r = await answerKmsi(SSO, r, txn, csrf, { cookie });
  const code = new URL(r.headers.get('location')!).searchParams.get('code')!;
  const key = await importJWK(KEY, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(key);
  const tok = await (await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: v,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  })).json();
  const hash = crypto.createHash('sha256').update(cookie.split('=')[1]).digest();
  const { rows: [s] } = await pool.query('SELECT sid FROM sessions WHERE token_hash = $1', [hash]);
  return { token: tok.access_token as string, sid: s.sid as string };
}

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const setOverride = (key: string, effect: string | null) =>
  effect
    ? pool.query(
        `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, $2, $3)
           ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = $3`, [sub, key, effect])
    : pool.query('DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = $2', [sub, key]);

const SETTING_KEYS = ['stepup_portal_required'];
const { rows: origSettings } = await pool.query('SELECT key, value FROM settings WHERE key = ANY($1)', [SETTING_KEYS]);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
const testLogIds: string[] = [];
const startedAt = new Date();

try {
  // Dev now runs with the portal sudo door ON — park it for sections 2-5
  // (section 6 flips it back on deliberately); the finally block restores.
  await setDb('stepup_portal_required', 'false');
  await sleep(5500); // settings cache

  // 1. wildcard matcher semantics
  ok(matchPerm('org.*', 'org.dashboard') && !matchPerm('org.*', 'org.users.view'),
     '1. org.* matches one segment only');
  ok(matchPerm('org.*.view', 'org.logs.view') && matchPerm('org.*.view', 'org.users.view') &&
     !matchPerm('org.*.view', 'org.users.edit.password'),
     '1a. org.*.view: middle wildcard, exact depth');
  ok(matchPerm('org.**', 'org.dashboard') && matchPerm('org.**', 'org.users.edit.mfa.reset') &&
     !matchPerm('org.**', 'profile.email.change'),
     '1b. org.** matches any depth');
  ok(!matchPerm('org.**.d', 'org.a.d') && !matchPerm('org.**.d', 'org.d'),
     '1c. org.**.d invalid -> matches nothing');
  ok(!matchPerm('org.*', 'org') && !matchPerm('org.**', 'org'),
     '1d. bare prefix never matches');

  const a = await login();
  const api = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
    fetch(SSO + path, {
      method,
      headers: {
        authorization: 'Bearer ' + a.token,
        ...(body ? { 'content-type': 'application/json' } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    });

  // 2. permission gates (tester = standard_user: all org.* denied)
  let r = await api('GET', '/account/org/dashboard');
  ok(r.status === 403 && (await r.json()).error === 'permission_denied', '2. dashboard w/o perm -> permission_denied');
  r = await api('GET', '/account/org/logs');
  ok(r.status === 403, '2a. logs w/o perm -> 403');

  // 3. dashboard shape (org.dashboard only -> NO recent activity block)
  await setOverride('org.dashboard', 'grant');
  r = await api('GET', '/account/org/dashboard');
  let d = await r.json();
  ok(r.status === 200 && d.users.total >= 2 && typeof d.sessions_active === 'number',
     '3. dashboard: user + session counts', `(${d.users.total} users)`);
  ok(Array.isArray(d.roles) && d.roles[0].slug === 'superadmin' && d.roles[0].level === 0 &&
     d.roles[0].is_system === true && d.default_org_role === 'standard_user',
     '3a. roles level-asc + is_system + singular default');
  ok(d.apps.some((x: { client_id: string }) => x.client_id === 'videosite'),
     '3b. app catalogs include videosite');
  ok(!('recent' in d), '3c. recent activity omitted without org.logs.view');

  // 4. logs: seed rows spread across buckets (UTC in DB; grouping is client-side)
  await setOverride('org.logs.view', 'grant');
  // test.one must be the NEWEST log row overall (the recent-5 check) — other
  // suites leave system rows (roles.reconcile) with fresher timestamps.
  for (const [action, ago] of [['test.one', '1 second'], ['test.two', '2 days'], ['test.three', '40 days']] as const) {
    const { rows: [row] } = await pool.query(
      `INSERT INTO org_audit_log (actor_sub, actor_label, action, detail, created_at)
       VALUES ($1, 'Org Test', $2, '{"t":1}', now() - $3::interval) RETURNING id`,
      [sub, action, ago]);
    testLogIds.push(row.id);
  }
  r = await api('GET', '/account/org/dashboard');
  d = await r.json();
  ok(Array.isArray(d.recent) && d.recent.length >= 1 && d.recent.length <= 5 &&
     d.recent.some((e: { action: string }) => e.action === 'test.one'),
     '4. dashboard recent (<=5) appears with org.logs.view');

  // 4a. list: newest first, UTC ISO
  r = await api('GET', '/account/org/logs?limit=50');
  const l1 = await r.json();
  const mine = l1.entries.filter((e: { action: string }) => e.action.startsWith('test.'));
  ok(mine.length === 3 && mine[0].action === 'test.one' && mine[2].action === 'test.three',
     '4a. entries newest-first', `(${mine.map((e: { action: string }) => e.action)})`);
  ok(/\d{4}-\d{2}-\d{2}T.*(Z|\+00)/.test(String(mine[0].created_at)), '4b. timestamps UTC', `(${mine[0].created_at})`);

  // 4c. keyset pagination: no overlap, no gap
  r = await api('GET', '/account/org/logs?limit=1');
  const p1 = await r.json();
  ok(p1.entries.length === 1 && !!p1.next_cursor, '4c. page 1 + cursor');
  r = await api('GET', '/account/org/logs?limit=1&cursor=' + encodeURIComponent(p1.next_cursor));
  const p2 = await r.json();
  ok(p2.entries.length === 1 && p2.entries[0].id !== p1.entries[0].id, '4d. page 2 distinct');

  // 5. clear: perm gate, soft-hide, itself audited
  r = await api('POST', '/account/org/logs/clear', { ids: [testLogIds[0]] });
  ok(r.status === 403 && (await r.json()).error === 'permission_denied', '5. clear w/o org.logs.clear -> 403');
  await setOverride('org.logs.clear', 'grant');
  r = await api('POST', '/account/org/logs/clear', { ids: [testLogIds[0]] });
  ok(r.status === 204, '5a. clear -> 204', `(${r.status})`);
  const { rows: [cleared] } = await pool.query('SELECT cleared_at, cleared_by FROM org_audit_log WHERE id = $1', [testLogIds[0]]);
  ok(!!cleared.cleared_at && cleared.cleared_by === sub, '5b. soft-cleared with cleared_by');
  r = await api('GET', '/account/org/logs?limit=100');
  ok(!(await r.json()).entries.some((e: { id: string }) => e.id === testLogIds[0]), '5c. default list hides cleared');
  r = await api('GET', '/account/org/logs?limit=100&include_cleared=1');
  const withCleared = await r.json();
  ok(withCleared.entries.some((e: { id: string; cleared_at: string }) => e.id === testLogIds[0] && e.cleared_at),
     '5d. include_cleared shows it, marked');
  ok(withCleared.entries.some((e: { action: string }) => e.action === 'logs.clear'), '5e. the clear itself was audited');
  r = await api('POST', '/account/org/logs/clear', { ids: ['not-a-uuid'] });
  ok(r.status === 400, '5f. malformed ids -> 400');

  // 6. step-up re-check on mutations (portal switch on)
  await setDb('stepup_portal_required', 'true');
  await sleep(5500); // settings cache
  r = await api('POST', '/account/org/logs/clear', { ids: [testLogIds[1]] });
  ok(r.status === 403 && (await r.json()).error === 'step_up_required',
     '6. stale/no sudo -> step_up_required');
  await pool.query('UPDATE sessions SET stepup_at = now() WHERE sid = $1', [a.sid]);
  r = await api('POST', '/account/org/logs/clear', { ids: [testLogIds[1]] }, { 'x-stepup-sid': a.sid });
  ok(r.status === 204, '6a. fresh sudo stamp + own sid -> allowed', `(${r.status})`);
  // someone ELSE's sid must not count
  const { rows: [other] } = await pool.query(
    `SELECT sid FROM sessions WHERE user_sub <> $1 LIMIT 1`, [sub]);
  if (other) {
    r = await api('POST', '/account/org/logs/clear', { ids: [testLogIds[2]] }, { 'x-stepup-sid': other.sid });
    ok(r.status === 403, '6b. another user\'s sid -> 403');
  } else {
    ok(true, '6b. (skipped — no foreign session present)');
  }
} finally {
  await setDb('stepup_portal_required', null);
  for (const row of origSettings) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  for (const k of ['org.dashboard', 'org.logs.view', 'org.logs.clear']) await setOverride(k, null);
  // remove ONLY what this test created: seeded rows + audit rows tester produced during the run
  if (testLogIds.length) await pool.query('DELETE FROM org_audit_log WHERE id = ANY($1::uuid[])', [testLogIds]);
  await pool.query(
    `DELETE FROM org_audit_log WHERE actor_sub = $1 AND action = 'logs.clear' AND created_at >= $2`,
    [sub, startedAt]);
  await pool.query('DELETE FROM sessions WHERE user_sub = $1', [sub]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
