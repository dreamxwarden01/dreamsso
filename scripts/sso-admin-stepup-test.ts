// E2E for the /admin API step-up gap fix: with stepup_admin_required ON, a
// session without a fresh sudo window can still read (GETs pass) but every
// mutation is refused with 403 step_up_required; with the door OFF the same
// request reaches normal validation (422). No state is mutated — the probe
// mutation is an empty client-create that would fail validation anyway.
// Run: npx tsx scripts/sso-admin-stepup-test.ts
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const setCookie = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};
const setDoor = async (v: string) => {
  await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', $1)
    ON CONFLICT (key) DO UPDATE SET value = $1`, [v]);
  await new Promise((r) => setTimeout(r, 5500)); // outwait the settings cache
};

// --- snapshot + setup ---
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
await setDoor('true');

// --- password-only admin login (amr ['pwd'] never pre-clears the window) ---
let r = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrfForm = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
});
const cookie = 'sso_session=' + setCookie(r, 'sso_session');
r = await answerKmsi(SSO, r, txn, csrfForm, { cookie });
const api = (method: string, path: string, csrf?: string, body?: unknown) =>
  fetch(SSO + path, {
    method,
    headers: {
      cookie,
      ...(csrf ? { 'x-csrf-token': csrf } : {}),
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

// 1. GETs pass with a stale window (the door gates powers, not reads)
r = await api('GET', '/admin/api/me');
const me = (await r.json()) as { csrf: string };
ok(r.status === 200 && !!me.csrf, '1. GET /admin/api/me passes without a fresh window', `(${r.status})`);
const csrf = me.csrf;
r = await api('GET', '/admin/api/keys');
ok(r.status === 200, '1a. GET keys passes too');

// 2. mutation with door ON + stale window -> refused BEFORE validation
r = await api('POST', '/admin/api/clients', csrf, {});
ok(r.status === 403 && (await r.json()).error === 'step_up_required',
   '2. mutation with stale window -> 403 step_up_required');

// 3. door OFF -> the same request reaches validation (422)
await setDoor('false');
r = await api('POST', '/admin/api/clients', csrf, {});
ok(r.status === 422 && !!(await r.json()).errors, '3. door off -> same request hits validation (422)');

// --- restore ---
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
if (suOrig[0]) {
  await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
} else {
  await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
