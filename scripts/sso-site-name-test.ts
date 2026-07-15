// E2E for the org-name handover (phase 3):
//   SSO admin changes site_name -> org.settings event -> videosite sso_org_name
//   videosite /api/me carries org_name + email + account_portal (dropdown data)
//   request-role-sync -> videosite's roles.sync now carries ITS site name ->
//     oauth_clients.name updated (app owns its display name)
// State: snapshots + restores SSO site_name, oauth_clients.name, admin door.
// Run: npx tsx scripts/sso-site-name-test.ts
import { execSync } from 'node:child_process';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const STREAM = 'https://stream-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const TEST_NAME = 'Org Renamed E2E';

const sql = (q: string) =>
  execSync(`docker exec -i dreamsso-videosite-db-1 sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" videosite -N' 2>/dev/null`, { input: q })
    .toString().trim();

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

// --- snapshots ---
const { rows: [{ value: origSiteName }] } = await pool.query<{ value: string }>(
  `SELECT COALESCE((SELECT value FROM settings WHERE key = 'site_name'), 'DreamSSO') AS value`);
const { rows: [{ name: origClientName }] } = await pool.query<{ name: string }>(
  `SELECT name FROM oauth_clients WHERE client_id = 'videosite'`);
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await new Promise((r) => setTimeout(r, 5500));
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);

// --- admin login ---
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
    headers: { cookie, ...(csrf ? { 'x-csrf-token': csrf } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
const csrf = ((await (await api('GET', '/admin/api/me')).json()) as { csrf: string }).csrf;

// 1. change site_name -> broadcast
r = await api('PUT', '/admin/api/settings', csrf, { site_name: TEST_NAME });
ok(r.status === 204, '1. site_name changed via admin', `(${r.status})`);
let mirrored = false;
for (let i = 0; i < 15 && !mirrored; i++) {
  if (sql(`SELECT setting_value FROM site_settings WHERE setting_key='sso_org_name';`) === TEST_NAME) mirrored = true;
  else await new Promise((res) => setTimeout(res, 1000));
}
ok(mirrored, '2. org.settings event mirrored into videosite sso_org_name');

// 3. videosite /api/me carries the dropdown data
{
  const jar: Record<string, string> = {};
  const absorb = (res: Response) => {
    for (const c of res.headers.getSetCookie?.() ?? []) {
      const nv = c.split(';')[0];
      const i = nv.indexOf('=');
      if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
    }
  };
  const ck = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
  let rr = await fetch(STREAM + '/auth/login', { redirect: 'manual' });
  absorb(rr);
  rr = await fetch(rr.headers.get('location')!, { redirect: 'manual' });
  const t = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
  rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(t));
  const cs = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  rr = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn: t, csrf: cs, username: USER, password: PASS }),
  });
  rr = await answerKmsi(SSO, rr, t, cs);
  rr = await fetch(rr.headers.get('location')!, { redirect: 'manual', headers: { cookie: ck() } });
  absorb(rr);
  rr = await fetch(STREAM + '/api/me', { headers: { cookie: ck() } });
  const me = (await rr.json()) as { user: { org_name: string; email: string | null; account_portal: string } };
  ok(me.user?.org_name === TEST_NAME, '3. /api/me org_name', `(${me.user?.org_name})`);
  ok(me.user?.email === 'tester@example.com', '3a. /api/me email', `(${me.user?.email})`);
  ok(!!me.user?.account_portal, '3b. /api/me account_portal', `(${me.user?.account_portal})`);
}

// 4. app -> SSO: roles.sync carries videosite's own name into the registry
const vsOwnName = sql(`SELECT COALESCE((SELECT setting_value FROM site_settings WHERE setting_key='site_name'), 'VideoSite');`);
await pool.query(`UPDATE oauth_clients SET name = 'placeholder-e2e' WHERE client_id = 'videosite'`);
r = await api('POST', '/admin/api/clients/videosite/request-role-sync', csrf);
ok(r.status === 204, '4. request-role-sync -> 204', `(${r.status})`);
let named = false;
for (let i = 0; i < 15 && !named; i++) {
  const { rows: [{ name }] } = await pool.query(`SELECT name FROM oauth_clients WHERE client_id = 'videosite'`);
  if (name === vsOwnName) named = true;
  else await new Promise((res) => setTimeout(res, 1000));
}
ok(named, '4a. oauth_clients.name updated from the app report', `(${vsOwnName})`);

// --- restore ---
r = await api('PUT', '/admin/api/settings', csrf, { site_name: origSiteName });
ok(r.status === 204, '5. site_name restored', `(${origSiteName})`);
let restored = false;
for (let i = 0; i < 15 && !restored; i++) {
  if (sql(`SELECT setting_value FROM site_settings WHERE setting_key='sso_org_name';`) === origSiteName) restored = true;
  else await new Promise((res) => setTimeout(res, 1000));
}
ok(restored, '5a. videosite mirror restored');
await pool.query(`UPDATE oauth_clients SET name = $1 WHERE client_id = 'videosite'`, [origClientName]);
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
if (suOrig[0]) {
  await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
} else {
  await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
