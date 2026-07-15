// E2E for the settings + email module:
//   settings PUT/GET roundtrip; token write-only (sealed at rest, never echoed)
//   sendEmail against a MOCK Cloudflare API (cf_api_base override) — asserts the
//   bearer token, account path, and payload; success + rejection paths
//   GET / redirect follows the account_portal_url setting
// Run: npx tsx scripts/sso-email-test.ts
import http from 'node:http';
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

// admin login (tester + temporary org.siteSettings.sso grant)
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);

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
const me = await (await fetch(SSO + '/admin/api/me', { headers: { cookie } })).json();
const csrf = me.csrf as string;
const api = (method: string, path: string, body?: unknown) =>
  fetch(SSO + path, {
    method,
    headers: { cookie, 'x-csrf-token': csrf, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });

// Snapshot the RAW settings rows we touch and restore them verbatim at the end —
// including the sealed token. (A previous version of this cleanup DELETED the
// real cf_api_token; never nuke shared state a test didn't create.)
const TOUCHED = ['site_name', 'account_portal_url', 'mail_from', 'cf_account_id', 'cf_api_token', 'cf_api_base'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [TOUCHED]);
const origTokenSet = origRows.some((x) => x.key === 'cf_api_token');

// 1. settings roundtrip
r = await api('PUT', '/admin/api/settings', {
  site_name: 'DreamSSO Test', account_portal_url: 'https://account-dev.dreamxwarden.ca',
  mail_from: 'no-reply@dreamxwarden.ca', cf_account_id: 'a'.repeat(32),
  cf_api_token: 'test-secret-token-123', cf_api_base: 'http://127.0.0.1:8897',
});
ok(r.status === 204, '1. PUT settings -> 204', `(${r.status})`);
let s = await (await fetch(SSO + '/admin/api/settings', { headers: { cookie } })).json();
ok(s.site_name === 'DreamSSO Test' && s.mail_from === 'no-reply@dreamxwarden.ca' && s.cf_account_id === 'a'.repeat(32),
   '2. GET reflects the values');
ok(s.cf_token_set === true && !JSON.stringify(s).includes('test-secret-token'),
   '3. token write-only: cf_token_set, value never echoed');

// 4. sealed at rest (DB value is enc:v1:, not plaintext)
const { rows: [tok] } = await pool.query(`SELECT value FROM settings WHERE key = 'cf_api_token'`);
ok(tok?.value.startsWith('enc:v1:') && !tok.value.includes('test-secret-token'),
   '4. token sealed at rest (enc:v1:)', `(${tok?.value.slice(0, 12)}…)`);

// 5. validation
r = await api('PUT', '/admin/api/settings', { cf_account_id: 'not-hex' });
ok(r.status === 422 && !!(await r.json()).errors?.cf_account_id, '5. invalid account id -> 422');
r = await api('PUT', '/admin/api/settings', { account_portal_url: 'https://host.example.com/some/path' });
ok(r.status === 422 && !!(await r.json()).errors?.account_portal_url, '5a. portal with path -> 422 (bare hostname only)');
r = await api('PUT', '/admin/api/settings', { session_idle_hours: '101', session_max_hours: '100' });
ok(r.status === 422 && !!(await r.json()).errors?.session_max_hours, '5a2. absolute < idle -> 422 (equal is allowed)');

// 5b. public branding endpoint + live site name on the SSO's server-rendered pages
r = await fetch(SSO + '/api/settings/public');
const pub = await r.json();
ok(r.status === 200 && pub.site_name === 'DreamSSO Test', '5b. /api/settings/public reflects site_name', `(${pub.site_name})`);
r = await fetch(SSO + '/login?txn=garbage');
const errPage = await r.text();
ok(errPage.includes('DreamSSO Test'), '5c. SSO error page branded with site_name (effective immediately)');

// 6. test-email against a mock CF API — assert auth + path + payload
let seen: { auth?: string; url?: string; body?: Record<string, unknown> } = {};
let respond: 'ok' | 'reject' = 'ok';
const mock = http.createServer((q, resp) => {
  let raw = '';
  q.on('data', (c) => (raw += c));
  q.on('end', () => {
    seen = { auth: q.headers.authorization, url: q.url, body: JSON.parse(raw || '{}') };
    resp.setHeader('content-type', 'application/json');
    if (respond === 'ok') {
      resp.end(JSON.stringify({ success: true, errors: [], result: { delivered: ['x'], permanent_bounces: [], queued: [] } }));
    } else {
      resp.statusCode = 403;
      resp.end(JSON.stringify({ success: false, errors: [{ message: 'unverified sender domain' }] }));
    }
  });
});
await new Promise<void>((resolve) => mock.listen(8897, '127.0.0.1', resolve));

r = await api('POST', '/admin/api/settings/test-email', { to: 'inbox@example.com' });
ok(r.status === 204, '6. test-email via mock -> 204', `(${r.status})`);
ok(seen.auth === 'Bearer test-secret-token-123', '6a. bearer token sent (decrypted from sealed setting)');
ok(seen.url === `/client/v4/accounts/${'a'.repeat(32)}/email/sending/send`, '6b. correct endpoint path', `(${seen.url})`);
ok(seen.body?.from === '"DreamSSO Test" <no-reply@dreamxwarden.ca>' && seen.body?.to === 'inbox@example.com' &&
   typeof seen.body?.html === 'string' && (seen.body.html as string).includes('DreamSSO Test') &&
   typeof seen.body?.text === 'string' && String(seen.body?.subject).includes('DreamSSO Test'),
   '6c. payload: NAMED from ("Site" <addr>), to/subject/html/text from settings', `(${seen.body?.from})`);

// 7. rejection path surfaces the CF error
respond = 'reject';
r = await api('POST', '/admin/api/settings/test-email', { to: 'inbox@example.com' });
const rej = await r.json();
ok(r.status === 502 && rej.error === 'rejected' && rej.detail === 'unverified sender domain',
   '7. CF rejection -> 502 + detail', `(${rej.error}: ${rej.detail})`);

// 8. invalid recipient
r = await api('POST', '/admin/api/settings/test-email', { to: 'not-an-email' });
ok(r.status === 422, '8. invalid recipient -> 422');

// 9. GET / follows the account_portal_url setting
r = await api('PUT', '/admin/api/settings', { account_portal_url: 'https://portal-test.dreamxwarden.ca' });
r = await fetch(SSO + '/', { redirect: 'manual' });
ok(r.status === 302 && r.headers.get('location') === 'https://portal-test.dreamxwarden.ca',
   '9. GET / follows the setting', `(${r.headers.get('location')})`);

// 10. blank token = UNCHANGED (no empty-string-clears footgun)
r = await api('PUT', '/admin/api/settings', { cf_api_token: '' });
let after = await (await fetch(SSO + '/admin/api/settings', { headers: { cookie } })).json();
ok(r.status === 204 && after.cf_token_set === true, '10. PUT with blank token -> unchanged (still set)');

// cleanup: restore the RAW snapshot verbatim (sealed token included)
await pool.query('DELETE FROM settings WHERE key = ANY($1)', [TOUCHED]);
for (const row of origRows) {
  await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
}
await new Promise((r) => setTimeout(r, 5500)); // outwait the server's 5s settings cache (direct DB writes bypass it)
after = await (await fetch(SSO + '/admin/api/settings', { headers: { cookie } })).json();
ok(after.cf_token_set === origTokenSet, '10a. cleanup: original settings restored verbatim',
   `(token ${origTokenSet ? 'preserved' : 'absent as before'})`);
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
mock.close();

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
