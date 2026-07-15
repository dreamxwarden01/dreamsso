// E2E for the SSO admin panel backend:
//   local login (/admin/start-login txn -> session, no OIDC client)
//   authz (401 unauthenticated, 403 without org.siteSettings.sso)
//   CSRF (mutations rejected without the /admin/api/me token)
//   client registry CRUD + lifecycle (create/dup/validate/edit/disable/enable/delete-guard)
//   disabled-client rejection at /authorize (styled page) and /token
//   jwks_uri end-to-end: test hosts a JWKS on loopback, full code->token flow
//   styled error pages (unknown client, expired txn)
// Run: npx tsx scripts/sso-admin-test.ts
import http from 'node:http';
import crypto from 'node:crypto';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const TESTAPP = 'testapp-admin-e2e';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';

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

// --- cleanup from any previous crashed run ---
await pool.query('DELETE FROM oauth_clients WHERE client_id = $1', [TESTAPP]);
// This suite tests the admin panel, not the step-up door — disable it for the run
// (tester has no strong factors; the door is covered by sso-stepup-test.ts).
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await new Promise((r) => setTimeout(r, 5500)); // outwait the settings cache
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const grantAdmin = () =>
  pool.query(
    `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
       ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
const revokeAdmin = () =>
  pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
await revokeAdmin();

// 0. front doors
let r = await fetch(SSO + '/', { redirect: 'manual' });
ok(r.status === 302 && (r.headers.get('location') || '').includes('account-dev'), '0. GET / -> account portal');
r = await fetch(SSO + '/admin', { redirect: 'manual' });
ok(r.status === 302 && (r.headers.get('location') || '') === '/admin/start-login', '0a. GET /admin no session -> login bounce');

// 1. unauthenticated
r = await fetch(SSO + '/admin/api/clients');
ok(r.status === 401, '1. no session -> 401', `(${r.status})`);

// 2. local login via /admin/start-login
r = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
const loginLoc = r.headers.get('location') || '';
ok(r.status === 302 && loginLoc.startsWith('/login?txn='), '2. start-login -> /login?txn', `(${loginLoc.split('?')[0]})`);
const txn = new URL(loginLoc, SSO).searchParams.get('txn')!;
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const page = await r.text();
const csrfForm = (page.match(/name="csrf" value="([^"]+)"/) || [])[1];
ok(page.includes('DreamSSO Admin'), '2a. login page shows DreamSSO Admin as the app');
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
});
const cookie = 'sso_session=' + setCookie(r, 'sso_session'); // transient cookie on the KMSI page
r = await answerKmsi(SSO, r, txn, csrfForm, { cookie }); // "Stay signed in?" -> /admin
ok(r.status === 302 && (r.headers.get('location') || '') === '/admin' && cookie.length > 20,
   '2b. local login -> session + redirect /admin', `(-> ${r.headers.get('location')})`);

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

// 3. authenticated but no permission
r = await api('GET', '/admin/api/me');
ok(r.status === 403 && (await r.json()).error === 'permission_denied', '3. standard_user -> 403 permission_denied', `(${r.status})`);
r = await fetch(SSO + '/admin', { headers: { cookie } });
ok(r.status === 403 && (await r.text()).includes('permission_denied'), '3a. GET /admin without perm -> styled denial');

// 4. grant + me + csrf
await grantAdmin();
// The shell ships an EMPTY <title> (site name arrives via /api/settings/public),
// so assert the built SPA structurally: root div + hashed asset bundle.
r = await fetch(SSO + '/admin', { headers: { cookie } });
const shell = await r.text();
ok(r.status === 200 && shell.includes('id="root"') && shell.includes('/admin/assets/'),
   '4. GET /admin with perm -> SPA shell');
r = await api('GET', '/admin/api/me');
const me = await r.json();
ok(r.status === 200 && me.username === USER && !!me.csrf, '4a. with perm -> me + csrf token');
const csrf = me.csrf as string;

// 5. list
r = await api('GET', '/admin/api/clients');
const list = (await r.json()).clients || [];
ok(r.status === 200 && list.some((c: { client_id: string }) => c.client_id === 'videosite') &&
   list.some((c: { client_id: string }) => c.client_id === 'account'),
   '5. clients list has videosite + account', `(${list.length})`);

// 6. mutation without csrf
r = await api('POST', '/admin/api/clients', undefined, { client_id: 'x1', name: 'x' });
ok(r.status === 403 && (await r.json()).error === 'csrf_failed', '6. mutation without csrf -> 403 csrf_failed');

// 7. create (jwks_uri served by this test on loopback)
const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
// Unique kid per run: the SSO caches the remote JWKS per (client, url) and only
// refetches on an UNKNOWN kid — which is exactly how real rotation works (new key
// = new thumbprint kid). Reusing a kid with different key material would pin the
// stale key from the previous run.
const pubJwk = await exportJWK(publicKey);
pubJwk.kid = 'testapp-key-' + Date.now(); pubJwk.alg = 'EdDSA'; pubJwk.use = 'sig';
const jwksServer = http.createServer((_q, s) => {
  s.setHeader('content-type', 'application/json');
  s.end(JSON.stringify({ keys: [pubJwk] }));
});
await new Promise<void>((resolve) => jwksServer.listen(8899, '127.0.0.1', resolve));

const HOST = 'stream-dev.dreamxwarden.ca';
// Unique URL per run: the SSO's remote-JWKS cache is per (client, url) with a
// refetch cooldown — a fresh URL (like a real re-registration) gets a fresh fetch.
const JWKS_URI = 'http://127.0.0.1:8899/jwks.json?run=' + Date.now();
const base = {
  name: 'Admin E2E App', is_first_party: true, entry_policy: 'opt_in',
  hostname: HOST, redirect_paths: ['/auth/callback'], events_path: null,
  jwks_uri: JWKS_URI, jwks: null, allowed_scopes: ['openid', 'profile'],
};
r = await api('POST', '/admin/api/clients', csrf, { client_id: TESTAPP, ...base });
ok(r.status === 201, '7. create client (hostname+paths) with jwks_uri -> 201', `(${r.status})`);
// The registration-time fetch is kept as an inline snapshot (feeds the edit
// form's paste view; saving in paste mode would pin it and clear the uri).
let snap = (await (await api('GET', '/admin/api/clients')).json()).clients
  .find((c: { client_id: string }) => c.client_id === TESTAPP);
ok(!!snap.jwks_uri && snap.jwks?.keys?.[0]?.kid === pubJwk.kid,
   '7d. fetched JWKS stored as inline snapshot alongside the uri');

// 8. duplicate + bad slug + missing key
r = await api('POST', '/admin/api/clients', csrf, { client_id: TESTAPP, ...base });
ok(r.status === 409 && (await r.json()).error === 'client_id_taken', '8. duplicate client_id -> 409');
r = await api('POST', '/admin/api/clients', csrf, { client_id: 'Bad_Slug!', ...base });
ok(r.status === 422 && !!(await r.json()).errors?.client_id, '8a. invalid slug -> 422');
r = await api('POST', '/admin/api/clients', csrf, { client_id: 'nokey-app', ...base, jwks_uri: null });
ok(r.status === 422 && !!(await r.json()).errors?.jwks, '8b. no key material -> 422');
r = await api('POST', '/admin/api/clients', csrf, { client_id: 'deadkey-app', ...base, jwks_uri: 'http://127.0.0.1:8898/jwks.json' });
ok(r.status === 422 && !!(await r.json()).errors?.jwks_uri, '8c. unreachable jwks_uri -> 422 (registration confirms the fetch)');

// 9. edit + normalization (shared-module rules enforced server-side)
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { name: 'Admin E2E App v2' });
ok(r.status === 204, '9. PATCH name -> 204', `(${r.status})`);
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { hostname: `HTTPS://Stream-Dev.dreamxwarden.ca/junk\\path` });
let cl = (await (await api('GET', '/admin/api/clients')).json()).clients
  .find((c: { client_id: string }) => c.client_id === TESTAPP);
ok(r.status === 204 && cl.hostname === HOST && cl.redirect_uris[0] === REDIRECT,
   '9a. pasted full-URL hostname normalized + URLs recomposed', `(${cl.hostname})`);
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { events_path: `https://${HOST}/api/backchannel-logout` });
cl = (await (await api('GET', '/admin/api/clients')).json()).clients
  .find((c: { client_id: string }) => c.client_id === TESTAPP);
ok(r.status === 204 && cl.events_path === '/api/backchannel-logout',
   '9b. same-host full URL in path field -> stripped to path', `(${cl.events_path})`);
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { redirect_paths: ['https://evil.example.com/cb'] });
ok(r.status === 422 && !!(await r.json()).errors?.['redirect_paths.0'], '9c. foreign-host path -> 422 (not silently stripped)');
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { hostname: HOST + ':8443' });
ok(r.status === 422 && !!(await r.json()).errors?.hostname, '9d. port in hostname -> 422');

// 9e/9f. key-mode flips: paste-mode save pins keys + disables fetch; a fetch-mode
// save re-enables it (re-verified + snapshot refreshed).
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { jwks: { keys: [pubJwk] }, jwks_uri: null });
snap = (await (await api('GET', '/admin/api/clients')).json()).clients
  .find((c: { client_id: string }) => c.client_id === TESTAPP);
ok(r.status === 204 && snap.jwks_uri === null && snap.has_inline_jwks,
   '9e. paste-mode save -> fetch off, keys pinned inline');
const JWKS_URI_2 = 'http://127.0.0.1:8899/jwks.json?run2=' + Date.now();
r = await api('PATCH', '/admin/api/clients/' + TESTAPP, csrf, { jwks_uri: JWKS_URI_2 });
snap = (await (await api('GET', '/admin/api/clients')).json()).clients
  .find((c: { client_id: string }) => c.client_id === TESTAPP);
ok(r.status === 204 && snap.jwks_uri === JWKS_URI_2 && snap.jwks?.keys?.[0]?.kid === pubJwk.kid,
   '9f. fetch-mode save -> fetch back on, snapshot refreshed');

// 10. jwks_uri end-to-end: full code -> token using the remote key
async function runFlow(clientId: string) {
  const v = crypto.randomBytes(32).toString('base64url');
  const chall = crypto.createHash('sha256').update(v).digest('base64url');
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: clientId, redirect_uri: REDIRECT, scope: 'openid profile',
    state: 'x', nonce: 'y', code_challenge: chall, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let rr = await fetch(u, { redirect: 'manual' });
  if (rr.status !== 302 || !(rr.headers.get('location') || '').includes('/login?txn=')) {
    return { status: rr.status, page: await rr.text() };
  }
  const t = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
  rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(t));
  const cs = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  rr = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn: t, csrf: cs, username: USER, password: PASS }),
  });
  rr = await answerKmsi(SSO, rr, t, cs); // "Stay signed in?" -> code
  const code = new URL(rr.headers.get('location')!).searchParams.get('code')!;
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: pubJwk.kid as string })
    .setIssuer(clientId).setSubject(clientId).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(privateKey);
  rr = await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: v,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  return { status: rr.status, body: await rr.json().catch(() => ({})) };
}
const flow = await runFlow(TESTAPP);
ok(flow.status === 200 && !!(flow as { body?: { id_token?: string } }).body?.id_token,
   '10. jwks_uri client completes code -> token', `(${flow.status})`);

// 11. lifecycle: delete guard -> disable -> rejected at authorize+token -> enable
r = await api('DELETE', '/admin/api/clients/' + TESTAPP, csrf);
ok(r.status === 409 && (await r.json()).error === 'must_disable_first', '11. delete while enabled -> 409');
r = await api('POST', `/admin/api/clients/${TESTAPP}/disable`, csrf);
ok(r.status === 204, '11a. disable -> 204');
const disabledFlow = await runFlow(TESTAPP);
ok(disabledFlow.status === 403 && String((disabledFlow as { page?: string }).page).includes('client_disabled'),
   '11b. disabled client -> styled denial at /authorize', `(${disabledFlow.status})`);
const fakeAssertion = 'x.' + Buffer.from(JSON.stringify({ iss: TESTAPP })).toString('base64url') + '.y';
r = await fetch(SSO + '/token', {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code', code: 'x', redirect_uri: REDIRECT, code_verifier: 'x',
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: fakeAssertion,
  }),
});
ok(r.status === 401 && (await r.json()).error_description === 'client disabled', '11c. disabled client -> 401 at /token');
r = await api('POST', `/admin/api/clients/${TESTAPP}/enable`, csrf);
ok(r.status === 204, '11d. enable -> 204');

// 12. styled error pages
r = await fetch(SSO + '/authorize?client_id=no-such-app&redirect_uri=' + encodeURIComponent(REDIRECT));
ok(r.status === 400 && (await r.text()).includes('unknown_client'), '12. unknown client -> styled page');
r = await fetch(SSO + '/login?txn=garbage');
ok(r.status === 400 && (await r.text()).includes('txn_expired'), '12a. expired txn -> styled page');

// 13. keys + settings
r = await api('GET', '/admin/api/keys');
const keys = await r.json();
ok(r.status === 200 && keys.keys?.length >= 1 && keys.jwks?.keys?.length >= 1, '13. keys view');
r = await api('GET', '/admin/api/settings');
ok(r.status === 200 && (await r.json()).issuer === SSO, '13a. settings view');

// cleanup: disable -> delete -> revoke perm
await api('POST', `/admin/api/clients/${TESTAPP}/disable`, csrf);
r = await api('DELETE', '/admin/api/clients/' + TESTAPP, csrf);
ok(r.status === 204, '14. disabled delete -> 204 (cleanup)');
await revokeAdmin();
if (suOrig[0]) {
  await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
} else {
  await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
}
jwksServer.close();

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
