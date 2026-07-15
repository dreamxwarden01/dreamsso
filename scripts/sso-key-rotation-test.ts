// E2E for signing-key rotation + system-client guards:
//   pre-rotation: id_token/access_token signed with kid A (full code -> token flow)
//   POST /admin/api/keys/rotate (CSRF-gated) -> new current kid B, A retired
//   JWKS publishes BOTH kids; old access token still accepted at /userinfo
//   new flow signs with kid B; old id_token verifies against the published JWKS
//   system client: disable/delete 'account' -> 409 system_client
//   clients list exposes the inline public JWKS (edit-form display)
// NOTE: this performs a REAL rotation and does not undo it — that's the point:
// the retired key keeps verifying for 24h and both RPs refetch the JWKS on an
// unknown kid, so a rotation per run is harmless (one extra retired row).
// Run: npx tsx scripts/sso-key-rotation-test.ts
import http from 'node:http';
import crypto from 'node:crypto';
import { SignJWT, jwtVerify, createLocalJWKSet, generateKeyPair, exportJWK } from 'jose';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const TESTAPP = 'testapp-keyrot-e2e';
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
const jwtHeader = (jwt: string) => JSON.parse(Buffer.from(jwt.split('.')[0], 'base64url').toString());

// --- setup: clean crashed runs, park the step-up door, grant the admin perm ---
await pool.query('DELETE FROM oauth_clients WHERE client_id = $1', [TESTAPP]);
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await new Promise((r) => setTimeout(r, 5500)); // outwait the settings cache
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);

// --- admin local login ---
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
const csrf = ((await (await api('GET', '/admin/api/me')).json()) as { csrf: string }).csrf;

// 1. one current key; published in the JWKS
r = await api('GET', '/admin/api/keys');
let keys = (await r.json()) as { keys: { kid: string; status: string; retired_at: string | null; in_jwks: boolean }[] };
const kidA = keys.keys.find((k) => k.status === 'current')?.kid;
ok(r.status === 200 && !!kidA && keys.keys.filter((k) => k.status === 'current').length === 1,
   '1. exactly one current key', `(${kidA?.slice(0, 8)}…)`);
r = await fetch(SSO + '/jwks');
let jwks = (await r.json()) as { keys: { kid: string }[] };
ok(jwks.keys.some((k) => k.kid === kidA), '1a. current kid published at /jwks');

// 2. register a throwaway client (loopback jwks_uri) + full code -> token flow
const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const pubJwk = await exportJWK(publicKey);
pubJwk.kid = 'keyrot-test-' + Date.now(); pubJwk.alg = 'EdDSA'; pubJwk.use = 'sig';
const jwksServer = http.createServer((_q, s) => {
  s.setHeader('content-type', 'application/json');
  s.end(JSON.stringify({ keys: [pubJwk] }));
});
await new Promise<void>((resolve) => jwksServer.listen(8897, '127.0.0.1', resolve));
r = await api('POST', '/admin/api/clients', csrf, {
  client_id: TESTAPP, name: 'Keyrot E2E App', is_first_party: true, entry_policy: 'opt_in',
  hostname: 'stream-dev.dreamxwarden.ca', redirect_paths: ['/auth/callback'], events_path: null,
  jwks_uri: 'http://127.0.0.1:8897/jwks.json?run=' + Date.now(), jwks: null, allowed_scopes: ['openid', 'profile'],
});
ok(r.status === 201, '2. throwaway client registered', `(${r.status})`);

async function runFlow() {
  const v = crypto.randomBytes(32).toString('base64url');
  const chall = crypto.createHash('sha256').update(v).digest('base64url');
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: TESTAPP, redirect_uri: REDIRECT, scope: 'openid profile',
    state: 'x', nonce: 'y', code_challenge: chall, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let rr = await fetch(u, { redirect: 'manual' });
  const t = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
  rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(t));
  const cs = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  rr = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn: t, csrf: cs, username: USER, password: PASS }),
  });
  rr = await answerKmsi(SSO, rr, t, cs);
  const code = new URL(rr.headers.get('location')!).searchParams.get('code')!;
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: pubJwk.kid as string })
    .setIssuer(TESTAPP).setSubject(TESTAPP).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(privateKey);
  rr = await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: v,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  return (await rr.json()) as { id_token: string; access_token: string };
}
const before = await runFlow();
ok(!!before.id_token && jwtHeader(before.id_token).kid === kidA,
   '2a. pre-rotation id_token signed with current kid');

// 3. rotate (CSRF-gated)
r = await api('POST', '/admin/api/keys/rotate');
ok(r.status === 403 && (await r.json()).error === 'csrf_failed', '3. rotate without csrf -> 403');
r = await api('POST', '/admin/api/keys/rotate', csrf);
const { kid: kidB } = (await r.json()) as { kid: string };
ok(r.status === 200 && !!kidB && kidB !== kidA, '3a. rotate -> new kid', `(${kidB?.slice(0, 8)}…)`);

// 4. key states after rotation
r = await api('GET', '/admin/api/keys');
keys = await r.json();
const rowA = keys.keys.find((k) => k.kid === kidA);
const rowB = keys.keys.find((k) => k.kid === kidB);
ok(rowB?.status === 'current' && keys.keys.filter((k) => k.status === 'current').length === 1,
   '4. new key is the only current');
ok(rowA?.status === 'retired' && !!rowA?.retired_at && rowA?.in_jwks === true,
   '4a. old key retired, still in the published set');

// 5. JWKS publishes both; old artifacts still verify
r = await fetch(SSO + '/jwks');
jwks = await r.json();
ok(jwks.keys.some((k) => k.kid === kidA) && jwks.keys.some((k) => k.kid === kidB),
   '5. JWKS carries old + new kids', `(${jwks.keys.length} keys)`);
r = await fetch(SSO + '/userinfo', { headers: { authorization: 'Bearer ' + before.access_token } });
ok(r.status === 200, '5a. pre-rotation access token still accepted at /userinfo', `(${r.status})`);
const verified = await jwtVerify(before.id_token, createLocalJWKSet(jwks as never), { issuer: SSO, audience: TESTAPP })
  .then(() => true).catch(() => false);
ok(verified, '5b. pre-rotation id_token verifies against the published JWKS');

// 6. new flow signs with the new kid
const after = await runFlow();
ok(!!after.id_token && jwtHeader(after.id_token).kid === kidB, '6. post-rotation id_token signed with new kid');

// 7. system-client guards (account portal)
r = await api('POST', '/admin/api/clients/account/disable', csrf);
ok(r.status === 409 && (await r.json()).error === 'system_client', '7. disable system client -> 409 system_client');
r = await api('DELETE', '/admin/api/clients/account', csrf);
ok(r.status === 409 && (await r.json()).error === 'system_client', '7a. delete system client -> 409 system_client');
r = await api('GET', '/admin/api/clients');
const clients = ((await r.json()) as { clients: { client_id: string; is_system: boolean; jwks: { keys: unknown[] } | null }[] }).clients;
const acct = clients.find((c) => c.client_id === 'account');
const vs = clients.find((c) => c.client_id === 'videosite');
ok(acct?.is_system === true && vs?.is_system === false, '7b. is_system flag on account only');
ok((acct?.jwks?.keys?.length ?? 0) > 0 && (vs?.jwks?.keys?.length ?? 0) > 0,
   '7c. inline public JWKS returned for edit-form display');

// cleanup: throwaway client + perm + step-up setting (rotation stays — see header)
await api('POST', `/admin/api/clients/${TESTAPP}/disable`, csrf);
await api('DELETE', '/admin/api/clients/' + TESTAPP, csrf);
await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
if (suOrig[0]) {
  await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
} else {
  await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
}
jwksServer.close();

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
