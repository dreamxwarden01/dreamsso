// Verifies RBAC enforcement on the SSO self-service endpoints: the permissions
// endpoint, per-field profile gating, password/session/MFA gates, and the
// last-strong-factor rule. Drives the SSO directly (videosite client key) and
// flips per-user overrides in the DB to exercise deny paths. Run via tsx.
import { SignJWT, importJWK, decodeJwt } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

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
const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const setCookie = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};
async function accessToken(): Promise<string> {
  const p = pkce();
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: p.c, code_challenge_method: 'S256',
  }).toString();
  let r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> code
  const code = new URL(r.headers.get('location')!).searchParams.get('code')!;
  const key = await importJWK(KEY, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(key);
  r = await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: p.v,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  return (await r.json()).access_token;
}
const api = (method: string, path: string, token: string, body?: unknown) =>
  fetch(SSO + path, {
    method,
    headers: { authorization: 'Bearer ' + token, ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });

const { rows: [id] } = await pool.query<{ sub: string; display_name: string }>(
  `SELECT sub, display_name FROM identities WHERE username = $1`, [USER]);
const sub = id.sub;
const override = (key: string, effect: string) =>
  pool.query(
    `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, $2, $3)
       ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = $3`, [sub, key, effect]);
const clearOverride = (key: string) =>
  pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = $2`, [sub, key]);

const token = await accessToken();

// 1. permissions endpoint returns the granted set (profile.* present, org.* absent)
let r = await api('GET', '/account/permissions', token);
const perms: string[] = (await r.json()).permissions || [];
ok(r.status === 200 && perms.includes('profile.displayname.change') && !perms.includes('org.users.create'),
   '1. GET /account/permissions = granted-only list', `(${perms.length} keys)`);

// 2. allowed profile edit works
r = await api('PATCH', '/account/profile', token, { display_name: 'RBAC Test' });
ok(r.status === 200, '2. PATCH display_name allowed (has perm)', `(${r.status})`);

// 3. denied per-field -> 403 permission_denied
await override('profile.displayname.change', 'deny');
r = await api('PATCH', '/account/profile', token, { display_name: 'Nope' });
let b = await r.json().catch(() => ({}));
ok(r.status === 403 && b.error === 'permission_denied' && b.permission === 'profile.displayname.change',
   '3. denied display_name -> 403 permission_denied', `(${r.status} ${b.error})`);
await clearOverride('profile.displayname.change');

// 4. password gate (middleware, before body logic)
await override('profile.security.password.change', 'deny');
r = await api('POST', '/account/password', token, { current_password: 'x', new_password: 'Whatever1!' });
b = await r.json().catch(() => ({}));
ok(r.status === 403 && b.error === 'permission_denied', '4. denied password change -> 403', `(${r.status} ${b.error})`);
await clearOverride('profile.security.password.change');

// 5. session view gate
r = await api('GET', '/account/sessions', token);
ok(r.status === 200, '5. sessions view allowed (has perm)', `(${r.status})`);
await override('profile.security.sessions.view', 'deny');
r = await api('GET', '/account/sessions', token);
ok(r.status === 403, '5a. denied sessions view -> 403', `(${r.status})`);
await clearOverride('profile.security.sessions.view');

// 6. last-strong-factor: tester has 0 factors + totp.remove granted, so the remove
//    PASSES requirePerm but the handler blocks it once mfa.disable is denied.
await override('profile.security.mfa.disable', 'deny');
r = await api('DELETE', '/account/mfa/authenticator/' + crypto.randomUUID(), token);
b = await r.json().catch(() => ({}));
ok(r.status === 403 && b.error === 'permission_denied' && b.detail === 'last_strong_factor',
   '6. last strong factor blocked when mfa.disable denied', `(${r.status} ${b.detail})`);
await clearOverride('profile.security.mfa.disable');

// restore display_name
await pool.query(`UPDATE identities SET display_name = $2 WHERE sub = $1`, [sub, id.display_name]);

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
