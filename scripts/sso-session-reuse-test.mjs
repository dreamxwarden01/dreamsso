// Verifies SSO session reuse (silent auth) + the `sid` claim, driving the SSO
// directly with the videosite client key (so we can exchange and read id_token).
//   1. no session            -> interactive /login
//   2. login                 -> code + sso_session cookie
//   3. authorize w/ session  -> silent code (no /login)
//   4. exchange              -> id_token carries sid
//   5. prompt=login          -> forced /login
//   6. prompt=none, no sess  -> login_required
//   7. prompt=none, w/ sess  -> silent code (same sid -> reuse is stable)
import { SignJWT, importJWK, decodeJwt } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { answerKmsi } from './lib/kmsi.mjs';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const KEY = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url), 'utf8')));
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const authzUrl = (challenge, extra = {}) => {
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
    scope: 'openid profile email', state: crypto.randomBytes(8).toString('hex'),
    nonce: crypto.randomBytes(8).toString('hex'),
    code_challenge: challenge, code_challenge_method: 'S256', ...extra,
  }).toString();
  return u.toString();
};
const setCookieValue = (res, name) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === name) return nv.slice(i + 1);
  }
  return null;
};
async function exchange(code, verifier) {
  const key = await importJWK(KEY, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(key);
  const r = await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  return { status: r.status, body: await r.json().catch(() => ({})) };
}

// 1. no session -> interactive /login
const p1 = pkce();
let r = await fetch(authzUrl(p1.c), { redirect: 'manual' });
let loc = r.headers.get('location') || '';
ok(r.status === 302 && loc.includes('/login?txn='), '1. no session -> /login', `(${loc.split('?')[0]})`);
const txn = new URL(loc, SSO).searchParams.get('txn');

// 2. login -> code + sso_session cookie
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
});
const cookie = setCookieValue(r, 'sso_session'); // transient cookie on the KMSI page
r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> code
loc = r.headers.get('location') || '';
ok(r.status === 302 && loc.startsWith(REDIRECT) && loc.includes('code=') && !!cookie,
   '2. login -> code + sso_session', `(cookie ${cookie ? '✓' : '✗'})`);

// 3. authorize WITH session -> silent code (no /login)
const p2 = pkce();
r = await fetch(authzUrl(p2.c), { redirect: 'manual', headers: { cookie: 'sso_session=' + cookie } });
loc = r.headers.get('location') || '';
const code2 = loc.startsWith(REDIRECT) ? new URL(loc).searchParams.get('code') : null;
ok(r.status === 302 && !!code2, '3. session reuse -> silent code', `(-> ${loc.split('?')[0]})`);

// 4. exchange -> id_token has sid
const tok = await exchange(code2, p2.v);
const claims = tok.body.id_token ? decodeJwt(tok.body.id_token) : {};
ok(tok.status === 200 && !!claims.sid, '4. id_token carries sid', `(sid=${claims.sid || 'MISSING'})`);

// 5. prompt=login WITH session -> forced /login
const p3 = pkce();
r = await fetch(authzUrl(p3.c, { prompt: 'login' }), { redirect: 'manual', headers: { cookie: 'sso_session=' + cookie } });
loc = r.headers.get('location') || '';
ok(r.status === 302 && loc.includes('/login?txn='), '5. prompt=login -> forced /login', `(${loc.split('?')[0]})`);

// 6. prompt=none WITHOUT session -> login_required
const p4 = pkce();
r = await fetch(authzUrl(p4.c, { prompt: 'none' }), { redirect: 'manual' });
loc = r.headers.get('location') || '';
ok(r.status === 302 && new URL(loc).searchParams.get('error') === 'login_required',
   '6. prompt=none, no session -> login_required', `(err=${new URL(loc).searchParams.get('error')})`);

// 7. prompt=none WITH session -> silent code, same sid (stable reuse)
const p5 = pkce();
r = await fetch(authzUrl(p5.c, { prompt: 'none' }), { redirect: 'manual', headers: { cookie: 'sso_session=' + cookie } });
loc = r.headers.get('location') || '';
const code5 = loc.startsWith(REDIRECT) ? new URL(loc).searchParams.get('code') : null;
const tok5 = code5 ? await exchange(code5, p5.v) : { body: {} };
const sid5 = tok5.body.id_token ? decodeJwt(tok5.body.id_token).sid : null;
ok(!!code5 && sid5 === claims.sid, '7. prompt=none reuse -> same sid', `(sid=${sid5})`);

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
