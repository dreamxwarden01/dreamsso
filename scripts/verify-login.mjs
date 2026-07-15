// Drives the auth-code flow end-to-end against the running SSO (no RP needed):
//   /authorize -> /login -> POST /login (wrong, then right) -> code in the redirect.
import crypto from 'node:crypto';

const BASE = process.env.SSO_BASE || 'http://localhost:3000';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/callback';

const verifier = crypto.randomBytes(32).toString('base64url');
const challenge = crypto.createHash('sha256').update(verifier).digest('base64url');
const state = crypto.randomBytes(8).toString('hex');

// 1. /authorize -> 302 /login?txn=
const authUrl = new URL(BASE + '/authorize');
authUrl.search = new URLSearchParams({
  response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
  scope: 'openid profile email', state, nonce: 'n-' + state,
  code_challenge: challenge, code_challenge_method: 'S256',
}).toString();
let r = await fetch(authUrl, { redirect: 'manual' });
const loginLoc = r.headers.get('location') || '';
console.log('/authorize           ->', r.status, loginLoc);
if (!loginLoc.includes('/login')) { console.error('FAIL: no /login redirect'); process.exit(1); }
const txn = new URL(loginLoc, BASE).searchParams.get('txn');

// 2. GET /login -> extract csrf
r = await fetch(BASE + '/login?txn=' + encodeURIComponent(txn));
const html = await r.text();
const csrf = (html.match(/name="csrf" value="([^"]+)"/) || [])[1];
console.log('/login               ->', r.status, csrf ? 'csrf found' : 'csrf MISSING');
if (!csrf) process.exit(1);

const post = (password) => fetch(BASE + '/login', {
  method: 'POST', redirect: 'manual',
  headers: {
    'content-type': 'application/x-www-form-urlencoded',
    origin: 'null',                 // mimic Safari / Referrer-Policy: no-referrer
    'sec-fetch-site': 'same-origin',
  },
  body: new URLSearchParams({ txn, csrf, username: 'tester', password }),
});

// 3a. wrong password (txn not consumed on failure)
r = await post('nope');
const wrong = await r.text();
console.log('POST /login (wrong)  ->', r.status, /Invalid username or password/.test(wrong) ? 'shows error ✓' : 'NO ERROR ✗');

// 3b. correct password -> 302 with code
r = await post('Test1234!');
const loc = r.headers.get('location') || '';
const setCookie = r.headers.getSetCookie?.() ?? [];
const code = loc ? new URL(loc).searchParams.get('code') : null;
const gotState = loc ? new URL(loc).searchParams.get('state') : null;
console.log('POST /login (right)  ->', r.status, loc.split('?')[0]);
console.log('  code           :', code ? `${code.slice(0, 10)}… (${code.length} chars) ✓` : 'MISSING ✗');
console.log('  state matches  :', gotState === state ? '✓' : '✗');
console.log('  session cookie :', setCookie.some((c) => c.startsWith('sso_session=')) ? '✓' : '✗');
if (!code || gotState !== state) { console.log('\nFLOW FAILED ✗'); process.exit(1); }

// 4. Exchange the code at /token (PKCE verifier + private_key_jwt client assertion).
const { SignJWT, jwtVerify, createRemoteJWKSet, importJWK } = await import('jose');
const fs = await import('node:fs');
const ISSUER = 'https://sso-dev.dreamxwarden.ca';
const priv = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url))));
const key = await importJWK(priv, 'EdDSA');
const now = Math.floor(Date.now() / 1000);
const assertion = await new SignJWT({})
  .setProtectedHeader({ alg: 'EdDSA', kid: priv.kid })
  .setIssuer(CLIENT).setSubject(CLIENT).setAudience(ISSUER)
  .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
  .sign(key);

const tr = await fetch(BASE + '/token', {
  method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({
    grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
    client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
  }),
});
const tok = await tr.json();
console.log('\nPOST /token          ->', tr.status, tok.id_token ? 'id_token + access_token ✓' : JSON.stringify(tok));
if (!tr.ok) process.exit(1);

const jwks = createRemoteJWKSet(new URL(BASE + '/jwks'));
const { payload } = await jwtVerify(tok.id_token, jwks, { issuer: ISSUER, audience: CLIENT });
console.log('  id_token verified  ✓  sub=' + String(payload.sub).slice(0, 12) + '…  amr=' + JSON.stringify(payload.amr) + '  acr=' + payload.acr);
console.log('  claims             :', JSON.stringify({ name: payload.name, preferred_username: payload.preferred_username, email: payload.email, nonce: payload.nonce }));

const ui = await fetch(BASE + '/userinfo', { headers: { authorization: 'Bearer ' + tok.access_token } });
console.log('GET /userinfo        ->', ui.status, JSON.stringify(await ui.json()));
console.log('\nFULL OIDC FLOW OK ✓');
