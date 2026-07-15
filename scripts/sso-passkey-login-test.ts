// E2E for passkey sign-in using a SOFTWARE AUTHENTICATOR (P-256 keypair, hand-built
// COSE key + authenticatorData + DER signature — a real assertion, verified by
// @simplewebauthn on the server):
//   login page ships the passkey UI (conditional-UI autocomplete + hidden button)
//   first-factor POST /login/passkey -> FULL auth: amr [passkey], acr 2fa,
//     toggle irrelevant, no challenge step
//   bad assertion -> back to the login form ("sign in with your password" copy)
//   challenge-phase passkey (toggle on) -> amr [pwd,passkey]
// Run: npx tsx scripts/sso-passkey-login-test.ts
import crypto from 'node:crypto';
import { SignJWT, importJWK, decodeJwt } from 'jose';
import fs from 'node:fs';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const ORIGIN = 'https://sso-dev.dreamxwarden.ca';
const RP_ID = 'dreamxwarden.ca';
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
const FORM = { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' } as const;
const b64u = (b: Buffer) => b.toString('base64url');
const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const cookieOf = (r: Response) =>
  (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='))?.split(';')[0] ?? null;

// --- software authenticator ---
const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const jwk = publicKey.export({ format: 'jwk' }) as { x: string; y: string };
// COSE_Key (EC2/P-256/ES256): {1:2, 3:-7, -1:1, -2:x, -3:y} hand-encoded CBOR.
const coseKey = Buffer.concat([
  Buffer.from([0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]),
  Buffer.from(jwk.x, 'base64url'),
  Buffer.from([0x22, 0x58, 0x20]),
  Buffer.from(jwk.y, 'base64url'),
]);
const credId = crypto.randomBytes(32);
let counter = 0;

function assert(challenge: string): string {
  counter += 1;
  const clientDataJSON = Buffer.from(JSON.stringify({
    type: 'webauthn.get', challenge, origin: ORIGIN, crossOrigin: false,
  }));
  const authData = Buffer.concat([
    crypto.createHash('sha256').update(RP_ID).digest(), // rpIdHash
    Buffer.from([0x05]), // flags: UP | UV
    Buffer.from([(counter >>> 24) & 0xff, (counter >>> 16) & 0xff, (counter >>> 8) & 0xff, counter & 0xff]),
  ]);
  const signature = crypto
    .createSign('SHA256')
    .update(Buffer.concat([authData, crypto.createHash('sha256').update(clientDataJSON).digest()]))
    .sign(privateKey); // DER, as WebAuthn expects
  return JSON.stringify({
    id: b64u(credId), rawId: b64u(credId), type: 'public-key', clientExtensionResults: {},
    response: {
      clientDataJSON: b64u(clientDataJSON), authenticatorData: b64u(authData),
      signature: b64u(signature), userHandle: null,
    },
  });
}

// --- helpers ---
async function newTxn() {
  const p = pkce();
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: p.c, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  const r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  const pageRes = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const page = await pageRes.text();
  const csrf = (page.match(/name="csrf" value="([^"]+)"/) || [])[1];
  const opts = (page.match(/var OPTS=(\{.*?\});/s) || [])[1];
  return { txn, csrf, page, opts: opts ? JSON.parse(opts) : null, verifier: p.v };
}
async function exchange(code: string, verifier: string) {
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
  return r.json();
}
const post = (path: string, body: Record<string, string>) =>
  fetch(SSO + path, { method: 'POST', redirect: 'manual', headers: FORM, body: new URLSearchParams(body) });

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);

try {
  await pool.query('DELETE FROM webauthn_credentials WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
  await pool.query(
    `INSERT INTO webauthn_credentials (user_sub, credential_id, public_key, sign_count, label)
     VALUES ($1, $2, $3, 0, 'soft-authn-e2e')`,
    [sub, credId, coseKey],
  );

  // 1. login page ships the passkey UI
  let t = await newTxn();
  ok(t.page.includes('autocomplete="username webauthn"'), '1. username box advertises conditional UI');
  ok(t.page.includes('Sign in with a passkey') && t.page.includes('pk-btn'), '1a. passkey button present (hidden until support check)');
  ok(!!t.opts?.challenge, '1b. request options embedded (pre-minted challenge)', `(${(t.opts?.challenge || '').slice(0, 12)}…)`);

  // 2. bad assertion -> back to the password form with the fallback copy
  let r = await post('/login/passkey', { txn: t.txn, csrf: t.csrf, credential: '{"id":"AAAA"}' });
  const failPage = await r.text();
  ok(r.status === 401 && failPage.includes('sign in with your password'), '2. bad assertion -> login form + fallback copy');

  // 3. real assertion (fresh challenge from the failure re-render) -> FULL auth
  const opts2 = (failPage.match(/var OPTS=(\{.*?\});/s) || [])[1];
  const chal2 = JSON.parse(opts2!).challenge as string;
  ok(!!chal2 && chal2 !== t.opts.challenge, '3. failed attempt consumed the challenge (fresh one minted)');
  r = await post('/login/passkey', { txn: t.txn, csrf: t.csrf, credential: assert(chal2) });
  const c3 = cookieOf(r); // transient cookie on the KMSI page
  r = await answerKmsi(SSO, r, t.txn, t.csrf);
  let loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.includes('code=') && !!c3, '3a. passkey sign-in -> session + code');
  let tok = await exchange(new URL(loc).searchParams.get('code')!, t.verifier);
  let claims = decodeJwt(tok.id_token);
  ok(JSON.stringify(claims.amr) === '["passkey"]' && claims.acr === 'urn:dreamsso:2fa',
     '3b. FULL auth: amr [passkey], acr 2fa — no challenge step', `(${JSON.stringify(claims.amr)})`);

  // 4. sign_count advanced + last_used_at touched
  const { rows: [cred] } = await pool.query(
    'SELECT sign_count, last_used_at FROM webauthn_credentials WHERE credential_id = $1', [credId]);
  ok(Number(cred.sign_count) === counter && !!cred.last_used_at, '4. sign_count + last_used_at updated', `(count=${cred.sign_count})`);

  // 5. challenge-phase passkey: toggle ON + password login -> passkey challenge
  await pool.query('UPDATE identities SET mfa_enabled = true WHERE sub = $1', [sub]);
  t = await newTxn();
  r = await post('/login', { txn: t.txn, csrf: t.csrf, username: USER, password: PASS });
  const chalPage = await r.text();
  ok(r.status === 200 && chalPage.includes('Waiting for your passkey'), '5. toggle on -> passkey challenge state');
  const chalOpts = JSON.parse((chalPage.match(/var OPTS=(\{.*?\});/s) || [])[1]!);
  ok(Array.isArray(chalOpts.allowCredentials) &&
     chalOpts.allowCredentials.some((c: { id: string }) => c.id === b64u(credId)),
     '5a. challenge options scoped to the user’s credentials');
  r = await post('/login/challenge', { txn: t.txn, csrf: t.csrf, method: 'passkey', credential: assert(chalOpts.challenge) });
  r = await answerKmsi(SSO, r, t.txn, t.csrf);
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.includes('code='), '5b. passkey challenge verified -> code');
  tok = await exchange(new URL(loc).searchParams.get('code')!, t.verifier);
  claims = decodeJwt(tok.id_token);
  ok(JSON.stringify(claims.amr) === '["pwd","passkey"]' && claims.acr === 'urn:dreamsso:2fa',
     '5c. amr [pwd,passkey], acr 2fa', `(${JSON.stringify(claims.amr)})`);
} finally {
  await pool.query('DELETE FROM webauthn_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
