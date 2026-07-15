// E2E for the Turnstile edge gate (turnstile-gate-sso worker + BFF assertion path):
//   admin generate-gate-key: private JWK returned once, public stored (no 'd')
//   configured (both keys) -> no token + no assertion -> 403
//   the WORKER driven in-process end-to-end: real siteverify (always-pass test
//     secret), token + smuggled x-gate-* stripped, Ed25519 assertion signed,
//     forwarded to the real BFF -> 204
//   worker: missing token -> 403, non-JSON -> 403, non-POST passes through
//   hand-signed assertions at the BFF: valid -> 204; tampered body / wrong
//     path / expired / stale iat / wrong key -> 403
//   no signing key configured -> assertion path skipped (token-only)
// Snapshots/restores every settings row it touches. Uses `nosuchuser99` so no
// email is ever sent (the 204 is uniform). Run: npx tsx scripts/sso-turnstile-gate-test.ts
import crypto from 'node:crypto';
import { SignJWT, importJWK, type JWK } from 'jose';
import { pool } from '../src/db.js';
import { setSecretSetting } from '../src/settings.js';
import { answerKmsi } from './lib/kmsi.mjs';
import worker from '../cloudflare/workers/turnstile-gate-sso/src/index.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const PORTAL = 'https://account-dev.dreamxwarden.ca';
const PATH = '/api/reset/request';
const SITE_KEY = '1x00000000000000000000AA'; // Cloudflare always-pass test pair
const SECRET_KEY = '1x0000000000000000000000000000000AA';
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const gsc = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};

const BODY = JSON.stringify({ identifier: 'nosuchuser99' });
const bodyHash = (b: string) => crypto.createHash('sha256').update(b).digest('base64url');

// Direct-to-BFF POST with an optional assertion header (raw string body so
// the signed hash covers the exact bytes).
const bffRaw = (body: string, assertion?: string) =>
  fetch(PORTAL + PATH, {
    method: 'POST',
    headers: {
      'content-type': 'application/json',
      ...(assertion ? { 'x-gate-assertion': assertion } : {}),
    },
    body,
  });

async function signAssertion(privJwk: JWK, over: {
  body?: string; path?: string; iat?: number; exp?: number; iss?: string; aud?: string;
} = {}): Promise<string> {
  const key = await importJWK(privJwk, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const iat = over.iat ?? now;
  return new SignJWT({
    path: over.path ?? PATH,
    body_sha256: bodyHash(over.body ?? BODY),
    jti: crypto.randomUUID(),
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: (privJwk as { kid?: string }).kid })
    .setIssuer(over.iss ?? 'turnstile-gate')
    .setAudience(over.aud ?? 'account-bff')
    .setIssuedAt(iat)
    .setExpirationTime(over.exp ?? iat + 90)
    .sign(key);
}

// --- snapshot settings rows verbatim ---
const TOUCHED = ['turnstile_site_key', 'turnstile_secret_key', 'gate_signing_public_jwk'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [TOUCHED]);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
const hadOverride = false; // test-created; removed in finally

try {
  // --- admin login (tester + temporary grant) ---
  let r = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrfForm = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
  });
  const cookie = 'sso_session=' + gsc(r, 'sso_session');
  await answerKmsi(SSO, r, txn, csrfForm, { cookie });
  const me = await (await fetch(SSO + '/admin/api/me', { headers: { cookie } })).json();

  // 1. generate the gate signing keypair via the admin API
  r = await fetch(SSO + '/admin/api/settings/generate-gate-key', {
    method: 'POST', headers: { cookie, 'x-csrf-token': me.csrf },
  });
  const gen = await r.json();
  const priv = gen.private_jwk as JWK & { kid?: string; d?: string };
  ok(r.status === 200 && priv?.kty === 'OKP' && priv?.crv === 'Ed25519' && !!priv?.d && !!gen.kid,
     '1. generate-gate-key -> private Ed25519 JWK + kid', `(${gen.kid})`);
  const { rows: [{ value: storedPub }] } = await pool.query(
    `SELECT value FROM settings WHERE key = 'gate_signing_public_jwk'`);
  ok(!storedPub.includes('"d"') && JSON.parse(storedPub).kid === gen.kid,
     '1a. stored key is PUBLIC only (no private part), kid matches');
  const s = await (await fetch(SSO + '/admin/api/settings', { headers: { cookie } })).json();
  ok(s.gate_key?.kid === gen.kid, '1b. GET settings surfaces the active kid');

  // configure Turnstile (both keys = enabled) and let the caches roll over
  await setDb('turnstile_site_key', SITE_KEY);
  await setSecretSetting('turnstile_secret_key', SECRET_KEY);
  await sleep(11_000);

  // 2. gate on: no token, no assertion -> 403
  r = await bffRaw(BODY);
  ok(r.status === 403 && (await r.json()).error === 'turnstile_failed', '2. no token + no assertion -> 403');
  // 2a. garbage assertion -> 403
  r = await bffRaw(BODY, 'not.a.jwt');
  ok(r.status === 403, '2a. malformed assertion -> 403');

  // 3. the WORKER end to end: verifies via real siteverify, strips the token
  //    and the smuggled x-gate-* header, signs, forwards to the real BFF
  const env = { TURNSTILE_SECRET_KEY: SECRET_KEY, GATE_SIGNING_KEY: JSON.stringify(priv) };
  r = (await worker.fetch(new Request(PORTAL + PATH, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-gate-assertion': 'client.smuggled.garbage' },
    body: JSON.stringify({ identifier: 'nosuchuser99', turnstile_token: 'XXXX.DUMMY' }),
  }), env)) as unknown as Response;
  ok(r.status === 204, '3. worker: siteverify + strip + sign + forward -> 204', `(${r.status})`);

  // 3a. worker rejects a missing token before forwarding
  r = (await worker.fetch(new Request(PORTAL + PATH, {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: BODY,
  }), env)) as unknown as Response;
  ok(r.status === 403 && (await r.json()).error === 'turnstile_failed', '3a. worker: no token -> 403');

  // 3b. worker rejects a non-JSON body
  r = (await worker.fetch(new Request(PORTAL + PATH, {
    method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'hello',
  }), env)) as unknown as Response;
  ok(r.status === 403, '3b. worker: non-JSON body -> 403');

  // 3c. non-POST passes through untouched
  r = (await worker.fetch(new Request(PORTAL + '/healthz'), env)) as unknown as Response;
  ok(r.status === 200 && (await r.json()).status === 'ok', '3c. worker: GET passes through to origin');

  // 3d. misconfigured env fails loud
  r = (await worker.fetch(new Request(PORTAL + PATH, { method: 'POST', body: BODY }),
    { TURNSTILE_SECRET_KEY: SECRET_KEY })) as unknown as Response;
  ok(r.status === 503, '3d. worker: missing signing key -> 503 (loud misconfig)');

  // 4. hand-signed assertion, no worker roundtrip: the BFF's verification path
  r = await bffRaw(BODY, await signAssertion(priv));
  ok(r.status === 204, '4. valid assertion + no token -> 204', `(${r.status})`);

  // 4a-4e. the rejection matrix
  r = await bffRaw(JSON.stringify({ identifier: 'nosuchuser98' }), await signAssertion(priv));
  ok(r.status === 403, '4a. assertion for body A, body B sent (tamper) -> 403');
  r = await bffRaw(BODY, await signAssertion(priv, { path: '/api/register/start' }));
  ok(r.status === 403, '4b. path-bound: signed for another endpoint -> 403');
  const past = Math.floor(Date.now() / 1000) - 300;
  r = await bffRaw(BODY, await signAssertion(priv, { iat: past, exp: past + 90 }));
  ok(r.status === 403, '4c. expired assertion -> 403');
  const stale = Math.floor(Date.now() / 1000) - 150;
  r = await bffRaw(BODY, await signAssertion(priv, { iat: stale, exp: stale + 300 }));
  ok(r.status === 403, '4d. stale iat (past maxTokenAge) -> 403 even if unexpired');
  const { privateKey: otherKey } = crypto.generateKeyPairSync('ed25519');
  const otherJwk = otherKey.export({ format: 'jwk' }) as JWK;
  r = await bffRaw(BODY, await signAssertion(otherJwk));
  ok(r.status === 403, '4e. signed by a different key -> 403');

  // 5. no signing key configured -> the assertion path is skipped entirely
  await setDb('gate_signing_public_jwk', null);
  await sleep(11_000);
  r = await bffRaw(BODY, await signAssertion(priv));
  ok(r.status === 403, '5. gate key unset: even a "valid" assertion -> 403 (token-only mode)');
  r = await fetch(PORTAL + PATH, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: 'nosuchuser99', turnstile_token: 'XXXX.DUMMY' }),
  });
  ok(r.status === 204, '5a. …but a real token still verifies at the origin', `(${r.status})`);
} finally {
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [TOUCHED]);
  for (const row of origRows) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  if (!hadOverride) {
    await pool.query(
      `DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
  }
  await pool.query('DELETE FROM sessions WHERE user_sub = $1', [sub]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
