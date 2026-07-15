// E2E for "Stay signed in?" (KMSI):
//   every interactive login lands on the KMSI page before the code is minted
//   No  -> transient session (persistent=false), browser-session cookie, short window
//   Yes -> persistent session, expiring cookie (Max-Age ~ absolute window)
//   silent reuse never re-asks; the transient window is enforced dynamically
//   token claims: sess_persistent + sess_exp reflect the choice + applicable window
//   refresh-safe (GET /login in the KMSI phase re-renders KMSI, not the password form)
// Snapshots/restores the session-window settings it touches. Run: npx tsx scripts/sso-kmsi-test.ts
import { SignJWT, importJWK, decodeJwt } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { pool } from '../src/db.js';
import { FORM } from './lib/kmsi.mjs';

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
const authzUrl = (challenge: string, extra: Record<string, string> = {}) => {
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: challenge, code_challenge_method: 'S256', ...extra,
  }).toString();
  return u.toString();
};
const rawCookie = (r: Response) => (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='));
const cookieOf = (r: Response) => rawCookie(r)?.split(';')[0] ?? null;
const post = (path: string, body: Record<string, string>, cookie?: string) =>
  fetch(SSO + path, { method: 'POST', redirect: 'manual', headers: { ...FORM, ...(cookie ? { cookie } : {}) }, body: new URLSearchParams(body) });

// Password login up to (not through) the KMSI page. Returns the KMSI response.
async function toKmsi() {
  const p = pkce();
  let r = await fetch(authzUrl(p.c, { prompt: 'login' }), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await post('/login', { txn, csrf, username: USER, password: PASS });
  return { r, txn, csrf, verifier: p.v };
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
  return (await r.json()) as { id_token: string };
}
const sidOf = async (cookie: string) => {
  const hash = crypto.createHash('sha256').update(cookie.split('=')[1]).digest();
  const { rows } = await pool.query<{ sid: string; persistent: boolean }>(
    'SELECT sid, persistent FROM sessions WHERE token_hash = $1', [hash]);
  return rows[0];
};

const WIN_KEYS = ['session_max_hours', 'session_transient_max_hours'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [WIN_KEYS]);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};

try {
  await setDb('session_max_hours', '168');
  await setDb('session_transient_max_hours', '24');
  await new Promise((r) => setTimeout(r, 5500));

  // 1. login lands on the KMSI page (session already created, transient cookie)
  let k = await toKmsi();
  const page = await k.r.text();
  ok(k.r.status === 200 && page.includes('Stay signed in?') && page.includes('/login/stay'),
     '1. interactive login -> KMSI page');
  ok(page.includes('<span>Test User</span>'),
     '1-label. KMSI chip shows the display name (authenticated identity)');
  const noCookie = cookieOf(k.r)!;
  ok(rawCookie(k.r)!.toLowerCase().indexOf('expires') === -1 && rawCookie(k.r)!.toLowerCase().indexOf('max-age') === -1,
     '1a. cookie set at login is browser-session (no expiry)');
  const sess1 = await sidOf(noCookie);
  ok(sess1 && sess1.persistent === false, '1b. session row born transient');

  // 1c. refresh-safe
  let r = await fetch(SSO + '/login?txn=' + encodeURIComponent(k.txn));
  ok((await r.text()).includes('Stay signed in?'), '1c. GET /login in KMSI phase -> KMSI, not password form');

  // 2. answer No -> transient stays, code minted, claims reflect transient
  r = await post('/login/stay', { txn: k.txn, csrf: k.csrf, choice: 'no' }, noCookie);
  let loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.includes('code='), '2. No -> code minted');
  let claims = decodeJwt((await exchange(new URL(loc).searchParams.get('code')!, k.verifier)).id_token);
  const now = Math.floor(Date.now() / 1000);
  ok(claims.sess_persistent === false, '2a. claim sess_persistent=false');
  ok(typeof claims.sess_exp === 'number' && Math.abs((claims.sess_exp as number) - (now + 24 * 3600)) < 120,
     '2b. sess_exp ~ now + 24h (transient window)', `(+${Math.round(((claims.sess_exp as number) - now) / 3600)}h)`);

  // 3. answer Yes -> persistent session + expiring cookie + full-window claim
  k = await toKmsi();
  const preCookie = cookieOf(k.r)!;
  r = await post('/login/stay', { txn: k.txn, csrf: k.csrf, choice: 'yes' }, preCookie);
  loc = r.headers.get('location') || '';
  const yesRaw = rawCookie(r); // persist re-sets the cookie on the stay response
  ok(r.status === 302 && loc.includes('code='), '3. Yes -> code minted');
  ok(!!yesRaw && /expires=/i.test(yesRaw), '3a. cookie replaced with an EXPIRING one');
  const sess3 = await sidOf(preCookie);
  ok(sess3 && sess3.persistent === true, '3b. session row now persistent');
  claims = decodeJwt((await exchange(new URL(loc).searchParams.get('code')!, k.verifier)).id_token);
  ok(claims.sess_persistent === true &&
     Math.abs((claims.sess_exp as number) - (now + 168 * 3600)) < 120,
     '3c. claims: persistent + sess_exp ~ now + 168h', `(+${Math.round(((claims.sess_exp as number) - now) / 3600)}h)`);

  // 4. silent reuse does NOT re-ask KMSI (answer given at creation)
  const p = pkce();
  r = await fetch(authzUrl(p.c), { redirect: 'manual', headers: { cookie: preCookie } });
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.startsWith(REDIRECT) && loc.includes('code='), '4. silent reuse -> straight to code, no KMSI');

  // 5. transient absolute window enforced dynamically (created_at beyond 24h)
  const transientSid = sess1!.sid;
  await pool.query(`UPDATE sessions SET created_at = now() - interval '30 hours' WHERE sid = $1`, [transientSid]);
  r = await fetch(authzUrl(pkce().c, { prompt: 'none' }), { redirect: 'manual', headers: { cookie: noCookie } });
  ok((new URL(r.headers.get('location')!).searchParams.get('error')) === 'login_required',
     '5. transient session past 24h -> rejected (login_required)');
  // ...but a PERSISTENT session at 30h is still fine (168h window)
  await pool.query(`UPDATE sessions SET created_at = now() - interval '30 hours' WHERE sid = $1`, [sess3!.sid]);
  r = await fetch(authzUrl(pkce().c, { prompt: 'none' }), { redirect: 'manual', headers: { cookie: preCookie } });
  ok(r.status === 302 && (r.headers.get('location') || '').includes('code='),
     '5a. persistent session at 30h still valid');
} finally {
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [WIN_KEYS]);
  for (const row of origRows) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
