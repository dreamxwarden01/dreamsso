// E2E for the step-up sudo window:
//   /admin door: password-only session -> bounced to the server-rendered challenge
//     (strong-only), solve -> stamp -> door opens; window expiry re-challenges
//   pre-clearance: strong-factor LOGIN (pwd+totp) births a pre-cleared session
//   toggle off (stepup_admin_required) -> no door
//   no factors -> stepup_enroll_required page (no email fallback)
//   resource API: status/verify (+ sid ownership), stamping visible to status
// Snapshots/restores settings rows + tester state. Run: npx tsx scripts/sso-stepup-test.ts
import crypto from 'node:crypto';
import { SignJWT, importJWK } from 'jose';
import fs from 'node:fs';
import { generateSync } from 'otplib';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { openSecret } from '../src/secretbox.js';

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
const FORM = { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' } as const;
const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const cookieOf = (r: Response) =>
  (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='))?.split(';')[0] ?? null;
const sidOf = async (cookie: string) => {
  const hash = crypto.createHash('sha256').update(cookie.split('=')[1]).digest();
  const { rows } = await pool.query<{ sid: string }>('SELECT sid FROM sessions WHERE token_hash = $1', [hash]);
  return rows[0]?.sid;
};
const post = (path: string, body: Record<string, string>, cookie?: string) =>
  fetch(SSO + path, {
    method: 'POST', redirect: 'manual',
    headers: { ...FORM, ...(cookie ? { cookie } : {}) },
    body: new URLSearchParams(body),
  });

async function passwordStep() {
  const p = pkce();
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: p.c, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  const cookie = cookieOf(r); // transient cookie on the login/KMSI page (null on the MFA challenge page)
  r = await answerKmsi(SSO, r, txn, csrf); // no-op unless it's the KMSI page (password-only login)
  return { r, txn, csrf, verifier: p.v, cookie };
}
async function accessTokenFrom(code: string, verifier: string) {
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
  return (await r.json()).access_token as string;
}
const totpNow = async (sub: string) => {
  const { rows: [{ secret_enc }] } = await pool.query(
    'SELECT secret_enc FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL', [sub]);
  return generateSync({ secret: openSecret(secret_enc), strategy: 'totp' });
};

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const SU_KEYS = ['stepup_admin_required', 'stepup_portal_required', 'stepup_validity_minutes'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [SU_KEYS]);
const setDb = async (key: string, value: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [key]);
  if (value != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [key, value]);
};
const settle = () => new Promise((r) => setTimeout(r, 5500));

try {
  // isolate: admin perm, one confirmed TOTP (seeded directly), login MFA toggle OFF
  await pool.query(
    `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
       ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM webauthn_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
  // Defaults are OFF/OFF/30 — this suite exercises the doors, so turn them on.
  await setDb('stepup_admin_required', 'true');
  await setDb('stepup_portal_required', 'true');
  await setDb('stepup_validity_minutes', null); // default 30
  await settle();
  // seed a confirmed TOTP without the API (sealSecret via mfa flow would need enroll round-trip)
  const { sealSecret } = await import('../src/secretbox.js');
  const { generateSecret } = await import('otplib');
  await pool.query(
    `INSERT INTO totp_credentials (user_sub, secret_enc, label, confirmed_at) VALUES ($1, $2, 'stepup-e2e', now())`,
    [sub, sealSecret(generateSecret())],
  );

  // 1. password-only login (toggle off -> no login challenge, NO pre-clearance)
  let step = await passwordStep();
  let loc = step.r.headers.get('location') || '';
  const cookie = step.cookie!;
  const code1 = new URL(loc).searchParams.get('code')!;
  ok(step.r.status === 302 && !!code1 && !!cookie, '1. password-only login (owns TOTP, toggle off)');
  const sid = await sidOf(cookie);
  const { rows: [s1] } = await pool.query('SELECT stepup_at FROM sessions WHERE sid = $1', [sid]);
  ok(s1.stepup_at === null, '1a. no pre-clearance from a pwd-only login');

  // 2. /admin door -> bounced to the strong-only challenge
  let r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie } });
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.startsWith('/login?txn='), '2. stale sudo window -> door bounce');
  const doorTxn = new URL(loc, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(doorTxn), { headers: { cookie } });
  const doorPage = await r.text();
  const doorCsrf = (doorPage.match(/name="csrf" value="([^"]+)"/) || [])[1];
  ok(doorPage.includes('Enter your code') && !doorPage.includes('name="password"'),
     '2a. door challenge = TOTP entry (strong-only, no password form)');

  // 3. wrong then right code -> stamp -> door opens
  r = await post('/login/challenge', { txn: doorTxn, csrf: doorCsrf, method: 'totp', code: '000000' }, cookie);
  ok(r.status === 401 && (await r.text()).includes('incorrect'), '3. wrong code -> error re-render');
  r = await post('/login/challenge', { txn: doorTxn, csrf: doorCsrf, method: 'totp', code: await totpNow(sub) }, cookie);
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc === '/admin' && !cookieOf(r), '3a. right code -> redirect /admin, NO new session');
  const { rows: [s2] } = await pool.query('SELECT stepup_at FROM sessions WHERE sid = $1', [sid]);
  ok(s2.stepup_at !== null, '3b. session stamped');
  r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie } });
  ok(r.status === 200, '3c. door open within the window', `(${r.status})`);

  // 4. window expiry -> door bounces again
  await pool.query(`UPDATE sessions SET stepup_at = now() - interval '2 hours' WHERE sid = $1`, [sid]);
  r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie } });
  ok(r.status === 302, '4. expired window (2h > 30min default) -> re-challenge');

  // 5. pre-clearance: strong-factor LOGIN births a cleared session
  await pool.query('UPDATE identities SET mfa_enabled = true WHERE sub = $1', [sub]);
  step = await passwordStep(); // -> challenge page (login MFA)
  r = await post('/login/challenge', { txn: step.txn, csrf: step.csrf, method: 'totp', code: await totpNow(sub) });
  const cookie2 = cookieOf(r)!; // transient cookie on the KMSI page
  r = await answerKmsi(SSO, r, step.txn, step.csrf);
  ok(r.status === 302 && !!cookie2, '5. pwd+totp login completed');
  r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie: cookie2 } });
  ok(r.status === 200, '5a. pre-cleared session -> door opens with NO second challenge', `(${r.status})`);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);

  // 6. toggle the door off -> no challenge even with a stale window
  await pool.query(`UPDATE sessions SET stepup_at = NULL WHERE sid = $1`, [sid]);
  await setDb('stepup_admin_required', 'false');
  await settle();
  r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie } });
  ok(r.status === 200, '6. stepup_admin_required=false -> door off', `(${r.status})`);
  await setDb('stepup_admin_required', 'true');
  await settle();

  // 7. no strong factors -> enroll-required page with a portal CTA (no email fallback)
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  r = await fetch(SSO + '/admin', { redirect: 'manual', headers: { cookie } });
  const enrollPage = await r.text();
  ok(r.status === 403 && enrollPage.includes('stepup_enroll_required'),
     '7. no factors -> enroll-required page (no email fallback)');
  ok(enrollPage.includes('/security') && enrollPage.includes('Open the account portal'),
     '7a. enroll page links to the portal Security (from settings, not hardcoded)');
  await pool.query(
    `INSERT INTO totp_credentials (user_sub, secret_enc, label, confirmed_at) VALUES ($1, $2, 'stepup-e2e-2', now())`,
    [sub, sealSecret(generateSecret())],
  );

  // 8. resource API: status + verify + sid ownership
  const token = await accessTokenFrom(code1, step.verifier).catch(() => null); // code1 consumed? mint fresh below
  let step3 = await passwordStep(); // toggle off -> code directly
  const loc3 = step3.r.headers.get('location') || '';
  const access = await accessTokenFrom(new URL(loc3).searchParams.get('code')!, step3.verifier);
  const cookie3 = step3.cookie!; // transient cookie captured pre-KMSI in passwordStep
  const sid3 = await sidOf(cookie3);
  const api = (method: string, path: string, body?: unknown) =>
    fetch(SSO + path, {
      method,
      headers: { authorization: 'Bearer ' + access, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  r = await api('GET', `/account/stepup/status?sid=${sid3}`);
  let st = await r.json();
  ok(r.status === 200 && st.required === true && st.verified === false &&
     JSON.stringify(st.methods) === '["totp"]' && st.enroll_required === false,
     '8. status: required, unverified, methods [totp]', JSON.stringify(st.methods));
  r = await api('GET', `/account/stepup/status?sid=${crypto.randomUUID()}`);
  ok(r.status === 404, '8a. foreign sid -> 404');
  r = await api('POST', '/account/stepup/verify', { sid: sid3, method: 'totp', code: '000000' });
  ok(r.status === 403 && (await r.json()).error === 'verification_failed', '8b. wrong code -> 403');
  r = await api('POST', '/account/stepup/verify', { sid: sid3, method: 'totp', code: await totpNow(sub) });
  ok(r.status === 204, '8c. right code -> 204 (stamped)', `(${r.status})`);
  st = await (await api('GET', `/account/stepup/status?sid=${sid3}`)).json();
  ok(st.verified === true && !!st.expires_at, '8d. status now verified with expires_at', `(${st.expires_at})`);

  // 9. enable-guard: an admin with NO strong factor can't turn a step-up toggle on
  await setDb('stepup_admin_required', 'false');
  await settle();
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  const me = await (await fetch(SSO + '/admin/api/me', { headers: { cookie: cookie3 } })).json();
  r = await fetch(SSO + '/admin/api/settings', {
    method: 'PUT',
    headers: { cookie: cookie3, 'x-csrf-token': me.csrf, 'content-type': 'application/json' },
    body: JSON.stringify({ stepup_admin_required: true }),
  });
  const guard = await r.json();
  ok(r.status === 422 && !!guard.errors?.stepup_admin_required,
     '9. enabling without a strong factor -> 422 (lockout guard)');

  void token;
} finally {
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [SU_KEYS]);
  for (const row of origRows) {
    await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  }
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
