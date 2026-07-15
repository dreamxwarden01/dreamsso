// E2E for slice 1 of the MFA login challenge (TOTP):
//   no factor -> no challenge (password-only login unchanged)
//   enroll TOTP via the account API -> next login renders the challenge page
//   wrong code -> re-render with error; right code -> session + code, amr [pwd,otp], acr 2fa
//   refresh-safe (GET /login re-renders the challenge, never the password form)
//   re-POSTing the password during the challenge phase doesn't bypass it
//   5 wrong codes -> txn burned (too_many_attempts)
//   silent session reuse does NOT re-challenge
//   unconfirmed setup rows expire after 15 min (confirm -> 422)
// Cleans up tester's TOTP rows in `finally`. Run: npx tsx scripts/sso-mfa-totp-test.ts
import { SignJWT, importJWK, decodeJwt } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { generateSync } from 'otplib';
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
const authzUrl = (challenge: string) => {
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: challenge, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  return u.toString();
};
const cookieOf = (r: Response) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    if (c.startsWith('sso_session=')) return c.split(';')[0];
  }
  return null;
};
const FORM = { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' } as const;

// Start a login txn and submit the password; returns whatever came back.
async function passwordStep() {
  const p = pkce();
  let r = await fetch(authzUrl(p.c), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf); // no-op unless it's the KMSI page (password-only login)
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
  return r.json();
}
const totpNow = (secret: string) => generateSync({ secret, strategy: 'totp' });

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);

try {
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);

  // 1. no factor -> password-only login (unchanged behavior) + grab an access token
  let step = await passwordStep();
  let loc = step.r.headers.get('location') || '';
  ok(step.r.status === 302 && loc.includes('code='), '1. no TOTP -> password-only login, code issued');
  const tok1 = await exchange(new URL(loc).searchParams.get('code')!, step.verifier);
  const claims1 = decodeJwt(tok1.id_token);
  ok(JSON.stringify(claims1.amr) === '["pwd"]' && claims1.acr === 'urn:dreamsso:1fa',
     '1a. amr [pwd], acr 1fa', `(${JSON.stringify(claims1.amr)})`);

  // 2. enroll a TOTP via the account API
  const api = (method: string, path: string, body?: unknown) =>
    fetch(SSO + path, {
      method,
      headers: { authorization: 'Bearer ' + tok1.access_token, ...(body ? { 'content-type': 'application/json' } : {}) },
      body: body ? JSON.stringify(body) : undefined,
    });
  let r = await api('POST', '/account/mfa/authenticator/setup', { label: 'mfa-e2e' });
  const setup = await r.json();
  ok(r.status === 200 && !!setup.secret, '2. authenticator setup');
  r = await api('POST', '/account/mfa/authenticator/confirm', { id: setup.id, code: totpNow(setup.secret) });
  ok(r.status === 204, '2a. confirm -> 204', `(${r.status})`);

  // 2b. possession alone does NOT challenge — the account toggle is still off
  step = await passwordStep();
  loc = step.r.headers.get('location') || '';
  ok(step.r.status === 302 && loc.includes('code='), '2b. TOTP owned but toggle OFF -> password-only login');

  // 2c. turn the toggle on — with a strong factor now enrolled, the toggle
  // demands a fresh sudo window (personal-security step-up gate); stamp the
  // session directly (the gate itself is covered by sso-security-stepup-test).
  r = await api('POST', '/account/mfa/enable');
  ok(r.status === 403 && ((await r.json()) as { error: string }).error === 'step_up_required',
     '2c0. toggle without step-up -> 403');
  const { rows: [stampSid] } = await pool.query<{ sid: string }>(
    `UPDATE sessions SET stepup_at = now() WHERE user_sub = $1
       AND created_at = (SELECT max(created_at) FROM sessions WHERE user_sub = $1)
     RETURNING sid`, [sub]);
  r = await fetch(SSO + '/account/mfa/enable', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + tok1.access_token, 'x-stepup-sid': stampSid.sid },
  });
  ok(r.status === 204, '2c. POST /account/mfa/enable -> 204', `(${r.status})`);

  // 3. next login -> challenge page instead of a code
  step = await passwordStep();
  let page = await step.r.text();
  ok(step.r.status === 200 && page.includes('Enter your code') && page.includes('/login/challenge'),
     '3. password now lands on the challenge page');
  ok(page.includes('<span>tester</span>'), '3a. challenge chip shows the TYPED username');
  // 3a2. logging in by email shows the full email in the chip
  {
    const p = pkce();
    let rr = await fetch(authzUrl(p.c), { redirect: 'manual' });
    const t2 = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
    rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(t2));
    const cs2 = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
    rr = await fetch(SSO + '/login', {
      method: 'POST', redirect: 'manual', headers: FORM,
      body: new URLSearchParams({ txn: t2, csrf: cs2, username: 'tester@example.com', password: PASS }),
    });
    ok((await rr.text()).includes('<span>tester@example.com</span>'),
       '3a2. login by email -> challenge chip shows the full email');
  }

  // 3b. refresh-safe: GET /login re-renders the challenge, not the password form
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(step.txn));
  page = await r.text();
  ok(page.includes('Enter your code') && !page.includes('name="password"'),
     '3b. GET /login in challenge phase -> challenge, never the password form');

  // 3c. re-POSTing the password can't bypass the challenge
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn: step.txn, csrf: step.csrf, username: USER, password: PASS }),
  });
  ok(r.status === 200 && (await r.text()).includes('Enter your code'), '3c. password re-POST -> still the challenge');

  // 4. wrong code -> error re-render; right code -> session + code
  const challenge = (code: string) =>
    fetch(SSO + '/login/challenge', {
      method: 'POST', redirect: 'manual', headers: FORM,
      body: new URLSearchParams({ txn: step.txn, csrf: step.csrf, method: 'totp', code }),
    });
  r = await challenge('000000');
  ok(r.status === 401 && (await r.text()).includes('incorrect or expired'), '4. wrong code -> error re-render');
  const { rows: [{ secret_enc }] } = await pool.query(
    'SELECT secret_enc FROM totp_credentials WHERE user_sub = $1 AND confirmed_at IS NOT NULL', [sub]);
  const { openSecret } = await import('../src/secretbox.js');
  r = await challenge(totpNow(openSecret(secret_enc)));
  const cookie = cookieOf(r); // transient cookie on the KMSI page (challenge succeeded)
  r = await answerKmsi(SSO, r, step.txn, step.csrf);
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.includes('code=') && !!cookie, '4a. right code -> session + code redirect');
  const tok2 = await exchange(new URL(loc).searchParams.get('code')!, step.verifier);
  const claims2 = decodeJwt(tok2.id_token);
  ok(JSON.stringify(claims2.amr) === '["pwd","otp"]' && claims2.acr === 'urn:dreamsso:2fa',
     '4b. amr [pwd,otp], acr 2fa', `(${JSON.stringify(claims2.amr)} ${claims2.acr})`);

  // 4c. txn consumed — challenge can't be replayed
  r = await challenge('000000');
  ok(r.status === 400 && (await r.text()).includes('txn_expired'), '4c. finished txn -> expired page');

  // 5. silent session reuse does NOT re-challenge
  const p5 = pkce();
  const silentUrl = new URL(SSO + '/authorize');
  silentUrl.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: p5.c, code_challenge_method: 'S256',
  }).toString();
  r = await fetch(silentUrl, { redirect: 'manual', headers: { cookie: cookie! } });
  loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.startsWith(REDIRECT) && loc.includes('code='), '5. silent reuse -> no re-challenge');

  // 6. attempt cap: 5 wrong codes burn the txn
  step = await passwordStep();
  let last: Response = step.r;
  for (let i = 0; i < 5; i++) {
    last = await fetch(SSO + '/login/challenge', {
      method: 'POST', redirect: 'manual', headers: FORM,
      body: new URLSearchParams({ txn: step.txn, csrf: step.csrf, method: 'totp', code: '111111' }),
    });
  }
  ok(last.status === 403 && (await last.text()).includes('too_many_attempts'), '6. 5 wrong codes -> txn burned');
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(step.txn));
  ok(r.status === 400 && (await r.text()).includes('txn_expired'), '6a. burned txn is gone');

  // 7. unconfirmed setup rows expire (15 min) — factor routes need the fresh
  // sudo window now, so re-stamp and ride the x-stepup-sid header.
  await pool.query(`UPDATE sessions SET stepup_at = now() WHERE sid = $1`, [stampSid.sid]);
  const gated = (path: string, body: unknown) =>
    fetch(SSO + path, {
      method: 'POST',
      headers: {
        authorization: 'Bearer ' + tok1.access_token,
        'x-stepup-sid': stampSid.sid,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
    });
  r = await gated('/account/mfa/authenticator/setup', { label: 'stale' });
  const stale = await r.json();
  await pool.query(`UPDATE totp_credentials SET created_at = now() - interval '20 minutes' WHERE id = $1`, [stale.id]);
  r = await gated('/account/mfa/authenticator/confirm', { id: stale.id, code: totpNow(stale.secret) });
  ok(r.status === 422, '7. stale (20 min) setup row cannot be confirmed', `(${r.status})`);
} finally {
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
