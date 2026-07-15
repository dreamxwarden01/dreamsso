// E2E for the email-OTP login challenge (the floor method — offered ONLY when the
// user owns no strong factor and the MFA toggle is on):
//   offer state ("Send a code to ma•••••@…"), explicit send (not on page load)
//   code captured via a MOCK Cloudflare API; wrong code / cooldown / resend-same-code
//   verify -> session, amr [pwd,email], acr 2fa
//   per-code attempt cap -> mustResend
// Snapshots/restores the raw settings rows + tester state. Run: npx tsx scripts/sso-mfa-email-test.ts
import http from 'node:http';
import crypto from 'node:crypto';
import { SignJWT, importJWK, decodeJwt } from 'jose';
import fs from 'node:fs';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { sealSecret } from '../src/secretbox.js';

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
  r = await answerKmsi(SSO, r, txn, csrf); // no-op when it's the email-offer challenge page
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

// mock CF email API — captures the sent html so the test can read the code
const inbox: string[] = [];
const mock = http.createServer((q, resp) => {
  let raw = '';
  q.on('data', (c) => (raw += c));
  q.on('end', () => {
    try { inbox.push(JSON.parse(raw).html ?? ''); } catch { inbox.push(''); }
    resp.setHeader('content-type', 'application/json');
    resp.end(JSON.stringify({ success: true, errors: [], result: { delivered: ['x'], permanent_bounces: [], queued: [] } }));
  });
});
await new Promise<void>((resolve) => mock.listen(8896, '127.0.0.1', resolve));
const codeFrom = (html: string) => (html.match(/>(\d{6})</) || [])[1];

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const MAIL_KEYS = ['mail_from', 'cf_account_id', 'cf_api_token', 'cf_api_base'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [MAIL_KEYS]);
const settle = () => new Promise((r) => setTimeout(r, 5500));

try {
  // isolate: no factors, toggle on, mail -> mock
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM webauthn_credentials WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM email_otps WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM email_otp_limits WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = true WHERE sub = $1', [sub]);
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [MAIL_KEYS]);
  await pool.query(
    `INSERT INTO settings (key, value) VALUES
       ('mail_from', 'no-reply@dreamxwarden.ca'),
       ('cf_account_id', $1),
       ('cf_api_token', $2),
       ('cf_api_base', 'http://127.0.0.1:8896')`,
    ['b'.repeat(32), 'enc:v1:' + sealSecret('mock-token').toString('base64')],
  );
  await settle();

  // 1. toggle on + only email -> challenge lands on the OFFER (no auto-send)
  let step = await passwordStep();
  let page = await step.r.text();
  ok(step.r.status === 200 && page.includes('Send a code to te•••••@example.com'),
     '1. email floor -> offer state with masked address');
  ok(inbox.length === 0, '1a. nothing sent on page load (send is a click)');

  const post = (path: string, body: Record<string, string>) =>
    fetch(SSO + path, { method: 'POST', redirect: 'manual', headers: FORM, body: new URLSearchParams(body) });

  // 2. send -> entry state + captured code
  let r = await post('/login/challenge/send-email', { txn: step.txn, csrf: step.csrf });
  page = await r.text();
  ok(r.status === 200 && page.includes('Check your email') && page.includes('Resend code in 60s'),
     '2. send -> entry state + cooldown note');
  ok(page.includes('expires in 5 minutes') && page.includes('resend-form') && page.includes('resend-wait'),
     '2c. expiry note + live countdown markup (hidden resend form ready)');
  const code1 = codeFrom(inbox[0] ?? '');
  ok(!!code1, '2a. code captured from the email', `(${code1})`);
  ok((inbox[0] ?? '').includes('DreamSSO'), '2b. email branded with site name');

  // 3. wrong code -> incorrect; cooldown blocks an instant resend
  r = await post('/login/challenge', { txn: step.txn, csrf: step.csrf, method: 'email', code: '000000' });
  ok(r.status === 401 && (await r.text()).includes('incorrect'), '3. wrong code -> error');
  r = await post('/login/challenge/send-email', { txn: step.txn, csrf: step.csrf });
  ok(r.status === 401 && (await r.text()).includes('Please wait'), '3a. resend inside cooldown -> wait message');

  // 4. resend after cooldown -> SAME code (reuse-in-window semantics)
  await pool.query(`UPDATE email_otp_limits SET last_sent = now() - interval '61 seconds' WHERE user_sub = $1`, [sub]);
  r = await post('/login/challenge/send-email', { txn: step.txn, csrf: step.csrf });
  const code2 = codeFrom(inbox[1] ?? '');
  ok(r.status === 200 && code2 === code1, '4. resend within validity -> the SAME code', `(${code2})`);

  // 5. right code -> session; amr [pwd,email], acr 2fa
  r = await post('/login/challenge', { txn: step.txn, csrf: step.csrf, method: 'email', code: code1! });
  const c5 = cookieOf(r); // transient cookie on the KMSI page
  r = await answerKmsi(SSO, r, step.txn, step.csrf);
  const loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.includes('code=') && !!c5, '5. right code -> session + code redirect');
  const tok = await exchange(new URL(loc).searchParams.get('code')!, step.verifier);
  const claims = decodeJwt(tok.id_token);
  ok(JSON.stringify(claims.amr) === '["pwd","email"]' && claims.acr === 'urn:dreamsso:2fa',
     '5a. amr [pwd,email], acr 2fa', `(${JSON.stringify(claims.amr)})`);

  // 6. per-code attempt cap -> mustResend
  await pool.query(`UPDATE email_otp_limits SET last_sent = now() - interval '61 seconds' WHERE user_sub = $1`, [sub]);
  step = await passwordStep();
  await post('/login/challenge/send-email', { txn: step.txn, csrf: step.csrf });
  let lastText = '';
  for (let i = 0; i < 5; i++) {
    const rr = await post('/login/challenge', { txn: step.txn, csrf: step.csrf, method: 'email', code: '999999' });
    lastText = await rr.text();
  }
  ok(lastText.includes('send a new one'), '6. 5 wrong codes -> mustResend message');
} finally {
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [MAIL_KEYS]);
  for (const row of origRows) {
    await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  }
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
  await pool.query('DELETE FROM email_otps WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM email_otp_limits WHERE user_sub = $1', [sub]);
  mock.close();
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
