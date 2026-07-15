// E2E for password reset (portal /forgot + /reset -> BFF gate -> SSO core):
//   input validation (username 3-20 [A-Za-z0-9_-], email <=254) both ends
//   uniform 204 (existing + nonexistent), async email via a MOCK CF API
//   latest-wins tokens; 3/24h per-email rate limit incl. window reset AND
//     the reserve/release-on-send-failure slot accounting
//   Turnstile gate at the BFF (always-pass test keys; missing token -> 403)
//   weak password -> 422; confirm -> sessions revoked + notification email
//   ticket hop: session on the SSO origin (amr [email]), KMSI chip, single-use
//   MFA path: toggle+TOTP -> challenge_required, wrong/right code, attempts cap
//   strong-factor reset pre-clears step-up (amr [email,otp] + stepup_at)
// Snapshots/restores tester's identity row + every settings row it touches.
// Run: npx tsx scripts/sso-password-reset-test.ts
import http from 'node:http';
import { generateSecret, generateSync } from 'otplib';
import { pool } from '../src/db.js';
import { redis } from '../src/redis.js';
import { sealSecret } from '../src/secretbox.js';
import { setSecretSetting } from '../src/settings.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const PORTAL = 'https://account-dev.dreamxwarden.ca';
const USER = 'tester';
const EMAIL = 'tester@example.com';
const PASS = 'Test1234!';
const NEWPASS = 'NewTest1234!';
const NEWPASS2 = 'NewTest12345!';
const MOCK_PORT = 8898;
const RL_KEY = `pwreset:rl:${EMAIL}`;

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const FORM = { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' } as const;

const bff = (path: string, body: Record<string, unknown>) =>
  fetch(PORTAL + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

// --- mock Cloudflare email API (cf_api_base override): captures every send ---
interface Mail { to: string; subject: string; html: string }
const mails: Mail[] = [];
let respond: 'ok' | 'reject' = 'ok';
const mock = http.createServer((q, resp) => {
  let raw = '';
  q.on('data', (c) => (raw += c));
  q.on('end', () => {
    resp.setHeader('content-type', 'application/json');
    if (respond === 'ok') {
      mails.push(JSON.parse(raw || '{}') as Mail);
      resp.end(JSON.stringify({ success: true, errors: [], result: { delivered: ['x'], permanent_bounces: [], queued: [] } }));
    } else {
      resp.statusCode = 403;
      resp.end(JSON.stringify({ success: false, errors: [{ message: 'mock rejection' }] }));
    }
  });
});
await new Promise<void>((resolve) => mock.listen(MOCK_PORT, '127.0.0.1', resolve));

// Match mails by CONTENT from a recorded index — notifications ("password was
// changed") are fired asynchronously after each successful confirm, so absolute
// indices into mails[] are a race.
const RESET_RE = /\/reset\?token=/;
const waitMailMatch = async (fromIdx: number, re: RegExp, ms = 5000): Promise<Mail | null> => {
  const t0 = Date.now();
  for (;;) {
    const m = mails.slice(fromIdx).find((x) => re.test(x.subject + ' ' + x.html));
    if (m) return m;
    if (Date.now() - t0 >= ms) return null;
    await sleep(100);
  }
};
const tokenOf = (m: Mail | null) => (m?.html.match(/\/reset\?token=([A-Za-z0-9_-]+)/) || [])[1] ?? '';

// --- snapshots (restore VERBATIM in finally — never nuke shared state) ---
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const { rows: [idSnap] } = await pool.query(
  'SELECT password_hash, password_changed_at, mfa_enabled FROM identities WHERE sub = $1', [sub]);
const TOUCHED = ['cf_api_base', 'turnstile_enabled', 'turnstile_site_key', 'turnstile_secret_key'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [TOUCHED]);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
// Age the limiter's last-send stamp past the 120s cooldown (so consecutive
// test sends exercise the COUNT rules, not the cooldown).
const coolOff = () => redis.hset(RL_KEY, 'last', String(Math.floor(Date.now() / 1000) - 121));

// Password login (videosite client txn) up to the KMSI page — the session
// already exists at that point; used to seed sessions for the revocation check.
async function passwordLogin(pass: string): Promise<Response> {
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: 'videosite', redirect_uri: 'https://stream-dev.dreamxwarden.ca/auth/callback',
    scope: 'openid profile email', state: 'x', nonce: 'y',
    code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  return fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn, csrf, username: USER, password: pass }),
  });
}

try {
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('UPDATE identities SET mfa_enabled = false WHERE sub = $1', [sub]);
  await redis.del(RL_KEY);
  await setDb('cf_api_base', `http://127.0.0.1:${MOCK_PORT}`);
  // Turnstile is ON exactly when both keys are set (no toggle) — clear them
  // so the early checks run gate-off. Snapshot above restores the real rows.
  await setDb('turnstile_site_key', null);
  await setDb('turnstile_secret_key', null);
  await sleep(5500); // settings cache

  // 1. input validation at the BFF
  let r = await bff('/api/reset/request', { identifier: 'ab' });
  ok(r.status === 422, '1. username too short -> 422', `(${r.status})`);
  r = await bff('/api/reset/request', { identifier: 'x'.repeat(21) });
  ok(r.status === 422, '1a. username too long -> 422');
  r = await bff('/api/reset/request', { identifier: 'bad!chars' });
  ok(r.status === 422, '1b. bad username charset -> 422');
  r = await bff('/api/reset/request', { identifier: 'foo@bar' });
  ok(r.status === 422, '1c. malformed email -> 422');

  // 2. uniform 204: nonexistent user sends nothing
  r = await bff('/api/reset/request', { identifier: 'nosuchuser99' });
  await sleep(700);
  ok(r.status === 204 && mails.length === 0, '2. unknown user -> 204, no email', `(${r.status}, ${mails.length})`);

  // 3. real user: 204 + reset email with the portal link
  r = await bff('/api/reset/request', { identifier: USER });
  const mail1 = await waitMailMatch(0, RESET_RE);
  ok(r.status === 204 && !!mail1, '3. tester -> 204 + email arrives');
  const token1 = tokenOf(mail1);
  ok(mail1?.to === EMAIL && /Reset your .* password/.test(mail1?.subject ?? '') && !!token1 &&
     !!mail1?.html.includes(`${PORTAL}/reset?token=`),
     '3a. email: to/subject/link', `(${mail1?.subject})`);

  // 3b. 120s cooldown: an immediate second request is silently dropped
  const n3b = mails.length;
  r = await bff('/api/reset/request', { identifier: USER });
  await sleep(1200);
  ok(r.status === 204 && mails.length === n3b, '3b. within 120s cooldown -> 204 but silently dropped');

  // 4. latest-wins: a second request invalidates the first link
  await coolOff();
  const n4 = mails.length;
  r = await bff('/api/reset/request', { identifier: EMAIL }); // by email this time
  const mail2 = await waitMailMatch(n4, RESET_RE);
  ok(r.status === 204 && !!mail2, '4. request by email -> 204 + email');
  const token2 = tokenOf(mail2);
  let v = await (await bff('/api/reset/validate', { token: token1 })).json();
  ok(v.valid === false, '4a. previous token invalidated (latest-wins)');
  v = await (await bff('/api/reset/validate', { token: token2 })).json();
  ok(v.valid === true && v.challenge === null, '4b. latest token valid, no challenge (MFA off)');

  // 5. rate limit: 3 per 24h, silent past the cap (coolOff isolates the
  // count rules from the 120s cooldown)
  await coolOff();
  const n5 = mails.length;
  await bff('/api/reset/request', { identifier: USER });
  ok(!!(await waitMailMatch(n5, RESET_RE)), '5. third send within the window still delivers');
  await coolOff();
  const n5a = mails.length;
  r = await bff('/api/reset/request', { identifier: USER });
  await sleep(1200);
  ok(r.status === 204 && mails.length === n5a, '5a. fourth request: 204 but silently dropped', `(${mails.length - n5a} extra)`);
  // window lapsed -> record CLEARED, fresh count of 1, email sent
  await redis.hset(RL_KEY, 'first', String(Math.floor(Date.now() / 1000) - 25 * 3600));
  const n5b = mails.length;
  await bff('/api/reset/request', { identifier: USER });
  ok(!!(await waitMailMatch(n5b, RESET_RE)), '5b. lapsed 24h window -> record reset, email sent');
  ok(Number(await redis.hget(RL_KEY, 'count')) === 1, '5b2. fresh record starts at count=1');
  // reserve/release: a FAILED send gives back the slot AND the cooldown
  await coolOff();
  respond = 'reject';
  await bff('/api/reset/request', { identifier: USER });
  await sleep(1200);
  const countAfterFail = Number(await redis.hget(RL_KEY, 'count'));
  const lastAfterFail = await redis.hget(RL_KEY, 'last');
  respond = 'ok';
  ok(countAfterFail === 1 && lastAfterFail === null,
     '5c. failed send releases the slot + cooldown', `(count=${countAfterFail}, last=${lastAfterFail})`);
  // 5d. after a failed send the record is NOT cleared (prior sends still
  // count) but last_sent=null is acceptable -> an immediate retry delivers
  const n5d = mails.length;
  await bff('/api/reset/request', { identifier: USER });
  ok(!!(await waitMailMatch(n5d, RESET_RE)), '5d. retry right after a failed send delivers (null last_sent accepted)');
  ok(Number(await redis.hget(RL_KEY, 'count')) === 2,
     '5d2. counter resumed from the rolled-back value, record intact', `(count=${await redis.hget(RL_KEY, 'count')})`);
  await redis.del(RL_KEY); // phase boundary: fresh budget for the rest

  // 6. Turnstile gate at the BFF (Cloudflare's always-pass test keys) —
  // setting both keys IS enabling (no toggle)
  await setDb('turnstile_site_key', '1x00000000000000000000AA');
  await setSecretSetting('turnstile_secret_key', '1x0000000000000000000000000000000AA');
  await sleep(11_000); // SSO settings cache (5s) + BFF gate-config cache (10s)
  r = await bff('/api/reset/request', { identifier: USER });
  ok(r.status === 403 && (await r.json()).error === 'turnstile_failed', '6. gate on, no token -> 403');
  const n6 = mails.length;
  r = await bff('/api/reset/request', { identifier: USER, turnstile_token: 'XXXX.DUMMY' });
  const mail6 = await waitMailMatch(n6, RESET_RE);
  ok(r.status === 204 && !!mail6, '6a. gate on, token verified via siteverify -> 204');
  const pub = await (await fetch(PORTAL + '/api/settings/public')).json();
  ok(pub.turnstile_site_key === '1x00000000000000000000AA', '6b. public settings expose the site key');
  await setDb('turnstile_site_key', null); // clearing the site key IS disabling
  await sleep(11_000);
  await redis.del(RL_KEY);
  const tokenA = tokenOf(mail6);

  // 7. weak password -> 422
  r = await bff('/api/reset/confirm', { token: tokenA, password: 'short' });
  ok(r.status === 422 && (await r.json()).error === 'weak_password', '7. weak password -> 422');
  r = await bff('/api/reset/confirm', { token: tokenA, password: 'alllowercase1' });
  ok(r.status === 422, '7a. <3 categories -> 422');

  // 8. confirm: password written, ALL sessions revoked, notification email
  await passwordLogin(PASS);
  await passwordLogin(PASS);
  const { rows: [{ n: before }] } = await pool.query(
    'SELECT count(*)::int AS n FROM sessions WHERE user_sub = $1', [sub]);
  ok(before >= 2, '8. two live sessions before confirm', `(${before})`);
  const n8 = mails.length;
  r = await bff('/api/reset/confirm', { token: tokenA, password: NEWPASS });
  const conf = await r.json();
  ok(r.status === 200 && typeof conf.complete_url === 'string' &&
     conf.complete_url.startsWith(SSO + '/reset/complete?ticket='),
     '8a. confirm -> complete_url', `(${r.status})`);
  const { rows: [{ n: after }] } = await pool.query(
    'SELECT count(*)::int AS n FROM sessions WHERE user_sub = $1', [sub]);
  ok(after === 0, '8b. every pre-reset session revoked', `(${after})`);
  const notif = await waitMailMatch(n8, /password was changed/i);
  ok(!!notif, '8c. "password was changed" notification sent');
  ok(!!notif && /password was changed/i.test(notif.subject) && notif.to === EMAIL,
     '8d. notification subject + recipient', `(${notif?.subject})`);

  // 9. token consumed
  v = await (await bff('/api/reset/validate', { token: tokenA })).json();
  ok(v.valid === false, '9. confirmed token is consumed');

  // 10. old password dead, new password lives
  r = await passwordLogin(PASS);
  ok(r.status === 401 && (await r.text()).includes('Invalid username or password'), '10. old password rejected');
  r = await passwordLogin(NEWPASS);
  ok(r.status === 200 && (await r.text()).includes('Stay signed in?'), '10a. new password -> KMSI');

  // 11. the ticket hop: session on the SSO origin -> KMSI -> portal login
  r = await fetch(conf.complete_url, { redirect: 'manual' });
  const rawCookie = (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session=')) ?? '';
  const cookie = rawCookie.split(';')[0];
  const loc = r.headers.get('location') || '';
  ok(r.status === 302 && loc.startsWith('/login?txn=') && !!cookie, '11. hop: transient session + KMSI redirect');
  ok(!/expires|max-age/i.test(rawCookie), '11a. hop cookie is browser-session (transient until KMSI says otherwise)');
  r = await fetch(SSO + loc, { headers: { cookie } });
  const kmsiPage = await r.text();
  ok(kmsiPage.includes('Stay signed in?') && kmsiPage.includes('<span>Test User</span>'),
     '11b. KMSI page, chip = display name');
  const kcsrf = (kmsiPage.match(/name="csrf" value="([^"]+)"/) || [])[1];
  const ktxn = new URL(SSO + loc).searchParams.get('txn')!;
  r = await fetch(SSO + '/login/stay', {
    method: 'POST', redirect: 'manual', headers: { ...FORM, cookie },
    body: new URLSearchParams({ txn: ktxn, csrf: kcsrf, choice: 'no' }),
  });
  ok(r.status === 302 && r.headers.get('location') === PORTAL + '/auth/login',
     '11c. KMSI answer -> portal /auth/login', `(${r.headers.get('location')})`);
  const { rows: [hopSess] } = await pool.query(
    'SELECT amr, persistent, stepup_at FROM sessions WHERE user_sub = $1 ORDER BY created_at DESC LIMIT 1', [sub]);
  ok(JSON.stringify(hopSess.amr) === '["email"]' && hopSess.persistent === false && hopSess.stepup_at === null,
     '11d. hop session: amr [email], transient, NO step-up pre-clearance', `(${JSON.stringify(hopSess.amr)})`);

  // 12. ticket is single-use
  r = await fetch(conf.complete_url, { redirect: 'manual' });
  ok(r.status === 400 && (await r.text()).includes('ticket_expired'), '12. ticket replay -> expired page');

  // 13. MFA path: toggle on + confirmed TOTP -> challenge demanded
  const secret = generateSecret();
  await pool.query(
    `INSERT INTO totp_credentials (user_sub, label, secret_enc, confirmed_at) VALUES ($1, 'pwreset-e2e', $2, now())`,
    [sub, sealSecret(secret)]);
  await pool.query('UPDATE identities SET mfa_enabled = true WHERE sub = $1', [sub]);
  const n13 = mails.length;
  await bff('/api/reset/request', { identifier: USER });
  const mailM = await waitMailMatch(n13, RESET_RE);
  ok(!!mailM, '13. reset email under MFA');
  const tokenM = tokenOf(mailM);
  v = await (await bff('/api/reset/validate', { token: tokenM })).json();
  ok(v.valid === true && v.challenge && JSON.stringify(v.challenge.methods) === '["totp"]' &&
     v.challenge.label === 'Test User',
     '13a. validate: challenge methods [totp], label = display name', `(${JSON.stringify(v.challenge)})`);

  // 14. confirm without solving -> challenge_required (no attempt burned)
  r = await bff('/api/reset/confirm', { token: tokenM, password: NEWPASS2 });
  let d = await r.json();
  ok(r.status === 401 && d.error === 'challenge_required' && d.challenge?.methods?.includes('totp'),
     '14. confirm without method -> challenge_required');

  // 15. wrong code -> challenge_failed with attempts_left
  r = await bff('/api/reset/confirm', { token: tokenM, password: NEWPASS2, method: 'totp', code: '000000' });
  d = await r.json();
  ok(r.status === 401 && d.error === 'challenge_failed' && d.attempts_left === 4,
     '15. wrong code -> challenge_failed, 4 left', `(${JSON.stringify(d)})`);

  // 16. right code -> success; strong-factor reset PRE-CLEARS step-up
  r = await bff('/api/reset/confirm', {
    token: tokenM, password: NEWPASS2, method: 'totp',
    code: generateSync({ secret, strategy: 'totp' }),
  });
  d = await r.json();
  ok(r.status === 200 && typeof d.complete_url === 'string', '16. right code -> confirm succeeds');
  r = await fetch(d.complete_url, { redirect: 'manual' });
  ok(r.status === 302, '16a. second ticket redeems');
  const { rows: [strongSess] } = await pool.query(
    'SELECT amr, stepup_at FROM sessions WHERE user_sub = $1 ORDER BY created_at DESC LIMIT 1', [sub]);
  ok(JSON.stringify(strongSess.amr) === '["email","otp"]' && strongSess.stepup_at !== null,
     '16b. session amr [email,otp] + step-up pre-cleared', `(${JSON.stringify(strongSess.amr)})`);

  // 17. attempts cap: 5 wrong codes burn the token (check 16's async
  // notification email may interleave here — matched by content, not index)
  await redis.del(RL_KEY);
  const n17 = mails.length;
  await bff('/api/reset/request', { identifier: USER });
  const mailC = await waitMailMatch(n17, RESET_RE);
  ok(!!mailC, '17. fresh link for the cap check');
  const tokenC = tokenOf(mailC);
  let last: Response = r;
  for (let i = 0; i < 5; i++) {
    last = await bff('/api/reset/confirm', { token: tokenC, password: NEWPASS2, method: 'totp', code: '111111' });
  }
  ok(last.status === 403 && (await last.json()).error === 'too_many_attempts', '17a. fifth wrong code -> burned');
  v = await (await bff('/api/reset/validate', { token: tokenC })).json();
  ok(v.valid === false, '17b. burned token invalid');

  // 18. the SSO internal API rejects calls without the portal's assertion
  r = await fetch(SSO + '/internal/reset/request', {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ identifier: USER }),
  });
  ok(r.status === 401 && (await r.json()).error === 'invalid_client', '18. internal API without assertion -> 401');
} finally {
  // Restore tester VERBATIM (hash + changed_at + toggle), drop test factors,
  // clear test sessions (tester is the throwaway test login), restore settings
  // rows exactly as found, and clear reset-flow redis keys.
  await pool.query(
    'UPDATE identities SET password_hash = $2, password_changed_at = $3, mfa_enabled = $4 WHERE sub = $1',
    [sub, idSnap.password_hash, idSnap.password_changed_at, idSnap.mfa_enabled]);
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM sessions WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM settings WHERE key = ANY($1)', [TOUCHED]);
  for (const row of origRows) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  const ptr = await redis.get(`pwreset:user:${sub}`);
  if (ptr) await redis.del(`pwreset:tok:${ptr}`, `pwreset:pk:${ptr}`);
  await redis.del(`pwreset:user:${sub}`, RL_KEY);
  mock.close();
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
redis.disconnect();
process.exit(fail ? 1 : 0);
