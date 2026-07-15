// E2E for email verification (verify-then-commit):
//   gate tiers (user rule): stepup w/ strong factor -> current-email OTP ->
//     current password (no email = the add case)
//   nothing swaps until the emailed link is clicked; old address stays live
//   pending change RESERVES its target address (shared uniqueness family)
//   single-use verify token; change notice to the OLD address AFTER commit
//   confirm-current flow clears a legacy Unverified pill
// Snapshots/restores tester's identity + settings rows; drives everything
// through the PORTAL BFF like a real browser session.
// Run: npx tsx scripts/sso-email-change-test.ts
import http from 'node:http';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { redis } from '../src/redis.js';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const MOCK_PORT = 8900;
const NEW1 = 'chg-new-1@example.com';
const NEW2 = 'chg-new-2@example.com';
const RESERVED = 'chg-reserved@example.com';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// --- mock CF mail ---
interface Mail { to: string; subject: string; html: string }
const mails: Mail[] = [];
const mock = http.createServer((q, resp) => {
  let raw = '';
  q.on('data', (c) => (raw += c));
  q.on('end', () => {
    mails.push(JSON.parse(raw || '{}') as Mail);
    resp.setHeader('content-type', 'application/json');
    resp.end(JSON.stringify({ success: true, errors: [], result: { delivered: ['x'], permanent_bounces: [], queued: [] } }));
  });
});
await new Promise<void>((resolve) => mock.listen(MOCK_PORT, '127.0.0.1', resolve));
const waitMail = async (fromIdx: number, re: RegExp, ms = 5000): Promise<Mail | null> => {
  const t0 = Date.now();
  for (;;) {
    const m = mails.slice(fromIdx).find((x) => re.test(x.to + ' ' + x.subject + ' ' + x.html));
    if (m) return m;
    if (Date.now() - t0 >= ms) return null;
    await sleep(100);
  }
};
const linkToken = (m: Mail | null) => (m?.html.match(/\/verify-email\?token=([A-Za-z0-9_-]+)/) || [])[1] ?? '';
const otpCode = (m: Mail | null) => ((m?.subject + ' ' + m?.html).match(/\b(\d{6})\b/) || [])[1] ?? '';

// --- BFF session (cookie jar + portal login) ---
const jar: Record<string, string> = {};
const absorb = (r: Response) => {
  for (const c of (r.headers.getSetCookie?.() ?? [])) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
};
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
const api = (method: string, path: string, body?: unknown) =>
  fetch(BFF + path, {
    method,
    headers: { cookie: cookie(), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
    body: body !== undefined ? JSON.stringify(body) : undefined,
  });

// --- snapshots ---
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const { rows: [snap] } = await pool.query(
  'SELECT email, email_verified FROM identities WHERE sub = $1', [sub]);
const { rows: origSettings } = await pool.query(
  "SELECT key, value FROM settings WHERE key = 'cf_api_base'");
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
const cleanRedis = async () => {
  for (const e of [snap.email, NEW1, NEW2, RESERVED]) {
    if (e) await redis.del(`emailchg:addr:${String(e).toLowerCase()}`, `reg:pending:${String(e).toLowerCase()}`, `reg:rl:${String(e).toLowerCase()}`);
  }
  const h = await redis.get(`emailchg:user:${sub}`);
  if (h) await redis.del(`emailchg:tok:${h}`);
  await redis.del(`emailchg:user:${sub}`);
};
const coolOff = (email: string) =>
  redis.hset(`reg:rl:${email.toLowerCase()}`, 'last', String(Math.floor(Date.now() / 1000) - 300));

try {
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1', [sub]);
  await pool.query("DELETE FROM email_otps WHERE user_sub = $1 AND purpose = 'email_change'", [sub]);
  await pool.query('DELETE FROM email_otp_limits WHERE user_sub = $1', [sub]);
  await cleanRedis();
  await setDb('cf_api_base', `http://127.0.0.1:${MOCK_PORT}`);
  await sleep(5500); // settings cache

  // login into the portal
  let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  absorb(r);
  r = await fetch(r.headers.get('location')!, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf);
  const cb = new URL(r.headers.get('location')!);
  r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code')!)}&state=${encodeURIComponent(cb.searchParams.get('state')!)}`,
    { redirect: 'manual', headers: { cookie: cookie() } });
  absorb(r);
  ok(!!jar.acct_sid, '0. portal login');
  if (!jar.acct_sid) process.exit(1);

  // 1. tier detection: no strong factors + has email -> email_otp
  r = await api('GET', '/api/email-change');
  let d = await r.json();
  ok(r.status === 200 && d.gate === 'email_otp' && d.email === snap.email && d.pending === null,
    '1. gate = email_otp (no strong factors, has email)', `(${d.gate})`);

  // 2. start without the code -> refused before anything happens
  r = await api('POST', '/api/email-change/start', { new_email: NEW1 });
  ok(r.status === 401 && (await r.json()).error === 'invalid_code', '2. no OTP -> 401 invalid_code');

  // 3. OTP send -> code lands at the CURRENT address
  const n3 = mails.length;
  r = await api('POST', '/api/email-change/otp/send', {});
  const otpMail = await waitMail(n3, /verification code/i);
  const code = otpCode(otpMail);
  ok(r.status === 200 && otpMail?.to === snap.email && code.length === 6,
    '3. OTP sent to the CURRENT address', `(${otpMail?.to})`);

  // 4. reserved target (in-flight registration) -> 409 even with a right code
  await redis.set(`reg:pending:${RESERVED}`, JSON.stringify({ token: 'x', code: null, createdAt: 0, lastSent: 0 }), 'EX', 600);
  r = await api('POST', '/api/email-change/start', { new_email: RESERVED, otp_code: code });
  ok(r.status === 409 && (await r.json()).errors?.new_email === 'email_taken',
    '4. registration-reserved address -> 409 email_taken');

  // early availability probe (step 1 of the modal) — no challenge spent
  r = await api('POST', '/api/email-change/check', { new_email: RESERVED });
  ok(r.status === 409, '4a. early check flags the reserved address');
  r = await api('POST', '/api/email-change/check', { new_email: snap.email });
  ok(r.status === 422 && (await r.json()).errors?.new_email === 'same_email', '4b. early check flags same-address');
  r = await api('POST', '/api/username-change/check', { new_username: 'whatever1' });
  ok(r.status === 403, '4c. username early check honors the permission');

  // 5. wrong code -> 401 (attempts count)
  r = await api('POST', '/api/email-change/start', { new_email: NEW1, otp_code: code === '111111' ? '222222' : '111111' });
  ok(r.status === 401, '5. wrong OTP -> 401');

  // 6. right code -> pending change; NOTHING swaps yet
  const n6 = mails.length;
  r = await api('POST', '/api/email-change/start', { new_email: NEW1, otp_code: code });
  d = await r.json();
  const verifyMail = await waitMail(n6, /Confirm your new/i);
  const token1 = linkToken(verifyMail);
  ok(r.status === 200 && d.sent === true && verifyMail?.to === NEW1 && !!token1,
    '6. start -> verify link to the NEW address', `(${verifyMail?.to})`);
  const { rows: [mid] } = await pool.query('SELECT email FROM identities WHERE sub = $1', [sub]);
  ok(mid.email === snap.email, '6a. identities email UNCHANGED until the click (verify-then-commit)');
  r = await api('GET', '/api/email-change');
  d = await r.json();
  ok(d.pending?.kind === 'change' && d.pending?.new_email === NEW1, '6b. pending visible on the row');

  // 7. bad token refused; real token commits + notifies the OLD address
  r = await fetch(BFF + '/api/verify-email', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: 'x'.repeat(43) }),
  });
  ok(r.status === 422, '7. bogus token -> 422');
  const n7 = mails.length;
  r = await fetch(BFF + '/api/verify-email', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: token1 }),
  });
  d = await r.json();
  const { rows: [after] } = await pool.query('SELECT email, email_verified FROM identities WHERE sub = $1', [sub]);
  ok(r.status === 200 && d.kind === 'change' && after.email === NEW1 && after.email_verified === true,
    '7a. verify -> swapped + VERIFIED', `(${after.email})`);
  const notice = await waitMail(n7, /email address was changed/i);
  ok(notice?.to === snap.email, '7b. change notice to the OLD address, after commit', `(${notice?.to})`);
  r = await fetch(BFF + '/api/verify-email', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: token1 }),
  });
  ok(r.status === 422, '7c. token is single-use');
  r = await api('GET', '/api/email-change');
  ok((await r.json()).pending === null, '7d. pending cleared');

  // 8. confirm-current flow: legacy Unverified -> Verify -> link -> verified
  await pool.query('UPDATE identities SET email_verified = false WHERE sub = $1', [sub]);
  await coolOff(NEW1);
  const n8 = mails.length;
  r = await api('POST', '/api/email/verify/send', {});
  const confirmMail = await waitMail(n8, /Verify your/i);
  const token2 = linkToken(confirmMail);
  ok(r.status === 200 && confirmMail?.to === NEW1 && !!token2, '8. confirm-current link sent');
  r = await fetch(BFF + '/api/verify-email', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: token2 }),
  });
  d = await r.json();
  const { rows: [conf] } = await pool.query('SELECT email_verified FROM identities WHERE sub = $1', [sub]);
  ok(r.status === 200 && d.kind === 'confirm' && conf.email_verified === true, '8a. confirm -> verified, no swap');

  // 9. tier A: strong factor -> stepup gate; stale sudo -> 403; stamped -> ok
  await pool.query(
    `INSERT INTO totp_credentials (user_sub, label, secret_enc, confirmed_at)
     VALUES ($1, 'org-emailchg-test', '\\x00'::bytea, now())`, [sub]);
  r = await api('GET', '/api/email-change');
  ok((await r.json()).gate === 'stepup', '9. strong factor -> gate = stepup');
  await pool.query('UPDATE sessions SET stepup_at = NULL WHERE user_sub = $1', [sub]);
  await coolOff(NEW2);
  r = await api('POST', '/api/email-change/start', { new_email: NEW2 });
  ok(r.status === 403 && (await r.json()).error === 'step_up_required', '9a. stale sudo window -> 403');
  await pool.query('UPDATE sessions SET stepup_at = now() WHERE user_sub = $1', [sub]);
  r = await api('POST', '/api/email-change/start', { new_email: NEW2 });
  ok(r.status === 200 && (await r.json()).sent === true, '9b. fresh sudo -> verify link sent');

  // 10. cancel frees the reservation
  r = await api('DELETE', '/api/email-change');
  ok(r.status === 204, '10. cancel -> 204');
  ok((await redis.exists(`emailchg:addr:${NEW2}`)) === 0, '10a. reservation freed');

  // 11. tier C: no strong factors + no email -> password gate (the add case)
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1 AND label = $2', [sub, 'org-emailchg-test']);
  await pool.query('UPDATE identities SET email = NULL, email_verified = false WHERE sub = $1', [sub]);
  r = await api('GET', '/api/email-change');
  ok((await r.json()).gate === 'password', '11. no email -> gate = password');
  await coolOff(NEW2);
  r = await api('POST', '/api/email-change/start', { new_email: NEW2, password: 'WrongPass1!' });
  ok(r.status === 401 && (await r.json()).error === 'invalid_password', '11a. wrong password -> 401');
  const n11 = mails.length;
  r = await api('POST', '/api/email-change/start', { new_email: NEW2, password: PASS });
  const addMail = await waitMail(n11, /Confirm your new/i);
  ok(r.status === 200 && addMail?.to === NEW2, '11b. right password -> add-flow link sent');
  r = await fetch(BFF + '/api/verify-email', {
    method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: linkToken(addMail) }),
  });
  const { rows: [added] } = await pool.query('SELECT email, email_verified FROM identities WHERE sub = $1', [sub]);
  ok(r.status === 200 && added.email === NEW2 && added.email_verified === true,
    '11c. add committed + verified (no old address -> no notice)');

  // 12. same-address change refused
  r = await api('POST', '/api/email-change/start', { new_email: NEW2, password: PASS });
  ok(r.status === 422 && (await r.json()).errors?.new_email === 'same_email', '12. same address -> 422');

  // 13. username change: permission-gated (superadmin-only by default)...
  r = await api('POST', '/api/username-change', { new_username: 'tester_chg', password: PASS });
  ok(r.status === 403 && (await r.json()).error === 'permission_denied', '13. no perm -> 403 permission_denied');

  // ...but with the perm, the SAME one-time gate applies
  await pool.query(
    `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'profile.username.change', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
  r = await api('POST', '/api/username-change', { new_username: 'DEMO' });
  ok(r.status === 409 && (await r.json()).errors?.new_username === 'username_taken',
    '13a. case-variant of a taken username -> 409 BEFORE the gate (citext + no code burned)');
  r = await api('POST', '/api/username-change', { new_username: 'TESTER' });
  ok(r.status === 422 && (await r.json()).errors?.new_username === 'same_username', '13b. own name case-variant -> same_username');
  r = await api('POST', '/api/username-change', { new_username: 'tester_chg' });
  ok(r.status === 401 && (await r.json()).error === 'invalid_code', '13c. gate enforced (tier B here) -> 401 without a code');
  const n13 = mails.length;
  // the OTP module's own 60s per-user cooldown — age it out for the test
  await pool.query("UPDATE email_otp_limits SET last_sent = now() - interval '2 minutes' WHERE user_sub = $1", [sub]);
  r = await api('POST', '/api/email-change/otp/send', {});
  const unMail = await waitMail(n13, /verification code/i);
  const unCode = otpCode(unMail);
  ok(r.status === 200 && unMail?.to === NEW2 && unCode.length === 6, '13d. gate OTP goes to the CURRENT (new) address');
  r = await api('POST', '/api/username-change', { new_username: 'tester_chg', otp_code: unCode });
  const { rows: [renamed] } = await pool.query('SELECT username FROM identities WHERE sub = $1', [sub]);
  ok(r.status === 200 && renamed.username === 'tester_chg', '13e. right code -> username committed', `(${renamed.username})`);
  await pool.query('UPDATE identities SET username = $2 WHERE sub = $1', [sub, USER]);
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.username.change'`, [sub]);
} finally {
  await pool.query('UPDATE identities SET email = $2, email_verified = $3, username = $4 WHERE sub = $1',
    [sub, snap.email, snap.email_verified, USER]);
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.username.change'`, [sub]);
  await pool.query('DELETE FROM totp_credentials WHERE user_sub = $1 AND label = $2', [sub, 'org-emailchg-test']);
  await pool.query("DELETE FROM email_otps WHERE user_sub = $1 AND purpose = 'email_change'", [sub]);
  await pool.query('DELETE FROM email_otp_limits WHERE user_sub = $1', [sub]);
  await pool.query('DELETE FROM sessions WHERE user_sub = $1', [sub]);
  await pool.query("DELETE FROM org_audit_log WHERE actor_sub = $1 AND (action LIKE 'email.%' OR action = 'username.change')", [sub]);
  await cleanRedis();
  await setDb('cf_api_base', null);
  for (const row of origSettings) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  mock.close();
}

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
redis.disconnect();
process.exit(fail ? 1 : 0);
