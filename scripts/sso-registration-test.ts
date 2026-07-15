// E2E for self-serve registration (portal /register/start + /register/complete
// -> BFF gate -> SSO core):
//   toggles (enable_registration / require_invitation_code) incl. fail-closed
//   check ORDER: invitation code BEFORE any identities lookup (user rule)
//   invitation codes: 12x A-Z0-9, case-insensitive entry, single consumption,
//     use-limit = 3 EMAIL SWITCHES (same-email resends free, 4th switch voids),
//     switch evicts the previous pending link, consumed row kept with used_by
//   pending links: 30min, same-token resend window, eviction, dead-code kill
//   stateful send limiter (5/24h, escalating backoff, honest 429s)
//   complete: aggregate 422s, case-insensitive username/email uniqueness,
//     role-per-invite, email_verified=true, /welcome single-use ticket hop
//   login page "Create an account" link tracks the toggle
// Snapshots/restores every settings row it touches; deletes its own accounts,
// codes, and Redis keys. Run: npx tsx scripts/sso-registration-test.ts
import http from 'node:http';
import { pool } from '../src/db.js';
import { redis } from '../src/redis.js';
import { voidInvite, sweepInvitations, pendingEmailExists } from '../src/registration.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const PORTAL = 'https://account-dev.dreamxwarden.ca';
const MOCK_PORT = 8899;
const EM = (n: string) => `regtest-${n}@example.com`;
const NEW_USER = 'reg_smoke_1';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

const bff = (path: string, body: Record<string, unknown>) =>
  fetch(PORTAL + path, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });

// --- mock Cloudflare email API ---
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
const lastLink = () => {
  const m = mails[mails.length - 1]?.html.match(/\/register\/complete\?email=([^&"]+)&(?:amp;)?token=([0-9a-f]+)/);
  return m ? { email: decodeURIComponent(m[1]), token: m[2] } : null;
};

// --- snapshots ---
const TOUCHED = ['cf_api_base', 'turnstile_site_key', 'turnstile_secret_key', 'enable_registration', 'require_invitation_code'];
const { rows: origRows } = await pool.query<{ key: string; value: string }>(
  'SELECT key, value FROM settings WHERE key = ANY($1)', [TOUCHED]);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
const { rows: [{ sub: testerSub }] } = await pool.query("SELECT sub FROM identities WHERE username = 'tester'");
const madeCodes: string[] = [];
const mkCode = async (code: string, role = 'standard_user', hours = 72): Promise<string> => {
  await pool.query(
    `INSERT INTO invitation_codes (code, created_by, created_by_label, invited_role_slug, expires_at, clear_at)
     VALUES ($1, $2, 'Reg Test', $3, now() + make_interval(hours => $4),
             now() + make_interval(hours => $4) + interval '24 hours')`,
    [code, testerSub, role, hours]);
  madeCodes.push(code);
  return code;
};
const codeRow = async (code: string) =>
  (await pool.query('SELECT * FROM invitation_codes WHERE code = $1', [code])).rows[0] ?? null;
// Skip the escalating backoff between deliberate sends (count rules under test).
const coolOff = (email: string) =>
  redis.hset(`reg:rl:${email.toLowerCase()}`, 'last', String(Math.floor(Date.now() / 1000) - 300));

try {
  await setDb('cf_api_base', `http://127.0.0.1:${MOCK_PORT}`);
  await setDb('turnstile_site_key', null);
  await setDb('turnstile_secret_key', null);
  await setDb('enable_registration', 'false');
  await setDb('require_invitation_code', 'true');
  await sleep(5500); // settings cache

  // 1. fail-closed: registration disabled
  let r = await bff('/api/register/start', { email: EM('a'), code: 'AAAABBBBCCCC' });
  ok(r.status === 403 && (await r.json()).error === 'registration_closed', '1. disabled -> 403 registration_closed', `(${r.status})`);

  await setDb('enable_registration', 'true');
  await sleep(5500);

  // 2. check order: a TAKEN email with a BAD code must fail on the CODE —
  // identities are never consulted without a valid invitation.
  r = await bff('/api/register/start', { email: 'tester@example.com', code: 'ZZZZZZZZZZZZ' });
  let d = await r.json();
  ok(r.status === 422 && d.errors?.code === 'invalid_code' && !d.errors?.email,
    '2. bad code + taken email -> code error only (order proof)');
  r = await bff('/api/register/start', { email: EM('a') });
  d = await r.json();
  ok(r.status === 422 && d.errors?.code === 'invalid_code', '2a. missing code while required -> 422');

  // 3. valid code + taken email -> honest email_taken (code-holders are semi-trusted)
  const c1 = await mkCode('REGTESTAAA01');
  r = await bff('/api/register/start', { email: 'tester@example.com', code: c1.toLowerCase() });
  d = await r.json();
  ok(r.status === 422 && d.errors?.email === 'email_taken', '3. valid code (lowercase entry ok) + taken email -> email_taken');

  // 4. happy start: sent + backoff + link; use 1 claimed
  const n4 = mails.length;
  r = await bff('/api/register/start', { email: EM('a'), code: c1 });
  d = await r.json();
  const link4 = lastLink();
  ok(r.status === 200 && d.sent === true && d.resend_backoff > 0 && mails.length === n4 + 1 && !!link4,
    '4. start -> sent + backoff + emailed link', `(backoff ${d.resend_backoff})`);
  ok((await codeRow(c1)).use_count === 1 && (await codeRow(c1)).pending_email === EM('a'), '4a. use 1 claimed, pending stamped');

  // 5. same-email resend: same token, use_count still 1 (free)
  await coolOff(EM('a'));
  r = await bff('/api/register/start', { email: EM('a'), code: c1 });
  const link5 = lastLink();
  ok(r.status === 200 && link5?.token === link4!.token && (await codeRow(c1)).use_count === 1,
    '5. same-email resend -> SAME token, use not counted');

  // 6. email switch: use 2, previous pending evicted
  await coolOff(EM('b'));
  r = await bff('/api/register/start', { email: EM('b'), code: c1 });
  ok(r.status === 200 && (await codeRow(c1)).use_count === 2, '6. switch to B -> use 2');
  r = await bff('/api/register/validate', { email: EM('a'), token: link4!.token });
  ok(r.status === 422, '6a. A\'s link died with the switch');

  // 7. switches C (use 3) then D -> code voided (deleted), pending killed
  await coolOff(EM('c'));
  r = await bff('/api/register/start', { email: EM('c'), code: c1 });
  ok(r.status === 200 && (await codeRow(c1)).use_count === 3, '7. switch to C -> use 3 (cap)');
  const linkC = lastLink();
  await coolOff(EM('d'));
  r = await bff('/api/register/start', { email: EM('d'), code: c1 });
  d = await r.json();
  const c1row = await codeRow(c1);
  ok(r.status === 422 && d.errors?.code === 'invalid_code' &&
     c1row?.voided_at != null && c1row?.clear_at != null && c1row?.pending_email === null,
    '7a. 4th switch -> VOIDED (marked, kept 24h, pending cleared)');
  r = await bff('/api/register/validate', { email: EM('c'), token: linkC!.token });
  ok(r.status === 422, '7b. C\'s pending died with the void');

  // 8. full completion on a fresh code carrying a ROLE (role-per-invite)
  const c2 = await mkCode('REGTESTAAA02', 'admin');
  await coolOff(EM('e'));
  r = await bff('/api/register/start', { email: EM('e'), code: c2 });
  const link8 = lastLink();
  ok(r.status === 200 && !!link8, '8. start on role-carrying code');
  r = await bff('/api/register/validate', { email: EM('e'), token: link8!.token });
  ok(r.status === 200 && (await r.json()).valid === true, '8a. validate -> ok');

  // 9. on-blur availability: case-insensitive taken + free
  r = await bff('/api/register/check-username', { email: EM('e'), token: link8!.token, username: 'TESTER' });
  ok(r.status === 200 && (await r.json()).available === false, '9. check-username TESTER -> taken (citext)');
  r = await bff('/api/register/check-username', { email: EM('e'), token: link8!.token, username: NEW_USER });
  ok(r.status === 200 && (await r.json()).available === true, '9a. fresh username -> available');

  // 10. complete: aggregate 422; ci username collision; confirm mismatch at BFF
  r = await bff('/api/register/complete', {
    email: EM('e'), token: link8!.token, username: 'x!', display_name: '', password: 'weak', confirm_password: 'weak',
  });
  d = await r.json();
  ok(r.status === 422 && d.errors?.username && d.errors?.display_name && d.errors?.password,
    '10. bad everything -> ALL field errors in one 422');
  r = await bff('/api/register/complete', {
    email: EM('e'), token: link8!.token, username: 'Tester', display_name: 'Reg Smoke', password: 'RegTest1234!', confirm_password: 'RegTest1234!',
  });
  d = await r.json();
  ok(r.status === 422 && d.errors?.username === 'username_taken', '10a. case-variant of taken username -> 422 (citext)');
  r = await bff('/api/register/complete', {
    email: EM('e'), token: link8!.token, username: NEW_USER, display_name: 'Reg Smoke', password: 'RegTest1234!', confirm_password: 'Different1!',
  });
  ok(r.status === 422 && (await r.json()).errors?.confirm === 'mismatch', '10b. confirm mismatch stops at the BFF');

  // 11. happy completion
  r = await bff('/api/register/complete', {
    email: EM('e'), token: link8!.token, username: NEW_USER, display_name: 'Reg Smoke', password: 'RegTest1234!', confirm_password: 'RegTest1234!',
  });
  d = await r.json();
  ok(r.status === 200 && typeof d.complete_url === 'string' && d.complete_url.includes('/welcome?ticket='),
    '11. complete -> complete_url', `(${r.status})`);
  const { rows: [made] } = await pool.query(
    `SELECT i.sub, i.email, i.email_verified, ur.org_role_slug FROM identities i
       LEFT JOIN user_org_roles ur ON ur.user_sub = i.sub WHERE i.username = $1 AND i.deleted_at IS NULL`, [NEW_USER]);
  ok(!!made && made.email === EM('e') && made.email_verified === true, '11a. identity created, email VERIFIED (link proof)');
  ok(made?.org_role_slug === 'admin', '11b. role-per-invite honored (admin)', `(${made?.org_role_slug})`);
  const rowC2 = await codeRow(c2);
  ok(rowC2 && rowC2.used_by === made.sub && rowC2.used_at != null && rowC2.pending_email === null &&
     rowC2.clear_at === null && rowC2.voided_at === null,
    '11c. code consumed -> PERMANENT record (clear_at NULL)');
  r = await bff('/api/register/validate', { email: EM('e'), token: link8!.token });
  ok(r.status === 422, '11d. pending consumed with the account');

  // 12. /welcome hop: session + single-use ticket
  r = await fetch(d.complete_url, { redirect: 'manual' });
  const cookie = (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='));
  ok(r.status === 302 && (r.headers.get('location') || '').startsWith('/login?txn=') && !!cookie,
    '12. /welcome -> session + KMSI txn', `(${r.status})`);
  const kmsiPage = await (await fetch(SSO + (r.headers.get('location') || ''))).text();
  ok(/Stay signed in|stay signed in/i.test(kmsiPage), '12a. KMSI page renders');
  r = await fetch(d.complete_url, { redirect: 'manual' });
  ok(r.status === 400, '12b. ticket is single-use', `(${r.status})`);

  // 13. stateful limiter: immediate resend -> honest 429 with retry_after
  const c3 = await mkCode('REGTESTAAA03');
  r = await bff('/api/register/start', { email: EM('f'), code: c3 });
  ok(r.status === 200, '13. first send ok');
  r = await bff('/api/register/start', { email: EM('f'), code: c3 });
  d = await r.json();
  ok(r.status === 429 && d.can_retry === true && d.retry_after > 0 && d.retry_after <= 60,
    '13a. immediate resend -> 429 retry_after<=60 can_retry', `(${d.retry_after})`);
  // burn through the daily cap (5) with cooloffs
  for (let i = 0; i < 4; i++) {
    await coolOff(EM('f'));
    await bff('/api/register/start', { email: EM('f'), code: c3 });
  }
  await coolOff(EM('f'));
  r = await bff('/api/register/start', { email: EM('f'), code: c3 });
  d = await r.json();
  ok(r.status === 429 && d.can_retry === false, '13b. over 5/24h -> 429 can_retry:false', `(${r.status})`);

  // 14. void (same helper the org endpoint uses) kills the in-flight link,
  // marks + keeps the row, and the sweeper clears it only past clear_at
  const { rows: [c3row] } = await pool.query('SELECT pending_email FROM invitation_codes WHERE code = $1', [c3]);
  await voidInvite(c3, c3row?.pending_email ?? null);
  const linkF = lastLink();
  r = await bff('/api/register/validate', { email: EM('f'), token: linkF?.token ?? 'x'.repeat(96) });
  const c3after = await codeRow(c3);
  ok(r.status === 422 && c3after?.voided_at != null, '14. voided code -> marked + its link is dead');
  await sweepInvitations();
  ok((await codeRow(c3)) != null, '14a. sweep keeps the voided row inside its 24h window');
  await pool.query(`UPDATE invitation_codes SET clear_at = now() - interval '1 minute' WHERE code = $1`, [c3]);
  await sweepInvitations();
  ok((await codeRow(c3)) == null && (await codeRow(c2)) != null,
    '14b. sweep clears past clear_at; the CONSUMED record survives');

  // 15. two-toggle mode: codes optional; login-page link tracks the toggle
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: 'videosite', redirect_uri: 'https://stream-dev.dreamxwarden.ca/auth/callback',
    scope: 'openid profile email', state: 'x', nonce: 'y',
    code_challenge: 'a'.repeat(43), code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let lr = await fetch(u, { redirect: 'manual' });
  let loginHtml = await (await fetch(SSO + new URL(lr.headers.get('location')!, SSO).pathname + '?txn=' +
    new URL(lr.headers.get('location')!, SSO).searchParams.get('txn'))).text();
  ok(/Sign up/.test(loginHtml) && /register\/start/.test(loginHtml),
    '15a. login page shows the "Sign up" strip while enabled');

  await setDb('require_invitation_code', 'false');
  await sleep(5500);
  await coolOff(EM('g'));
  r = await bff('/api/register/start', { email: EM('g') });
  ok(r.status === 200 && (await r.json()).sent === true, '15b. codes optional -> start without a code works');
  // a live pending registration reserves its email system-wide (uniqueness source)
  ok(await pendingEmailExists(EM('g')), '15b2. pending email registers as taken');

  await setDb('enable_registration', 'false');
  await sleep(5500);
  r = await bff('/api/register/start', { email: EM('g') });
  ok(r.status === 403, '15c. disabled again -> 403');
  lr = await fetch(u, { redirect: 'manual' });
  loginHtml = await (await fetch(SSO + new URL(lr.headers.get('location')!, SSO).pathname + '?txn=' +
    new URL(lr.headers.get('location')!, SSO).searchParams.get('txn'))).text();
  ok(!/Sign up/.test(loginHtml), '15d. login-page strip gone when disabled');
} finally {
  // cleanup: our account, codes, redis keys; settings restored VERBATIM
  await pool.query('DELETE FROM user_org_roles WHERE user_sub IN (SELECT sub FROM identities WHERE username = $1)', [NEW_USER]);
  await pool.query('DELETE FROM sessions WHERE user_sub IN (SELECT sub FROM identities WHERE username = $1)', [NEW_USER]);
  await pool.query('DELETE FROM org_audit_log WHERE actor_label LIKE $1', ['%(' + NEW_USER + ')%']);
  await pool.query('DELETE FROM invitation_codes WHERE code = ANY($1) OR created_by_label = $2', [madeCodes, 'Reg Test']);
  await pool.query('DELETE FROM identities WHERE username = $1', [NEW_USER]);
  for (const n of ['a', 'b', 'c', 'd', 'e', 'f', 'g']) {
    await redis.del(`reg:pending:${EM(n)}`, `reg:rl:${EM(n)}`);
  }
  for (const k of TOUCHED) {
    const orig = origRows.find((x) => x.key === k);
    await setDb(k, orig ? orig.value : null);
  }
  mock.close();
}

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
