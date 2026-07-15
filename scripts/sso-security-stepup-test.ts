// E2E for the personal-security step-up gates + factor limits:
//   zero strong factors -> FIRST authenticator enrolls with no gate (exception)
//   with a factor: mfa enable/disable + add/remove demand a fresh sudo window
//   the solved step-up stamps stepup_at -> REUSABLE across actions
//   aged stamp (31 min) -> 403 step_up_required on remove; re-verify -> works
//   limits: 5 authenticators (real), 10 passkeys (seeded rows)
//   two-tier windows: factor actions capped at 10 min, toggle at the setting
// State: requires tester to START with zero strong factors; restores
// mfa_enabled + deletes every factor it created.
// Run: npx tsx scripts/sso-security-stepup-test.ts
import { generateSync } from 'otplib';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { sealSecret } from '../src/secretbox.js';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const jar: Record<string, string> = {};
const absorb = (res: Response) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
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

// --- baseline guard + snapshot ---
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const { rows: [{ n: baseFactors }] } = await pool.query(
  `SELECT (SELECT count(*) FROM totp_credentials WHERE user_sub = $1)
        + (SELECT count(*) FROM webauthn_credentials WHERE user_sub = $1) AS n`, [sub]);
if (Number(baseFactors) !== 0) {
  console.error(`tester has ${baseFactors} factor rows — refusing to run against non-clean state`);
  process.exit(1);
}
const { rows: [{ mfa_enabled: mfaOrig }] } = await pool.query(
  'SELECT mfa_enabled FROM identities WHERE sub = $1', [sub]);

// --- BFF login (password only — amr ['pwd'] never pre-clears the window) ---
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
ok(!!jar.acct_sid, '1. password login -> BFF session');
const { rows: [{ sid: ssoSid }] } = await pool.query(
  `SELECT sid FROM sessions WHERE user_sub = $1 ORDER BY created_at DESC LIMIT 1`, [sub]);

// 2. zero strong factors -> first enrollment needs NO step-up
r = await api('POST', '/api/security/authenticator/setup', {});
const setup1 = await r.json();
ok(r.status === 200 && !!setup1.secret, '2. first authenticator setup allowed without step-up', `(${r.status})`);
r = await api('POST', '/api/security/authenticator/confirm', {
  id: setup1.id, code: generateSync({ secret: setup1.secret, strategy: 'totp' }), label: 'secstep-e2e-1',
});
ok(r.status === 204, '2a. confirmed -> first strong factor exists', `(${r.status})`);

// 3. now the gates bite: MFA toggle without a fresh window -> 403
r = await api('POST', '/api/security/mfa/enable', {});
ok(r.status === 403 && (await r.json()).error === 'step_up_required', '3. mfa enable without step-up -> 403');

// 4. solve the step-up (stamps the session's sudo window)
r = await api('POST', '/api/stepup/verify', { method: 'totp', code: generateSync({ secret: setup1.secret, strategy: 'totp' }) });
ok(r.status === 204, '4. step-up verified (stamp lands)', `(${r.status})`);
r = await api('POST', '/api/security/mfa/enable', {});
ok(r.status === 204, '4a. mfa enable now passes');

// 5. window is REUSABLE: disable immediately with the same stamp
r = await api('POST', '/api/security/mfa/disable', {});
ok(r.status === 204, '5. same stamp reused for mfa disable');

// 6. add up to the authenticator limit (window still fresh)
for (let i = 2; i <= 5; i++) {
  await pool.query(
    `INSERT INTO totp_credentials (user_sub, secret_enc, label, confirmed_at) VALUES ($1, $2, $3, now())`,
    [sub, sealSecret('SECSTEPE2ESECRET' + i), 'secstep-e2e-' + i],
  );
}
r = await api('POST', '/api/security/authenticator/setup', {});
ok(r.status === 422 && (await r.json()).error === 'limit_reached', '6. 6th authenticator -> 422 limit_reached');

// 7. age the stamp -> remove demands a fresh window again
await pool.query(`UPDATE sessions SET stepup_at = now() - interval '31 minutes' WHERE sid = $1`, [ssoSid]);
const { rows: [{ id: firstTotpId }] } = await pool.query(
  `SELECT id FROM totp_credentials WHERE user_sub = $1 AND label = 'secstep-e2e-2'`, [sub]);
r = await api('DELETE', '/api/security/authenticator/' + firstTotpId);
ok(r.status === 403 && (await r.json()).error === 'step_up_required', '7. stale window -> remove refused');
// refresh the window via DB stamp — a second REAL verify here would reuse the
// same TOTP code within one 30s step and hit anti-replay (the verify->stamp
// path is already proven at check 4).
await pool.query(`UPDATE sessions SET stepup_at = now() WHERE sid = $1`, [ssoSid]);
r = await api('DELETE', '/api/security/authenticator/' + firstTotpId);
ok(r.status === 204, '7a. window refreshed -> remove passes', `(${r.status})`);

// 8. passkey limit: options OK under the cap, 422 at 10
r = await api('POST', '/api/security/passkey/register-options', {});
ok(r.status === 200, '8. passkey options under the cap -> 200', `(${r.status})`);
for (let i = 0; i < 10; i++) {
  await pool.query(
    `INSERT INTO webauthn_credentials (user_sub, credential_id, public_key, label)
     VALUES ($1, $2, '\\x00'::bytea, $3)`,
    [sub, Buffer.from('secstep-e2e-' + i), 'secstep-e2e-' + i],
  );
}
r = await api('POST', '/api/security/passkey/register-options', {});
ok(r.status === 422 && (await r.json()).error === 'limit_reached', '8a. 11th passkey -> 422 limit_reached');

// 9. two-tier windows: a stamp aged 8 min still covers factor actions (10-min
// cap), 11 min does not — while the TOGGLE still rides the standard 30-min window.
await pool.query(`UPDATE sessions SET stepup_at = now() - interval '8 minutes' WHERE sid = $1`, [ssoSid]);
r = await api('POST', '/api/security/authenticator/setup', {});
ok(r.status === 200, '9. stamp aged 8 min -> factor action allowed (10-min cap)', `(${r.status})`);
await pool.query(`UPDATE sessions SET stepup_at = now() - interval '11 minutes' WHERE sid = $1`, [ssoSid]);
r = await api('POST', '/api/security/authenticator/setup', {});
ok(r.status === 403 && (await r.json()).error === 'step_up_required',
   '9a. aged 11 min -> factor action refused (beyond cap)');
r = await api('POST', '/api/security/mfa/enable', {});
ok(r.status === 204, '9b. same 11-min stamp still covers the MFA toggle (standard window)', `(${r.status})`);
r = await api('GET', '/api/stepup/status');
const st = await r.json();
ok(typeof st.age_seconds === 'number' && st.age_seconds > 600 && st.verified === true,
   '9c. status exposes age_seconds for the client gate', `(${st.age_seconds}s, verified=${st.verified})`);

// --- restore: drop every factor this suite created, restore the toggle ---
// baseline was asserted ZERO at start, so restore = drop everything (this also
// catches the label-less PENDING setup rows checks 9/9a created).
await pool.query(`DELETE FROM totp_credentials WHERE user_sub = $1`, [sub]);
await pool.query(`DELETE FROM webauthn_credentials WHERE user_sub = $1`, [sub]);
await pool.query(`UPDATE identities SET mfa_enabled = $2 WHERE sub = $1`, [sub, mfaOrig]);
const { rows: [{ n: leftover }] } = await pool.query(
  `SELECT (SELECT count(*) FROM totp_credentials WHERE user_sub = $1)
        + (SELECT count(*) FROM webauthn_credentials WHERE user_sub = $1) AS n`, [sub]);
ok(Number(leftover) === 0, '10. cleanup: tester back to zero factors');

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
