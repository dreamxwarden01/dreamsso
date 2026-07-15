// E2E for the passkey backend through the BFF (:4001), minus the browser
// attestation ceremony (that needs a real authenticator). Verifies:
//  - register-options shape (rpID, challenge, residentKey)
//  - list / rename / remove (a credential row is seeded directly via pg, since
//    finishRegistration requires a genuine WebAuthn attestation)
// Usage: node scripts/account-passkey-test.mjs [username] [password]
import crypto from 'node:crypto';
import pg from 'pg';
import { answerKmsi } from './lib/kmsi.mjs';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';
const PG = 'postgresql://dreamsso:dreamsso@127.0.0.1:5432/dreamsso';

const jar = {};
function absorb(res) {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
}
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const api = (path, opts = {}) =>
  fetch(BFF + path, { ...opts, headers: { cookie: cookie(), 'content-type': 'application/json', ...(opts.headers || {}) } });

async function login() {
  let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  absorb(r);
  r = await fetch(r.headers.get('location'), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location'), SSO).searchParams.get('txn');
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> callback with code
  const cb = new URL(r.headers.get('location'));
  r = await fetch(`${BFF}/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`,
    { redirect: 'manual', headers: { cookie: cookie() } });
  absorb(r);
  return !!jar.acct_sid;
}

ok(await login(), '0. login -> BFF session');

// who am I (need the sub to seed a credential row)
let r = await api('/api/me');
const sub = (await r.json()).profile.sub;
ok(!!sub, '1. /api/me sub', `(${sub})`);

// register-options shape
r = await api('/api/security/passkey/register-options', { method: 'POST', body: '{}' });
const opt = await r.json();
ok(
  r.status === 200 && opt.challenge && opt.rp?.id === 'dreamxwarden.ca' &&
    opt.user?.name === USER && opt.authenticatorSelection?.residentKey === 'required',
  '2. register-options shape',
  `(rp.id=${opt.rp?.id}, residentKey=${opt.authenticatorSelection?.residentKey})`,
);

// seed a credential row directly (finishRegistration needs a real attestation)
const pool = new pg.Pool({ connectionString: PG });
const credId = crypto.randomBytes(32);
const { rows: [seeded] } = await pool.query(
  `INSERT INTO webauthn_credentials (user_sub, credential_id, public_key, sign_count, label)
   VALUES ($1,$2,$3,0,'Test Passkey') RETURNING id`,
  [sub, credId, crypto.randomBytes(64)],
);
const pkId = seeded.id;
ok(!!pkId, '3. seed credential row', `(${pkId})`);

// list shows it
r = await api('/api/security');
let pks = (await r.json()).mfa.passkeys;
ok(pks.some((p) => p.id === pkId && p.label === 'Test Passkey'), '4. listed with label', `(count=${pks.length})`);

// rename
r = await api('/api/security/passkey/' + pkId, { method: 'PATCH', body: JSON.stringify({ label: 'Renamed Passkey' }) });
ok(r.status === 204, '5. rename -> 204');
r = await api('/api/security');
ok((await r.json()).mfa.passkeys.find((p) => p.id === pkId)?.label === 'Renamed Passkey', '6. rename reflected');

// remove — with a strong factor present this demands a fresh sudo window; a
// script can't run a real passkey assertion, so stamp the session directly
// (the gate itself is e2e-covered by sso-security-stepup-test).
r = await api('/api/security/passkey/' + pkId, { method: 'DELETE' });
ok(r.status === 403 && (await r.json()).error === 'step_up_required', '6a. remove without step-up -> 403');
await pool.query(
  `UPDATE sessions SET stepup_at = now() WHERE user_sub = $1
     AND created_at = (SELECT max(created_at) FROM sessions WHERE user_sub = $1)`,
  [sub],
);
r = await api('/api/security/passkey/' + pkId, { method: 'DELETE' });
ok(r.status === 204, '7. remove -> 204');
r = await api('/api/security');
ok(!(await r.json()).mfa.passkeys.find((p) => p.id === pkId), '8. gone after remove');

// safety net: ensure the seeded row is gone even if a check above failed
await pool.query('DELETE FROM webauthn_credentials WHERE id = $1', [pkId]);
await pool.end();

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
