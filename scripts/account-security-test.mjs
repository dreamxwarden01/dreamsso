// E2E for the account console Security pane (through the BFF on :4001):
// password change (+ wrong/weak guards, restored after) and the full authenticator
// lifecycle (setup -> confirm via otplib -> list -> rename -> bad-code -> remove).
// Usage: node scripts/account-security-test.mjs [username] [password]
import { generateSync } from 'otplib';
import { answerKmsi } from './lib/kmsi.mjs';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

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

// --- log in to get a BFF session ---
async function login(pass) {
  let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  absorb(r);
  const authorizeUrl = r.headers.get('location');
  r = await fetch(authorizeUrl, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location'), SSO).searchParams.get('txn');
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: pass }),
  });
  r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> callback with code
  const cbLoc = r.headers.get('location') || '';
  const cb = new URL(cbLoc);
  r = await fetch(`${BFF}/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`,
    { redirect: 'manual', headers: { cookie: cookie() } });
  absorb(r);
  return !!jar.acct_sid && cbLoc.includes('/auth/callback');
}
ok(await login(PASS), '0. login -> BFF session');

// --- GET /api/security shape ---
let r = await api('/api/security');
const sec = await r.json();
ok(r.status === 200 && sec.password && sec.mfa && Array.isArray(sec.mfa.authenticators),
   '1. GET /api/security', `(pw_set=${sec.password?.is_set}, auth=${sec.mfa?.authenticators?.length})`);

// --- password: too short rejected ---
r = await api('/api/security/password', { method: 'POST', body: JSON.stringify({ current_password: PASS, new_password: 'short' }) });
ok(r.status === 400 && (await r.json()).error === 'weak_password', '2. short password -> 400');

// --- password: long but <3 categories rejected (policy: 3 of 4) ---
r = await api('/api/security/password', { method: 'POST', body: JSON.stringify({ current_password: PASS, new_password: 'lowercaseonly' }) });
ok(r.status === 400 && (await r.json()).error === 'weak_password', '2b. low-complexity -> 400');

// --- password: wrong current rejected ---
r = await api('/api/security/password', { method: 'POST', body: JSON.stringify({ current_password: 'WRONGpass1', new_password: 'TempPass5678' }) });
ok(r.status === 403 && (await r.json()).error === 'wrong_password', '3. wrong current -> 403');

// --- password: real change, then change back ---
r = await api('/api/security/password', { method: 'POST', body: JSON.stringify({ current_password: PASS, new_password: 'TempPass5678' }) });
ok(r.status === 204, '4. change password -> 204');
r = await api('/api/security/password', { method: 'POST', body: JSON.stringify({ current_password: 'TempPass5678', new_password: PASS }) });
ok(r.status === 204, '5. restore password -> 204');

// --- authenticator: setup ---
r = await api('/api/security/authenticator/setup', { method: 'POST', body: '{}' });
const setup = await r.json();
ok(r.status === 200 && setup.id && setup.secret && setup.otpauth_uri && setup.qr_data_url?.startsWith('data:image'),
   '6. authenticator setup', `(secret ${setup.secret?.slice(0, 6)}…)`);

// --- authenticator: confirm with a real code ---
const code = generateSync({ secret: setup.secret, strategy: 'totp' });
r = await api('/api/security/authenticator/confirm', { method: 'POST', body: JSON.stringify({ id: setup.id, code, label: 'Test TOTP' }) });
ok(r.status === 204, '7. confirm authenticator -> 204', `(code ${code})`);

// --- list shows it with the label ---
r = await api('/api/security');
const after = await r.json();
const mine = after.mfa.authenticators.find((a) => a.id === setup.id);
ok(!!mine && mine.label === 'Test TOTP', '8. listed with label', `(${mine?.label})`);

// --- rename ---
r = await api('/api/security/authenticator/' + setup.id, { method: 'PATCH', body: JSON.stringify({ label: 'Renamed TOTP' }) });
ok(r.status === 204, '9. rename -> 204');
r = await api('/api/security');
ok((await r.json()).mfa.authenticators.find((a) => a.id === setup.id)?.label === 'Renamed TOTP', '10. rename reflected');

// --- with a strong factor present, further factor changes demand a fresh
// sudo window (personal-security step-up gate) — verify once, window reused ---
r = await api('/api/security/authenticator/setup', { method: 'POST', body: '{}' });
ok(r.status === 403 && (await r.json()).error === 'step_up_required', '10a. second setup without step-up -> 403');
r = await api('/api/stepup/verify', {
  method: 'POST',
  body: JSON.stringify({ method: 'totp', code: generateSync({ secret: setup.secret, strategy: 'totp' }) }),
});
ok(r.status === 204, '10b. step-up verified', `(${r.status})`);

// --- bad code rejected on a fresh setup ---
r = await api('/api/security/authenticator/setup', { method: 'POST', body: '{}' });
const setup2 = await r.json();
r = await api('/api/security/authenticator/confirm', { method: 'POST', body: JSON.stringify({ id: setup2.id, code: '000000' }) });
ok(r.status === 422 && (await r.json()).error === 'invalid_code', '11. bad code -> 422 invalid_code');

// --- remove (cleanup) ---
r = await api('/api/security/authenticator/' + setup.id, { method: 'DELETE' });
ok(r.status === 204, '12. remove -> 204');
r = await api('/api/security');
const final = await r.json();
ok(!final.mfa.authenticators.find((a) => a.id === setup.id), '13. gone after remove', `(remaining=${final.mfa.authenticators.length})`);

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
