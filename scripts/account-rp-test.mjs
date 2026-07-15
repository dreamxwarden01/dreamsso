// End-to-end test of the account console BFF: drives /auth/login through the SSO
// login, lands the server session, then exercises /api/me and the profile edit
// (PATCH /api/profile -> SSO /account/profile). The BFF is hit directly on :4001
// (no Caddy/DNS needed); only the SSO legs go through the edge.
// Usage: node scripts/account-rp-test.mjs [username] [password]
import { answerKmsi } from './lib/kmsi.mjs';
const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

const jar = {}; // BFF cookies (acct_flow, acct_sid); the SSO leg is stateless (txn+csrf)
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

// 1. BFF /auth/login -> 302 to SSO /authorize, sets acct_flow
let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
absorb(r);
const authorizeUrl = r.headers.get('location') || '';
ok(r.status === 302 && authorizeUrl.startsWith(SSO) && !!jar.acct_flow, '1. BFF /auth/login -> SSO',
   `(${r.status}, acct_flow ${jar.acct_flow ? '✓' : '✗'})`);

// 2. SSO /authorize -> /login?txn
r = await fetch(authorizeUrl, { redirect: 'manual' });
const txn = new URL(r.headers.get('location') || '', SSO).searchParams.get('txn');
ok(!!txn, '2. SSO /authorize -> txn', `(${r.status})`);

// 3. SSO GET /login -> csrf
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
ok(!!csrf, '3. SSO /login -> csrf', `(${r.status})`);

// 4. SSO POST /login -> 302 to account-dev/auth/callback?code
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
});
r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> callback with code
const cbLoc = r.headers.get('location') || '';
ok(cbLoc.includes('/auth/callback') && cbLoc.includes('code='), '4. SSO POST /login -> code', `(${r.status} ${cbLoc.split('?')[0]})`);
if (!cbLoc.includes('code=')) { console.error('   no code — aborting'); process.exit(1); }
const cb = new URL(cbLoc);
const code = cb.searchParams.get('code');
const state = cb.searchParams.get('state');

// 5. BFF /auth/callback (with acct_flow) -> 302 / + acct_sid
r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`,
   { redirect: 'manual', headers: { cookie: cookie() } });
absorb(r);
const cbRedirect = r.headers.get('location') || '';
ok(r.status === 302 && !cbRedirect.includes('/auth/error') && !!jar.acct_sid, '5. BFF /auth/callback -> session',
   `(${r.status} -> ${cbRedirect}, acct_sid ${jar.acct_sid ? '✓' : '✗'})`);
if (!jar.acct_sid) { console.error('   callback failed (redirected to error) — aborting'); process.exit(1); }

// 6. /api/me
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
const me = await r.json().catch(() => ({}));
ok(r.status === 200 && me.profile?.sub, '6. /api/me', JSON.stringify(me.profile || me));

// 7a. PATCH /api/profile display_name (round-trip on the throwaway `tester`)
const orig = me.profile?.display_name;
r = await fetch(BFF + '/api/profile', {
  method: 'PATCH', headers: { cookie: cookie(), 'content-type': 'application/json' },
  body: JSON.stringify({ display_name: 'Edited By Test' }),
});
const pd = await r.json().catch(() => ({}));
ok(r.status === 200 && pd.profile?.display_name === 'Edited By Test', '7a. PATCH display_name', `(${r.status} -> ${pd.profile?.display_name})`);

// 7b. /api/me reflects the edit (session claims updated)
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
const me2 = await r.json().catch(() => ({}));
ok(me2.profile?.display_name === 'Edited By Test', '7b. /api/me reflects edit', `(${me2.profile?.display_name})`);

// 7c. email is NO LONGER accepted here — changes ride the verify-then-commit
// flow (/api/email-change/*); the legacy field is refused outright.
r = await fetch(BFF + '/api/profile', {
  method: 'PATCH', headers: { cookie: cookie(), 'content-type': 'application/json' },
  body: JSON.stringify({ email: 'anything@example.com' }),
});
const ie = await r.json().catch(() => ({}));
ok(r.status === 400 && ie.error === 'use_email_change_flow', '7c. email via PATCH -> 400 use_email_change_flow', `(${r.status} ${ie.error})`);

// 7d. restore original display_name
r = await fetch(BFF + '/api/profile', {
  method: 'PATCH', headers: { cookie: cookie(), 'content-type': 'application/json' },
  body: JSON.stringify({ display_name: orig }),
});
ok(r.status === 200, '7d. restore display_name', `(${r.status} -> ${orig})`);

// 8. logout (front-channel GET -> 302 to SSO end_session) destroys the server session
r = await fetch(BFF + '/auth/logout', { redirect: 'manual', headers: { cookie: cookie() } });
const logoutRedirect = (r.headers.get('location') || '').includes('/logout');
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(r.status === 401 && logoutRedirect, '8. logout -> 302 SSO /logout + /api/me 401', `(${r.status})`);

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
