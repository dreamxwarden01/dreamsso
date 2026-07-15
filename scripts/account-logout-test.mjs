// E2E for rotate-by-sid + logout cascade (account BFF + SSO):
//   - log in twice on the SAME SSO session -> the first BFF session is rotated out
//   - SSO /logout -> deletes the master session, back-channel fans out to the BFF
//     -> the BFF session is killed (cross-session), and a "signed out" page renders
// Usage: node scripts/account-logout-test.mjs [username] [password]
import { answerKmsi } from './lib/kmsi.mjs';
const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const getSetCookie = (res, name) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === name) return nv.slice(i + 1);
  }
  return null;
};
const meStatus = (acctSid) =>
  fetch(BFF + '/api/me', { headers: { cookie: 'acct_sid=' + acctSid } }).then((r) => r.status);

// Full BFF login. If ssoSession is passed, it's sent to /authorize (silent reuse).
async function bffLogin(ssoSession) {
  let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  const flow = getSetCookie(r, 'acct_flow');
  let loc = r.headers.get('location'); // SSO /authorize
  r = await fetch(loc, { redirect: 'manual', headers: ssoSession ? { cookie: 'sso_session=' + ssoSession } : {} });
  loc = r.headers.get('location') || '';
  let newSso = ssoSession;
  if (loc.includes('/login?txn=')) {
    const txn = new URL(loc, SSO).searchParams.get('txn');
    r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
    const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
    r = await fetch(SSO + '/login', {
      method: 'POST', redirect: 'manual',
      headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
      body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
    });
    newSso = getSetCookie(r, 'sso_session') || ssoSession; // transient cookie on the KMSI page
    r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> callback with code
    loc = r.headers.get('location') || '';
  }
  const cb = new URL(loc); // account-dev/auth/callback?code=...
  r = await fetch(`${BFF}/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`,
    { redirect: 'manual', headers: { cookie: 'acct_flow=' + flow } });
  return { acctSid: getSetCookie(r, 'acct_sid'), ssoSession: newSso, silent: !loc.includes('/login') };
}

// 1. first login (interactive) -> BFF session + sso_session
const a = await bffLogin();
ok(!!a.acctSid && !!a.ssoSession, '1. login #1 -> acct_sid + sso_session');
ok((await meStatus(a.acctSid)) === 200, '2. session #1 active (/api/me 200)');

// 3. second login REUSING the SSO session (silent) -> rotates session #1 out
const b = await bffLogin(a.ssoSession);
ok(!!b.acctSid && b.silent, '3. login #2 silent reuse (same SSO session)');
ok((await meStatus(a.acctSid)) === 401, '4. session #1 ROTATED OUT (/api/me 401)');
ok((await meStatus(b.acctSid)) === 200, '5. session #2 active');

// 6. SSO /logout (front-channel) -> kills master session + back-channel fan-out
let r = await fetch(SSO + '/logout', { redirect: 'manual', headers: { cookie: 'sso_session=' + a.ssoSession } });
const body = await r.text();
ok(r.status === 200 && /Signed out/i.test(body), '6. SSO /logout -> signed-out page', `(${r.status})`);

// 7. cascade: the BFF session was killed by the back-channel logout
// (delivered via the event channel's 2s debounce -> poll briefly)
let dead7 = false;
for (let i = 0; i < 16 && !dead7; i++) {
  await new Promise((r) => setTimeout(r, 500));
  dead7 = (await meStatus(b.acctSid)) === 401;
}
ok(dead7, '7. session #2 killed by back-channel');

// 8. master session gone: a fresh silent /authorize now falls back to /login
r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
const flow2 = getSetCookie(r, 'acct_flow');
r = await fetch(r.headers.get('location'), { redirect: 'manual', headers: { cookie: 'sso_session=' + a.ssoSession } });
ok((r.headers.get('location') || '').includes('/login?txn='), '8. master session gone -> /authorize falls back to /login');
void flow2;

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
