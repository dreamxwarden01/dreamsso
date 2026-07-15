// E2E for the videosite RP side: rotate-by-sid + back-channel logout.
//   - log in twice on the SAME SSO session -> the first videosite session rotates out
//   - SSO /logout -> back-channel fan-out -> videosite session killed (cross-app)
// Usage: node scripts/videosite-logout-test.mjs [username] [password]
import { answerKmsi } from './lib/kmsi.mjs';
const STREAM = 'https://stream-dev.dreamxwarden.ca';
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
// videosite's /api/me returns 200 {"user":null} when unauthenticated (not 401),
// so "logged in" = a user object is present.
const loggedIn = (sid) =>
  fetch(STREAM + '/api/me', { headers: { cookie: 'sid=' + sid } })
    .then((r) => r.json())
    .then((b) => !!(b && b.user))
    .catch(() => false);

async function videositeLogin(ssoSession) {
  let r = await fetch(STREAM + '/auth/login', { redirect: 'manual' });
  const flow = getSetCookie(r, 'oidc_flow');
  let loc = r.headers.get('location'); // SSO /authorize
  r = await fetch(loc, { redirect: 'manual', headers: ssoSession ? { cookie: 'sso_session=' + ssoSession } : {} });
  loc = r.headers.get('location') || '';
  let newSso = ssoSession;
  const silent = !loc.includes('/login');
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
  const cb = new URL(loc); // STREAM/auth/callback?code=...
  r = await fetch(`${STREAM}/auth/callback?code=${cb.searchParams.get('code')}&state=${cb.searchParams.get('state')}`,
    { redirect: 'manual', headers: { cookie: 'oidc_flow=' + flow } });
  return { sid: getSetCookie(r, 'sid'), ssoSession: newSso, silent };
}

// 1. first login
const a = await videositeLogin();
ok(!!a.sid && !!a.ssoSession, '1. videosite login -> sid + sso_session');
ok((await loggedIn(a.sid)) === true, '2. session #1 active');

// 3. second login REUSING the SSO session -> rotates #1 out
const b = await videositeLogin(a.ssoSession);
ok(!!b.sid && b.silent, '3. login #2 silent reuse (same SSO session)');
ok((await loggedIn(a.sid)) === false, '4. session #1 ROTATED OUT');
ok((await loggedIn(b.sid)) === true, '5. session #2 active');

// 6. SSO /logout -> master session gone + back-channel fan-out to videosite
let r = await fetch(SSO + '/logout', { redirect: 'manual', headers: { cookie: 'sso_session=' + a.ssoSession } });
ok(r.status === 200 && /Signed out/i.test(await r.text()), '6. SSO /logout -> signed-out page', `(${r.status})`);

// 7. cascade: the videosite session was killed by the back-channel logout
// (delivered via the event channel's 2s debounce -> poll briefly)
let dead = false;
for (let i = 0; i < 16 && !dead; i++) {
  await new Promise((r) => setTimeout(r, 500));
  dead = (await loggedIn(b.sid)) === false;
}
ok(dead, '7. session #2 killed by back-channel');

console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
