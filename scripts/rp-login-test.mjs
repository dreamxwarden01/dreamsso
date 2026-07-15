// End-to-end test of videosite's OIDC RP routes: drives /auth/login through the
import { answerKmsi } from './lib/kmsi.mjs';
// SSO login and asserts the videosite session + /api/me (+ profile + a gated
// admin endpoint). Usage: node scripts/rp-login-test.mjs [username] [password]
const STREAM = 'https://stream-dev.dreamxwarden.ca';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

const jar = {}; // stream-dev cookies only (the SSO leg is stateless via txn+csrf)
function absorb(res) {
  for (const c of (res.headers.getSetCookie?.() ?? [])) {
    const nv = c.split(';')[0]; const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
}
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');

// 1. videosite /auth/login -> 302 to SSO /authorize, sets oidc_flow
let r = await fetch(STREAM + '/auth/login', { redirect: 'manual' });
absorb(r);
const authorizeUrl = r.headers.get('location') || '';
console.log('1. /auth/login     ->', r.status, authorizeUrl.startsWith(SSO) ? 'to SSO ✓' : 'NOT SSO ✗', jar.oidc_flow ? 'oidc_flow ✓' : '✗');

// 2. SSO /authorize -> 302 /login?txn=
r = await fetch(authorizeUrl, { redirect: 'manual' });
const loginLoc = r.headers.get('location') || '';
const txn = new URL(loginLoc, SSO).searchParams.get('txn');
console.log('2. SSO /authorize  ->', r.status, txn ? 'txn ✓' : 'txn ✗');

// 3. SSO GET /login -> csrf
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
console.log('3. SSO /login      ->', r.status, csrf ? 'csrf ✓' : 'csrf ✗');

// 4. SSO POST /login -> 302 to videosite /auth/callback?code=
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
});
r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> callback with code
const cbLoc = r.headers.get('location') || '';
console.log('4. POST /login     ->', r.status, cbLoc.split('?')[0] || '(no location)');
if (!cbLoc.includes('/auth/callback')) { console.error('   FAIL: expected /auth/callback, got:', cbLoc); process.exit(1); }

// 5. videosite /auth/callback (with oidc_flow) -> 302 / + sid
r = await fetch(cbLoc, { redirect: 'manual', headers: { cookie: cookie() } });
absorb(r);
console.log('5. /auth/callback  ->', r.status, '->', r.headers.get('location') || '', jar.sid ? 'sid ✓' : 'sid ✗');
if (!jar.sid) { console.error('   FAIL: no session cookie (callback likely redirected to /auth/error)'); process.exit(1); }

// 6. /api/me with the session
r = await fetch(STREAM + '/api/me', { headers: { cookie: cookie() } });
const me = await r.json();
console.log('6. /api/me         ->', r.status, JSON.stringify(me.user || me));
if (!me || !me.user) { console.error('\nFAIL: /api/me returned no user'); process.exit(1); }
console.log(`   login OK ✓  username=${me.user.username}  role_id=${me.user.role_id}`);

// 7. /api/profile — was 500 on the unthreaded getUserById
r = await fetch(STREAM + '/api/profile', { headers: { cookie: cookie() } });
console.log('7. /api/profile    ->', r.status, r.status === 200 ? '✓' : 'FAIL ✗');

// 8. an MFA-gated admin endpoint — should NOT demand MFA now (200, or 403 if this user lacks the perm)
r = await fetch(STREAM + '/api/admin/users?page=1&limit=5', { headers: { cookie: cookie() } });
const adm = await r.json().catch(() => ({}));
console.log('8. /api/admin/users->', r.status, adm.requireMFA ? 'STILL requires MFA ✗' : (r.status === 200 ? 'OK ✓' : r.status === 403 ? '(403 no perm — MFA gate not the blocker)' : JSON.stringify(adm).slice(0, 80)));

// 9. /api/courses — home course list (enrollment query, newly threaded)
r = await fetch(STREAM + '/api/courses', { headers: { cookie: cookie() } });
console.log('9. /api/courses    ->', r.status, r.status === 200 ? '✓' : 'FAIL ✗');

// 10. /api/profile/security — sessions + email/mfa display (newly threaded reads)
r = await fetch(STREAM + '/api/profile/security', { headers: { cookie: cookie() } });
console.log('10./api/profile/security ->', r.status, r.status === 200 ? '✓' : 'FAIL ✗');

// 11. admin user-detail for demo's UUID — exercises checkPermissionLevel(idBuf) + getUserById(hex)
r = await fetch(STREAM + '/api/admin/users/019ef1f091d6794c9d018d67f6b83481', { headers: { cookie: cookie() } });
const det = await r.json().catch(() => ({}));
console.log('11./api/admin/users/:id->', r.status, r.status === 200 && det.targetUser ? ('OK ✓ (' + det.targetUser.username + ')') : r.status === 403 ? '(403 — needs admin)' : JSON.stringify(det).slice(0, 80));
