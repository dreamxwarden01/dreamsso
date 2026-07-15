// E2E test: the SSO defines the app role AT LOGIN via the id_token `app_role`
// claim — videosite must apply it at the callback (update + cache purge)
// exactly like a roles_change event. Falsifiable by DRIFT: we manually demote
// tester's videosite row, log in through the SSO, and the callback must snap
// it back to the SSO's effective role (catalog default `user` = 2) BEFORE the
// first API response — synchronous, no event-debounce wait.
// State: mutates ONLY the throwaway `tester` row and restores it by design
// (the login itself is the restore).
// Usage: node scripts/sso-login-role-test.mjs
import { execSync } from 'node:child_process';
import { answerKmsi } from './lib/kmsi.mjs';

const STREAM = 'https://stream-dev.dreamxwarden.ca';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';

// SQL via stdin (two shell layers mangle inline quotes — the known gotcha)
const sql = (q) =>
  execSync(`docker exec -i dreamsso-videosite-db-1 sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" videosite -N' 2>/dev/null`, { input: q })
    .toString().trim();

const jar = {};
function absorb(res) {
  for (const c of (res.headers.getSetCookie?.() ?? [])) {
    const nv = c.split(';')[0]; const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
}
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

// 1. snapshot + inject drift: demote tester locally (simulates the app's
// users table disagreeing with the SSO's effective assignment)
const before = sql(`SELECT role_id FROM users WHERE username='${USER}';`);
ok(before === '2', '1. baseline: tester is role 2 locally', `(${before})`);
sql(`UPDATE users SET role_id = 1 WHERE username='${USER}';`);
ok(sql(`SELECT role_id FROM users WHERE username='${USER}';`) === '1', '2. drift injected: tester demoted to role 1');

// 3. full SSO login
let r = await fetch(STREAM + '/auth/login', { redirect: 'manual' });
absorb(r);
r = await fetch(r.headers.get('location') || '', { redirect: 'manual' });
const txn = new URL(r.headers.get('location') || '', SSO).searchParams.get('txn');
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
});
r = await answerKmsi(SSO, r, txn, csrf);
const cbLoc = r.headers.get('location') || '';
ok(cbLoc.includes('/auth/callback') && cbLoc.includes('code='), '3. SSO login -> code');

// 4. callback must succeed (unknown-role would bounce to /auth/error)
r = await fetch(cbLoc, { redirect: 'manual', headers: { cookie: cookie() } });
absorb(r);
const cbTo = r.headers.get('location') || '';
ok(!!jar.sid && !cbTo.includes('/auth/error'), '4. callback -> session (no role error)', `(-> ${cbTo})`);

// 5. IMMEDIATELY after: the claim must have been applied synchronously
r = await fetch(STREAM + '/api/me', { headers: { cookie: cookie() } });
const me = await r.json().catch(() => ({}));
ok(r.status === 200 && me.user?.role_id === 2, '5. /api/me right after login -> role 2 (claim beat the drift)',
  `(role_id=${me.user?.role_id})`);

// 6. and the row itself is corrected (which is also the state restore)
const after = sql(`SELECT role_id FROM users WHERE username='${USER}';`);
ok(after === '2', '6. videosite row corrected to 2', `(${after})`);

if (fail) {
  // safety net: never leave tester drifted
  sql(`UPDATE users SET role_id = 2 WHERE username='${USER}';`);
}
console.log(fail ? `\n${fail} check(s) FAILED ✗ (tester restored)` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
