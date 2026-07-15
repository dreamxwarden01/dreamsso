// End-to-end test of the Devices pane through the account BFF: logs in (landing a
// real server session bound to a fresh SSO master session), then exercises
// GET /api/sessions and confirms the BFF marks exactly the caller's own session
// as is_current (the access token can't convey this) and guards it from deletion.
// Usage: node scripts/account-devices-test.mjs [username] [password]
import crypto from 'node:crypto';
import { answerKmsi } from './lib/kmsi.mjs';
const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

const jar = {};
const absorb = (res) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
};
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');
let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

// --- log into the BFF (fresh SSO session) ---
let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
absorb(r);
const authorizeUrl = r.headers.get('location') || '';
r = await fetch(authorizeUrl, { redirect: 'manual' });
const txn = new URL(r.headers.get('location') || '', SSO).searchParams.get('txn');
r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
  body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
});
r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> code
const cb = new URL(r.headers.get('location') || '');
r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code'))}&state=${encodeURIComponent(cb.searchParams.get('state'))}`,
  { redirect: 'manual', headers: { cookie: cookie() } });
absorb(r);
ok(!!jar.acct_sid, '0. BFF login -> server session');
if (!jar.acct_sid) process.exit(1);

// 1. GET /api/sessions
r = await fetch(BFF + '/api/sessions', { headers: { cookie: cookie() } });
const list = (await r.json().catch(() => ({}))).sessions || [];
ok(r.status === 200 && Array.isArray(list) && list.length >= 1, '1. GET /api/sessions', `(${list.length} sessions)`);

// 2. exactly one session marked is_current (this BFF's bound SSO session)
const currents = list.filter((s) => s.is_current);
const cur = currents[0];
ok(currents.length === 1, '2. exactly one is_current', `(found ${currents.length})`);

// 3. the portal itself is hidden from the apps list (account-only session -> empty)
ok(!!cur && !cur.apps.some((a) => a.client_id === 'account'),
   '3. account portal hidden from apps', `(apps: ${(cur?.apps || []).map((a) => a.client_id).join(',') || 'none'})`);

// 4. the BFF refuses to delete the current session (that's logout, not a device action)
r = await fetch(BFF + '/api/sessions/' + encodeURIComponent(cur.sid), { method: 'DELETE', headers: { cookie: cookie() } });
ok(r.status === 409, '4. DELETE current session -> 409', `(${r.status})`);

// 5. deleting an unowned/random sid -> 404 (SSO ownership guard, via proxy)
r = await fetch(BFF + '/api/sessions/' + crypto.randomUUID(), { method: 'DELETE', headers: { cookie: cookie() } });
ok(r.status === 404, '5. DELETE foreign sid -> 404', `(${r.status})`);

// cleanup: logout (kills this SSO session)
await fetch(BFF + '/auth/logout', { redirect: 'manual', headers: { cookie: cookie() } });

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
