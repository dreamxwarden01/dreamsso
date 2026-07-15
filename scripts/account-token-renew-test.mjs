// E2E test of session-bound access-token renewal: the BFF's 15-minute access
// token must renew transparently against /internal/token/renew (live SSO
// session = the refresh credential) instead of 401-bouncing the SPA — and
// must STILL 401 when the SSO session behind it is gone.
// Usage: node scripts/account-token-renew-test.mjs
import { answerKmsi } from './lib/kmsi.mjs';
import { Redis } from 'ioredis';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const redis = new Redis(process.env.REDIS_URL ?? 'redis://127.0.0.1:6379');

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

// --- login (same legs as account-rp-test) ---
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
r = await answerKmsi(SSO, r, txn, csrf);
const cb = new URL(r.headers.get('location') || '');
r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code'))}&state=${encodeURIComponent(cb.searchParams.get('state'))}`,
  { redirect: 'manual', headers: { cookie: cookie() } });
absorb(r);
ok(!!jar.acct_sid, '1. login -> BFF session');
if (!jar.acct_sid) { console.error('   login failed — aborting'); process.exit(1); }

const KEY = 'acct:sess:' + jar.acct_sid;
const now = () => Math.floor(Date.now() / 1000);

// 2. baseline /api/me with a live token
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
const me = await r.json().catch(() => ({}));
ok(r.status === 200 && me.profile?.sub, '2. /api/me (fresh token)', `(${r.status})`);

// 3. rewind the token to expired — the next call must renew, NOT 401
let sess = JSON.parse(await redis.get(KEY));
const realExp = sess.accessExpiresAt;
ok(typeof realExp === 'number' && realExp > now(), '3. session has a live token', `(exp in ${realExp - now()}s)`);
sess.accessExpiresAt = now() - 100;
await redis.set(KEY, JSON.stringify(sess), 'KEEPTTL');

r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
const me2 = await r.json().catch(() => ({}));
sess = JSON.parse(await redis.get(KEY));
ok(r.status === 200 && me2.profile?.sub === me.profile.sub, '4. /api/me with expired token -> 200 (renewed)', `(${r.status})`);
ok(sess.accessExpiresAt > now() + 800, '5. session holds a fresh ~15min token', `(exp in ${sess.accessExpiresAt - now()}s)`);

// 6. an org API call rides the renewed token too
r = await fetch(BFF + '/api/stepup/status', { headers: { cookie: cookie() } });
ok(r.status === 200, '6. /api/stepup/status after renewal', `(${r.status})`);

// 7. fail-soft: dead SSO session behind the token -> renewal refused -> 401
const realSsoSid = sess.ssoSid;
sess.ssoSid = 'bogus-sid-that-does-not-exist';
sess.accessExpiresAt = now() - 100;
await redis.set(KEY, JSON.stringify(sess), 'KEEPTTL');
r = await fetch(BFF + '/api/profile', {
  method: 'PATCH', headers: { cookie: cookie(), 'content-type': 'application/json' },
  body: JSON.stringify({ display_name: 'x' }),
});
const dead = await r.json().catch(() => ({}));
ok(r.status === 401 && dead.error === 'token_expired', '7. dead SSO session -> renewal refused -> 401', `(${r.status} ${dead.error})`);

// restore + verify recovery
sess = JSON.parse(await redis.get(KEY));
sess.ssoSid = realSsoSid;
await redis.set(KEY, JSON.stringify(sess), 'KEEPTTL');
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(r.status === 200, '8. restored sid -> renewal recovers', `(${r.status})`);

// 9. logout cleanup
await fetch(BFF + '/auth/logout', { redirect: 'manual', headers: { cookie: cookie() } });
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(r.status === 401, '9. logout -> 401', `(${r.status})`);

redis.disconnect();
console.log(fail ? `\n${fail} check(s) FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
