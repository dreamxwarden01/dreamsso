// Drives the WHOLE browser round-trip headlessly:
//   RP /login -> SSO /authorize -> SSO login (tester) -> RP /callback (token exchange) -> claims.
// Proves the dev RP completes end-to-end, exactly as Safari will.
const RP = 'http://localhost:4000';
const SSO = 'http://localhost:3000';
const strip = (u) => u.replace('https://sso-dev.dreamxwarden.ca', '').replace('https://stream-dev.dreamxwarden.ca', '');

function jar() {
  const m = new Map();
  return {
    set(list) { for (const sc of list ?? []) { const kv = sc.split(';')[0]; const i = kv.indexOf('='); m.set(kv.slice(0, i), kv.slice(i + 1)); } },
    header() { return [...m.entries()].map(([k, v]) => `${k}=${v}`).join('; '); },
  };
}
const rp = jar();
const sso = jar();

// 1. RP /login -> 302 to SSO /authorize (+ rp_flow cookie)
let r = await fetch(RP + '/login', { redirect: 'manual' });
rp.set(r.headers.getSetCookie());
const authPath = strip(r.headers.get('location') || '');
console.log('RP /login         ->', r.status, authPath.split('?')[0]);

// 2. SSO /authorize -> 302 /login?txn
r = await fetch(SSO + authPath, { redirect: 'manual' });
const loginLoc = r.headers.get('location') || '';
const txn = new URL(loginLoc, SSO).searchParams.get('txn');

// 3. GET /login -> csrf
r = await fetch(SSO + loginLoc);
const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];

// 4. POST /login (tester) -> 302 to stream-dev/callback?code
r = await fetch(SSO + '/login', {
  method: 'POST', redirect: 'manual',
  headers: { 'content-type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ txn, csrf, username: 'tester', password: 'Test1234!' }),
});
const cbPath = strip(r.headers.get('location') || '');
console.log('SSO POST /login   ->', r.status, cbPath.split('?')[0]);

// 5. RP /callback (with rp_flow cookie) -> RP exchanges code over the internal URL
r = await fetch(RP + cbPath, { headers: { cookie: rp.header() } });
const out = await r.text();
const ok = /Logged in/.test(out);
const uname = (out.match(/&quot;preferred_username&quot;: &quot;([^&]+)&quot;/) || out.match(/"preferred_username":\s*"([^"]+)"/) || [])[1];
console.log('RP /callback      ->', r.status, ok ? 'shows "Logged in ✓"' : 'did NOT complete');
console.log('  claims show user:', uname || '(none found)');
console.log(ok ? '\nRP ROUND-TRIP OK ✓ — the browser flow will work.' : '\nRP ROUND-TRIP FAILED ✗');
process.exit(ok ? 0 : 1);
