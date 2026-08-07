// Session location capture + fallback rendering.
//
// cf-ipcountry ships with IP geolocation alone; cf-ipcity / cf-region only arrive
// when the zone has Cloudflare's "Add visitor location headers" managed transform
// enabled. So every rung of the chain must stand on its own:
//   city+country -> "Vancouver, Canada"
//   region only  -> "British Columbia, Canada"
//   country only -> "Canada"            (what every pre-transform session shows)
//   none         -> "Unknown"
// This drives real logins with the headers Cloudflare would set, asserts what
// lands in the DB, and checks the portal's formatter against the same rows.
// Run: node scripts/sso-location-test.mjs
import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fmtLocation } from '../account/client/src/format.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const USER = 'tester';
const PASS = 'Test1234!';

const pkce = () => {
  const v = crypto.randomBytes(32).toString('base64url');
  return { v, c: crypto.createHash('sha256').update(v).digest('base64url') };
};
const authzUrl = (challenge) => {
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT,
    scope: 'openid profile email', state: crypto.randomBytes(8).toString('hex'),
    nonce: crypto.randomBytes(8).toString('hex'),
    code_challenge: challenge, code_challenge_method: 'S256',
  }).toString();
  return u.toString();
};

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const psql = (sql) => execFileSync('docker', [
  'exec', 'dreamsso-postgres-1', 'psql', '-U', 'dreamsso', '-d', 'dreamsso', '-tA', '-c', sql,
]).toString().trim();

// A login carrying the given cf-* headers; returns the new session's sid.
async function loginWith(headers) {
  const jar = {};
  const absorb = (r) => {
    for (const c of r.headers.getSetCookie?.() ?? []) {
      const nv = c.split(';')[0]; const i = nv.indexOf('=');
      if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
    }
  };
  // Drive a normal interactive login and attach the geo headers to POST /login —
  // that is the request whose headers createSession actually reads.
  const p = pkce();
  let r = await fetch(authzUrl(p.c), { redirect: 'manual' });
  const loc = r.headers.get('location');
  const txn = loc && new URL(loc, SSO).searchParams.get('txn');
  if (!txn) throw new Error('no txn from /authorize: ' + loc);
  r = await fetch(`${SSO}/login?txn=${encodeURIComponent(txn)}`);
  absorb(r);
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(`${SSO}/login`, {
    method: 'POST', redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'null', 'sec-fetch-site': 'same-origin',
      cookie: Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '),
      ...headers,
    },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  absorb(r);
  if (r.status >= 400) throw new Error('login failed: ' + r.status);
  return psql(`SELECT sid FROM sessions s JOIN identities i ON i.sub=s.user_sub
               WHERE i.username='${USER}' ORDER BY s.created_at DESC LIMIT 1`);
}

const geoOf = (sid) => {
  const [country, city, region] = psql(
    `SELECT COALESCE(country,'')||'|'||COALESCE(city,'')||'|'||COALESCE(region,'') FROM sessions WHERE sid='${sid}'`
  ).split('|');
  return { country: country || null, city: city || null, region: region || null };
};

const made = [];
console.log('\n--- capture: what the edge sends is what we store ---');

const full = await loginWith({ 'cf-ipcountry': 'CA', 'cf-ipcity': 'Vancouver', 'cf-region': 'British Columbia' });
made.push(full);
let g = geoOf(full);
ok(g.country === 'CA' && g.city === 'Vancouver' && g.region === 'British Columbia',
  'full headers stored', JSON.stringify(g));
ok(fmtLocation(g) === 'Vancouver, Canada', 'renders "city, country"', fmtLocation(g));

const regionOnly = await loginWith({ 'cf-ipcountry': 'CA', 'cf-region': 'British Columbia' });
made.push(regionOnly);
g = geoOf(regionOnly);
ok(g.city === null && g.region === 'British Columbia', 'city absent stored as NULL', JSON.stringify(g));
ok(fmtLocation(g) === 'British Columbia, Canada', 'falls back to "region, country"', fmtLocation(g));

const countryOnly = await loginWith({ 'cf-ipcountry': 'CA' });
made.push(countryOnly);
g = geoOf(countryOnly);
ok(g.city === null && g.region === null, 'transform off -> country only', JSON.stringify(g));
ok(fmtLocation(g) === 'Canada', 'falls back to "country"', fmtLocation(g));

const none = await loginWith({});
made.push(none);
g = geoOf(none);
ok(g.country === null, 'no edge headers at all -> nothing stored', JSON.stringify(g));
ok(fmtLocation(g) === 'Unknown', 'renders "Unknown"', fmtLocation(g));

console.log('\n--- formatter edge cases ---');
ok(fmtLocation({ country: 'T1', city: 'Vancouver' }) === 'Tor network',
  'Tor is never given a city', fmtLocation({ country: 'T1', city: 'Vancouver' }));
ok(fmtLocation({ country: 'XX', city: 'Vancouver' }) === 'Unknown', 'XX is Unknown, not "Vancouver, XX"');
ok(fmtLocation({}) === 'Unknown', 'empty object is safe');
ok(fmtLocation() === 'Unknown', 'no argument is safe');
ok(fmtLocation({ country: 'CA', city: '  ' }) === 'Canada', 'whitespace-only city ignored');

// --- cleanup: only the sessions this test created ---
psql(`DELETE FROM sessions WHERE sid IN (${made.map((s) => `'${s}'`).join(',')})`);
const left = psql(`SELECT count(*) FROM sessions WHERE sid IN (${made.map((s) => `'${s}'`).join(',')})`);
ok(left === '0', 'cleanup: test sessions removed', `${left} left`);

console.log(fail ? `\n${fail} FAILED\n` : '\nall passed\n');
process.exit(fail ? 1 : 0);
