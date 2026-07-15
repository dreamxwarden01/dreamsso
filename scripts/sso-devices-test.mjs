// Verifies the Devices-pane resource API on the SSO:
//   - device-name parsing from the login User-Agent (browser+major, OS name only)
//   - country capture from cf-ipcountry
//   - apps-accessed list (clients[] appended at /token)
//   - GET /account/sessions, DELETE /account/sessions/:sid, terminate-others
//   - auth + ownership guards
// Drives the SSO directly with the videosite client key (to exchange tokens).
import { SignJWT, importJWK, decodeJwt } from 'jose';
import { answerKmsi } from './lib/kmsi.mjs';
import crypto from 'node:crypto';
import fs from 'node:fs';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const KEY = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url), 'utf8')));
const USER = process.argv[2] || 'tester';
const PASS = process.argv[3] || 'Test1234!';

const UA_MAC = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36';
const UA_IOS = 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1';

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
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
const setCookieValue = (res, name) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === name) return nv.slice(i + 1);
  }
  return null;
};

// Full interactive login with a chosen UA + country -> { cookie, code, verifier }.
async function login(ua, country) {
  const p = pkce();
  let r = await fetch(authzUrl(p.c), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location'), SSO).searchParams.get('txn');
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      origin: 'null', 'sec-fetch-site': 'same-origin',
      'user-agent': ua, 'cf-ipcountry': country,
    },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  const cookie = setCookieValue(r, 'sso_session'); // transient cookie on the KMSI page
  r = await answerKmsi(SSO, r, txn, csrf); // "Stay signed in?" -> code
  const loc = r.headers.get('location') || '';
  const code = loc.startsWith(REDIRECT) ? new URL(loc).searchParams.get('code') : null;
  return { cookie, code, verifier: p.v };
}
async function exchange(code, verifier) {
  const key = await importJWK(KEY, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(key);
  const r = await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: verifier,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  });
  return r.json();
}
const api = (method, path, token, body) =>
  fetch(SSO + path, {
    method,
    headers: { ...(token ? { authorization: 'Bearer ' + token } : {}), ...(body ? { 'content-type': 'application/json' } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });

// 1. two devices: Mac/Chrome (CA) + iPhone/Safari (US), each redeems a code.
const a = await login(UA_MAC, 'CA');
const ta = await exchange(a.code, a.verifier);
const sidA = ta.id_token ? decodeJwt(ta.id_token).sid : null;
const access = ta.access_token;
const b = await login(UA_IOS, 'US');
const tb = await exchange(b.code, b.verifier);
const sidB = tb.id_token ? decodeJwt(tb.id_token).sid : null;
ok(!!access && !!sidA && !!sidB && sidA !== sidB, '1. two distinct sessions + access token');

// 2. list shows both, parsed correctly
let r = await api('GET', '/account/sessions', access);
let list = (await r.json()).sessions || [];
const SA = list.find((s) => s.sid === sidA);
const SB = list.find((s) => s.sid === sidB);
ok(r.status === 200 && SA && SB, '2. GET /account/sessions lists both');
ok(SA?.device_name === 'Chrome 149 on macOS' && SA?.device_type === 'desktop',
   '2a. Mac device name (no OS version)', `(${SA?.device_name} / ${SA?.device_type})`);
ok(SB?.device_name === 'Safari 17 on iOS' && SB?.device_type === 'mobile',
   '2b. iPhone device name', `(${SB?.device_name} / ${SB?.device_type})`);
ok(SA?.country === 'CA' && SB?.country === 'US', '2c. country from cf-ipcountry', `(${SA?.country}/${SB?.country})`);
ok(Array.isArray(SA?.apps) && SA.apps.some((x) => x.client_id === CLIENT),
   '2d. apps-accessed includes videosite', `(${(SA?.apps || []).map((x) => x.client_id).join(',')})`);

// 3. auth/ownership guards
ok((await api('GET', '/account/sessions', null)).status === 401, '3a. no token -> 401');
ok((await api('DELETE', '/account/sessions/not-a-uuid', access)).status === 404, '3b. bad sid -> 404');
ok((await api('DELETE', '/account/sessions/' + crypto.randomUUID(), access)).status === 404, '3c. foreign/missing sid -> 404');
ok((await api('POST', '/account/sessions/terminate-others', access, {})).status === 400, '3d. terminate-others no keep_sid -> 400');

// 4. delete sidB -> gone from the list
ok((await api('DELETE', '/account/sessions/' + sidB, access)).status === 204, '4. DELETE sidB -> 204');
list = (await (await api('GET', '/account/sessions', access)).json()).sessions || [];
ok(!list.some((s) => s.sid === sidB) && list.some((s) => s.sid === sidA), '4a. sidB gone, sidA remains');

// 5. terminate-others keeping sidA -> only sidA left (also cleans up stale tester sessions)
ok((await api('POST', '/account/sessions/terminate-others', access, { keep_sid: sidA })).status === 204,
   '5. terminate-others keep sidA -> 204');
list = (await (await api('GET', '/account/sessions', access)).json()).sessions || [];
ok(list.length === 1 && list[0].sid === sidA, '5a. only sidA remains', `(count=${list.length})`);

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
