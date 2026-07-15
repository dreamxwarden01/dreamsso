// E2E for RP client-key rotation (both relying parties):
//   videosite: rotateClientKey() in-container -> host file gains {keys:[new, old]},
//     both kids published at its jwks_uri, OLD and NEW assertions both accepted
//     by the SSO (remote-JWKS refetch on the unknown kid), full login after a
//     container restart (running server signs with the new key)
//   portal: BFF /internal/rotate-client-key rejects garbage + replays (jti);
//     the SSO admin endpoint relays a signed rotate+jwt end-to-end; cap-2
//     retirement (oldest key drops on the second rotation); portal login e2e
// Rotation is the real operation — files stay rotated (that's the feature);
// only the admin door + perm override are restored.
// Run: npx tsx scripts/sso-client-key-rotation-test.ts
import { execSync } from 'node:child_process';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { SignJWT, importJWK, type JWK } from 'jose';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';
import { getSigningKey } from '../src/keys.js';
import { config } from '../src/config.js';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const STREAM = 'https://stream-dev.dreamxwarden.ca';
const PORTAL = 'https://account-dev.dreamxwarden.ca';
const BFF = 'http://127.0.0.1:4001';
const USER = 'tester';
const PASS = 'Test1234!';
const VS_KEY_FILE = new URL('../.videosite-client-key.json', import.meta.url);
const ACCT_KEY_FILE = new URL('../account/server/.account-client-key.json', import.meta.url);

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
type KeyFile = { keys: (JWK & { kid: string })[]; rotated_at?: string };
const readKeys = (u: URL): KeyFile => {
  const raw = JSON.parse(fs.readFileSync(u, 'utf8'));
  return Array.isArray(raw.keys) ? raw : { keys: [raw] };
};
const setCookie = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};

// Sign a videosite client assertion with a given private JWK; probe
// /internal/avatar with a well-formed-but-absent file name: 404 = the
// assertion VERIFIED (auth passed, file missing), 401 = key rejected.
async function probeAssertion(jwk: JWK & { kid: string }): Promise<number> {
  const key = await importJWK(jwk, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
    .setIssuer('videosite').setSubject('videosite').setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
    .sign(key);
  const r = await fetch(SSO + '/internal/avatar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      file: `${crypto.randomUUID()}-${crypto.randomBytes(8).toString('hex')}.webp`,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    }),
  });
  return r.status;
}

const mkJar = () => {
  const jar: Record<string, string> = {};
  return {
    jar,
    absorb(res: Response) {
      for (const c of res.headers.getSetCookie?.() ?? []) {
        const nv = c.split(';')[0];
        const i = nv.indexOf('=');
        if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
      }
    },
    cookie: () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '),
  };
};

async function ssoLoginLeg(startUrl: string, j: ReturnType<typeof mkJar>) {
  let r = await fetch(startUrl, { redirect: 'manual' });
  j.absorb(r);
  r = await fetch(r.headers.get('location')!, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf);
  return r.headers.get('location')!;
}

async function videositeLogin(): Promise<boolean> {
  const j = mkJar();
  const cbLoc = await ssoLoginLeg(STREAM + '/auth/login', j);
  const r = await fetch(cbLoc, { redirect: 'manual', headers: { cookie: j.cookie() } });
  j.absorb(r);
  if (!j.jar.sid) return false;
  const me = await fetch(STREAM + '/api/me', { headers: { cookie: j.cookie() } });
  return me.status === 200;
}

async function portalLogin(): Promise<boolean> {
  const j = mkJar();
  const cbLoc = await ssoLoginLeg(BFF + '/auth/login', j);
  const cb = new URL(cbLoc);
  const r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code')!)}&state=${encodeURIComponent(cb.searchParams.get('state')!)}`,
    { redirect: 'manual', headers: { cookie: j.cookie() } });
  j.absorb(r);
  if (!j.jar.acct_sid) return false;
  const me = await fetch(BFF + '/api/me', { headers: { cookie: j.cookie() } });
  return me.status === 200;
}

// ============================ videosite ============================
console.log('--- videosite ---');
const vsBefore = readKeys(VS_KEY_FILE);
const vsKidBefore = vsBefore.keys[0].kid;

// 1. rotate inside the container (same code path the admin route calls)
const out = execSync(
  `docker exec dreamsso-videosite-web-1 node -e "require('/app/lib/oidc').rotateClientKey().then((r) => { console.log(JSON.stringify(r)); process.exit(0); }).catch((e) => { console.error(e.message); process.exit(1); })"`,
).toString().trim();
const rot = JSON.parse(out) as { kid: string; rotated_at: string };
ok(!!rot.kid && rot.kid !== vsKidBefore, '1. rotateClientKey -> new kid', `(${rot.kid.slice(0, 12)}…)`);

const vsAfter = readKeys(VS_KEY_FILE);
ok(vsAfter.keys.length === 2 && vsAfter.keys[0].kid === rot.kid && vsAfter.keys[1].kid === vsKidBefore,
   '1a. host file: {keys:[new, old]} (bind mount, survives rebuilds)');

// 2. jwks_uri publishes both, private members stripped
let r = await fetch(STREAM + '/.well-known/jwks.json');
const pub = (await r.json()) as { keys: { kid: string; d?: string }[] };
ok(r.status === 200 && pub.keys.length === 2 &&
   pub.keys.some((k) => k.kid === rot.kid) && pub.keys.some((k) => k.kid === vsKidBefore) &&
   pub.keys.every((k) => !('d' in k)),
   '2. jwks_uri serves old + new, public halves only');

// 3. overlap: the SSO accepts BOTH keys (unknown kid triggers a refetch)
ok((await probeAssertion(vsAfter.keys[0])) === 404, '3. NEW key verifies at the SSO (404 = authed, file absent)');
ok((await probeAssertion(vsAfter.keys[1])) === 404, '3a. OLD key still verifies (published overlap)');

// 4. restart so the RUNNING server signs with the new key, then a full login
execSync('docker compose restart videosite-web', { cwd: new URL('..', import.meta.url).pathname, stdio: 'ignore' });
let up = false;
for (let i = 0; i < 30 && !up; i++) {
  try { up = (await fetch(STREAM + '/', { redirect: 'manual' })).status < 500; } catch { /* booting */ }
  if (!up) await new Promise((res) => setTimeout(res, 1000));
}
ok(up, '4. container back up after restart');
ok(await videositeLogin(), '4a. full videosite login (token exchange signed with the new key)');

// ============================ portal ============================
console.log('--- account portal ---');
const acctBefore = readKeys(ACCT_KEY_FILE);
const acctKidBefore = acctBefore.keys[0].kid;

// 5. internal endpoint: garbage token -> 401
r = await fetch(BFF + '/internal/rotate-client-key', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: 'x.y.z' }),
});
ok(r.status === 401, '5. garbage token -> 401');

// 6. valid SSO-signed token -> rotates; replay of the SAME token -> 401 (jti)
const { kid: ssoKid, privateKey } = await getSigningKey();
const now = Math.floor(Date.now() / 1000);
const rotateToken = await new SignJWT({})
  .setProtectedHeader({ alg: 'EdDSA', kid: ssoKid, typ: 'rotate+jwt' })
  .setIssuer(config.issuer).setAudience(config.accountClientId)
  .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
  .sign(privateKey);
r = await fetch(BFF + '/internal/rotate-client-key', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: rotateToken }),
});
const rot1 = (await r.json()) as { kid: string };
ok(r.status === 200 && !!rot1.kid && rot1.kid !== acctKidBefore, '6. signed rotate -> 200 + new kid');
r = await fetch(BFF + '/internal/rotate-client-key', {
  method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ token: rotateToken }),
});
ok(r.status === 401, '6a. replayed token -> 401 (jti guard)');

// 7. the SSO admin path (the actual button): admin login -> relay -> new kid;
//    second rotation also proves cap-2 retirement (kidBefore drops off)
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const { rows: suOrig } = await pool.query(`SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
await new Promise((res) => setTimeout(res, 5500)); // settings cache
try {
  let rr = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
  const txn = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
  rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrfForm = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  rr = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
  });
  const cookie = 'sso_session=' + setCookie(rr, 'sso_session');
  rr = await answerKmsi(SSO, rr, txn, csrfForm, { cookie });
  const csrf = ((await (await fetch(SSO + '/admin/api/me', { headers: { cookie } })).json()) as { csrf: string }).csrf;

  rr = await fetch(SSO + '/admin/api/account-portal/rotate-client-key', {
    method: 'POST', headers: { cookie, 'x-csrf-token': csrf },
  });
  const rot2 = (await rr.json()) as { kid: string };
  ok(rr.status === 200 && !!rot2.kid && rot2.kid !== rot1.kid, '7. admin button relays end-to-end', `(${(rot2.kid || '').slice(0, 12)}…)`);

  const acctAfter = readKeys(ACCT_KEY_FILE);
  ok(acctAfter.keys.length === 2 && acctAfter.keys[0].kid === rot2.kid && acctAfter.keys[1].kid === rot1.kid,
     '7a. cap-2 retirement: [newest, previous], original dropped');

  r = await fetch(PORTAL + '/.well-known/jwks.json');
  const acctPub = (await r.json()) as { keys: { kid: string; d?: string }[] };
  ok(acctPub.keys.length === 2 && acctPub.keys.some((k) => k.kid === rot2.kid) && acctPub.keys.every((k) => !('d' in k)),
     '7b. portal jwks_uri publishes both, public halves only');

  // 8. the BFF now signs with the newest key in-process (cache reset by rotate)
  ok(await portalLogin(), '8. full portal login (assertion signed with the newest key)');
} finally {
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
  if (suOrig[0]) {
    await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
  } else {
    await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
  }
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
