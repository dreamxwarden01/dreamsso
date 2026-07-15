// E2E for avatar phase 2 — videosite as consumer:
//   portal upload -> account.profile_change event -> users.sso_avatar mirrored
//   videosite /api/me + /api/profile carry the file name
//   GET /api/avatar/:file -> S2S fetch-on-miss, private+immutable (own-only)
//   claim path: column nulled directly -> fresh login repopulates from `picture`
//   portal delete -> event clears the mirror
// State: tester must start with no avatar anywhere; ends clean.
// Run: node scripts/videosite-avatar-test.mjs
import { execSync } from 'node:child_process';
import sharp from 'sharp';
import { answerKmsi } from './lib/kmsi.mjs';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const STREAM = 'https://stream-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';

// SQL via stdin (two shell layers mangle inline quotes — the known gotcha)
const sql = (q) =>
  execSync(`docker exec -i dreamsso-videosite-db-1 sh -c 'mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" videosite -N' 2>/dev/null`, { input: q })
    .toString().trim();

let fail = 0;
const ok = (c, label, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const mkJar = () => {
  const jar = {};
  return {
    jar,
    absorb(res) {
      for (const c of res.headers.getSetCookie?.() ?? []) {
        const nv = c.split(';')[0];
        const i = nv.indexOf('=');
        if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
      }
    },
    cookie: () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; '),
  };
};

async function ssoLoginLeg(startUrl, j) {
  let r = await fetch(startUrl, { redirect: 'manual' });
  j.absorb(r);
  r = await fetch(r.headers.get('location'), { redirect: 'manual' });
  const txn = new URL(r.headers.get('location'), SSO).searchParams.get('txn');
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf, username: USER, password: PASS }),
  });
  r = await answerKmsi(SSO, r, txn, csrf);
  return r.headers.get('location');
}

async function videositeLogin() {
  const j = mkJar();
  const cbLoc = await ssoLoginLeg(STREAM + '/auth/login', j);
  const r = await fetch(cbLoc, { redirect: 'manual', headers: { cookie: j.cookie() } });
  j.absorb(r);
  return j;
}

async function portalLogin() {
  const j = mkJar();
  const cbLoc = await ssoLoginLeg(BFF + '/auth/login', j);
  const cb = new URL(cbLoc);
  const r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code'))}&state=${encodeURIComponent(cb.searchParams.get('state'))}`,
    { redirect: 'manual', headers: { cookie: j.cookie() } });
  j.absorb(r);
  return j;
}

const pollColumn = async (want, label) => {
  for (let i = 0; i < 15; i++) {
    const v = sql(`SELECT COALESCE(sso_avatar,'NULL') FROM users WHERE username='${USER}';`);
    if (v === want) return true;
    await new Promise((r) => setTimeout(r, 1000));
  }
  return false;
};

// --- baseline ---
const base = sql(`SELECT COALESCE(sso_avatar,'NULL') FROM users WHERE username='${USER}';`);
if (base !== 'NULL') {
  console.error(`tester already has a mirrored avatar (${base}) — refusing to run`);
  process.exit(1);
}

// 1. portal upload
const portal = await portalLogin();
ok(!!portal.jar.acct_sid, '1. portal login');
const img = await sharp({ create: { width: 640, height: 640, channels: 3, background: { r: 40, g: 160, b: 90 } } })
  .jpeg().toBuffer();
let r = await fetch(BFF + '/api/avatar', {
  method: 'POST',
  headers: { cookie: portal.cookie(), 'content-type': 'image/jpeg' },
  body: new Uint8Array(img),
});
const { avatar: file } = await r.json();
ok(r.status === 200 && !!file, '1a. uploaded', `(${file})`);

// 2. event mirrors the file name into videosite
ok(await pollColumn(file), '2. users.sso_avatar mirrored via account.profile_change');

// 3. videosite session: /api/me + /api/profile + serving
const vs = await videositeLogin();
ok(!!vs.jar.sid, '3. videosite login');
r = await fetch(STREAM + '/api/me', { headers: { cookie: vs.cookie() } });
const me = await r.json();
ok(me.user?.avatar === file, '3a. /api/me carries the avatar file name');
r = await fetch(STREAM + '/api/profile', { headers: { cookie: vs.cookie() } });
ok((await r.json()).profile?.avatar === file, '3b. /api/profile carries it too');
r = await fetch(STREAM + '/api/avatar/' + file, { headers: { cookie: vs.cookie() } });
const bytes = Buffer.from(await r.arrayBuffer());
ok(r.status === 200 && r.headers.get('cache-control') === 'private, max-age=31536000, immutable' &&
   r.headers.get('content-type')?.includes('image/webp') && bytes.length > 0,
   '3c. served via S2S fetch-on-miss, private+immutable', `(${bytes.length} bytes)`);
r = await fetch(STREAM + '/api/avatar/' + file.replace(/.{5}\.webp$/, '00000.webp'), { headers: { cookie: vs.cookie() } });
ok(r.status === 404, '3d. wrong name -> 404 (own-only)');
r = await fetch(STREAM + '/api/avatar/' + file);
ok(r.status === 401, '3e. no session -> 401');

// 4. claim path: null the mirror directly -> a fresh login repopulates it
sql(`UPDATE users SET sso_avatar = NULL WHERE username='${USER}';`);
await videositeLogin();
ok(await pollColumn(file), '4. picture claim at callback restores the mirror');

// 5. portal delete -> event clears it
r = await fetch(BFF + '/api/avatar', { method: 'DELETE', headers: { cookie: portal.cookie() } });
ok(r.status === 204, '5. portal delete -> 204');
ok(await pollColumn('NULL'), '5a. mirror cleared via event');

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
process.exit(fail ? 1 : 0);
