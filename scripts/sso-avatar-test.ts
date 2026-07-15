// E2E for profile pictures (phase 1: SSO core + portal path):
//   upload through the BFF -> processed to 1:1 webp (cover-crop, cap 512),
//   {sub}-{16hex}.webp name, old file deleted on replace
//   session-gated serving with private+max-age=1y+immutable
//   /api/me picture updates in place; a FRESH login carries the claim
//   KMSI page chip shows the avatar (capability URL, pre-session)
//   /internal/avatar S2S fetch with a videosite client assertion
//   account.profile_change lands in videosite's event outbox as delivered
//   server re-validation: garbage -> 422; small images stay small (1:1)
// State: requires tester to start with NO avatar; removes everything it made.
// Run: npx tsx scripts/sso-avatar-test.ts
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import sharp from 'sharp';
import { SignJWT, importJWK } from 'jose';
import { answerKmsi } from './lib/kmsi.mjs';
import { pool } from '../src/db.js';

const BFF = 'http://127.0.0.1:4001';
const SSO = 'https://sso-dev.dreamxwarden.ca';
const USER = 'tester';
const PASS = 'Test1234!';
const AVATAR_DIR = path.join(process.cwd(), 'data', 'avatars');
const FILE_RE = /^[0-9a-f-]{36}-[0-9a-f]{16}\.webp$/;

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const jar: Record<string, string> = {};
const absorb = (res: Response) => {
  for (const c of res.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0) jar[nv.slice(0, i)] = nv.slice(i + 1);
  }
};
const cookie = () => Object.entries(jar).map(([k, v]) => `${k}=${v}`).join('; ');

async function bffLogin(): Promise<boolean> {
  for (const k of Object.keys(jar)) delete jar[k];
  let r = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  absorb(r);
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
  const cb = new URL(r.headers.get('location')!);
  r = await fetch(`${BFF}/auth/callback?code=${encodeURIComponent(cb.searchParams.get('code')!)}&state=${encodeURIComponent(cb.searchParams.get('state')!)}`,
    { redirect: 'manual', headers: { cookie: cookie() } });
  absorb(r);
  return !!jar.acct_sid;
}

// --- baseline guard ---
const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
const { rows: [{ avatar: origAvatar }] } = await pool.query('SELECT avatar FROM identities WHERE sub = $1', [sub]);
if (origAvatar) {
  console.error(`tester already has an avatar (${origAvatar}) — refusing to run`);
  process.exit(1);
}

ok(await bffLogin(), '1. login -> BFF session');

// 2. upload a 800x600 JPEG -> cover-cropped to 512x512 webp
const bigJpeg = await sharp({ create: { width: 800, height: 600, channels: 3, background: { r: 200, g: 30, b: 30 } } })
  .jpeg().toBuffer();
let r = await fetch(BFF + '/api/avatar', {
  method: 'POST',
  headers: { cookie: cookie(), 'content-type': 'image/jpeg' },
  body: new Uint8Array(bigJpeg),
});
const up1 = (await r.json()) as { avatar: string };
ok(r.status === 200 && FILE_RE.test(up1.avatar) && up1.avatar.startsWith(sub + '-'),
   '2. upload -> {sub}-{16hex}.webp', `(${up1.avatar})`);
const p1 = path.join(AVATAR_DIR, up1.avatar);
const meta1 = await sharp(p1).metadata();
ok(meta1.format === 'webp' && meta1.width === 512 && meta1.height === 512,
   '2a. stored as 512x512 webp (cover-cropped)', `(${meta1.width}x${meta1.height})`);
const { rows: [{ avatar: dbAv1 }] } = await pool.query('SELECT avatar FROM identities WHERE sub = $1', [sub]);
ok(dbAv1 === up1.avatar, '2b. identities.avatar updated');

// 3. serving: session-gated, immutable
r = await fetch(BFF + '/api/avatar/' + up1.avatar, { headers: { cookie: cookie() } });
ok(r.status === 200 && r.headers.get('content-type')?.includes('image/webp') &&
   r.headers.get('cache-control') === 'private, max-age=31536000, immutable',
   '3. GET via BFF -> webp + private/immutable', `(${r.headers.get('cache-control')})`);
r = await fetch(BFF + '/api/avatar/' + up1.avatar);
ok(r.status === 401, '3a. no session -> 401');

// 4. /api/me carries the picture immediately (session claim updated in place)
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(((await r.json()) as { profile: { picture: string } }).profile.picture === up1.avatar,
   '4. /api/me picture fresh without re-login');

// 5. garbage -> 422 from the server-side re-validation
r = await fetch(BFF + '/api/avatar', {
  method: 'POST',
  headers: { cookie: cookie(), 'content-type': 'image/png' },
  body: new Uint8Array(Buffer.from('definitely not an image')),
});
ok(r.status === 422 && (await r.json()).error === 'unprocessable_image', '5. garbage -> 422 unprocessable_image');

// 6. small non-square image stays small: 100x80 -> 80x80; old file deleted
const smallPng = await sharp({ create: { width: 100, height: 80, channels: 3, background: { r: 20, g: 90, b: 200 } } })
  .png().toBuffer();
r = await fetch(BFF + '/api/avatar', {
  method: 'POST',
  headers: { cookie: cookie(), 'content-type': 'image/png' },
  body: new Uint8Array(smallPng),
});
const up2 = (await r.json()) as { avatar: string };
const meta2 = await sharp(path.join(AVATAR_DIR, up2.avatar)).metadata();
ok(r.status === 200 && up2.avatar !== up1.avatar && meta2.width === 80 && meta2.height === 80,
   '6. small image -> 80x80 (1:1, no upscale), new name', `(${meta2.width}x${meta2.height})`);
ok(!fs.existsSync(p1), '6a. previous file deleted on replace');

// 7. capability URL on the SSO itself (used by KMSI/step-up chips pre-session)
r = await fetch(SSO + '/avatar/' + up2.avatar);
ok(r.status === 200 && r.headers.get('cache-control') === 'private, max-age=31536000, immutable',
   '7. SSO /avatar capability URL serves');
r = await fetch(SSO + '/avatar/' + sub + '-' + '0'.repeat(16) + '.webp');
ok(r.status === 404, '7a. wrong suffix -> 404 (name is the capability)');

// 8. KMSI page chip shows the avatar (fresh login, capture the KMSI HTML)
{
  let rr = await fetch(BFF + '/auth/login', { redirect: 'manual' });
  const flowCookies: Record<string, string> = {};
  for (const c of rr.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0]; const i = nv.indexOf('=');
    if (i > 0) flowCookies[nv.slice(0, i)] = nv.slice(i + 1);
  }
  rr = await fetch(rr.headers.get('location')!, { redirect: 'manual' });
  const t = new URL(rr.headers.get('location')!, SSO).searchParams.get('txn')!;
  rr = await fetch(SSO + '/login?txn=' + encodeURIComponent(t));
  const cs = ((await rr.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  rr = await fetch(SSO + '/login', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn: t, csrf: cs, username: USER, password: PASS }),
  });
  const html = await rr.text();
  ok(html.includes('Stay signed in?') && html.includes(`/avatar/${up2.avatar}`) && html.includes('chip-av'),
     '8. KMSI chip carries the avatar');
}

// 9. /internal/avatar with a videosite client assertion
{
  const priv = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(path.join(process.cwd(), '.videosite-client-key.json'), 'utf8')));
  const key = await importJWK(priv, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: priv.kid })
    .setIssuer('videosite').setSubject('videosite').setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID())
    .sign(key);
  r = await fetch(SSO + '/internal/avatar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      file: up2.avatar,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
      client_assertion: assertion,
    }),
  });
  const bytes = Buffer.from(await r.arrayBuffer());
  ok(r.status === 200 && bytes.length > 0, '9. S2S fetch with videosite assertion', `(${bytes.length} bytes)`);
  r = await fetch(SSO + '/internal/avatar', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ file: up2.avatar, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: 'x.y.z' }),
  });
  ok(r.status === 401, '9a. bad assertion -> 401');
}

// 10. profile_change event delivered to videosite (poll the outbox archive)
{
  let delivered = false;
  for (let i = 0; i < 15 && !delivered; i++) {
    const { rows } = await pool.query(
      `SELECT status FROM event_outbox
        WHERE kind = 'account.profile_change' AND target_client_id = 'videosite'
          AND payload->>'sub' = $1 AND payload->>'avatar' = $2`,
      [sub, up2.avatar],
    );
    if (rows.some((x) => x.status === 'delivered')) delivered = true;
    else await new Promise((res) => setTimeout(res, 1000));
  }
  ok(delivered, '10. account.profile_change delivered to videosite');
}

// 11. fresh login carries the claim end-to-end
ok(await bffLogin(), '11. second login');
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(((await r.json()) as { profile: { picture: string } }).profile.picture === up2.avatar,
   '11a. picture claim present after fresh login');

// 12. remove
r = await fetch(BFF + '/api/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
ok(r.status === 204, '12. delete -> 204');
const { rows: [{ avatar: dbAv2 }] } = await pool.query('SELECT avatar FROM identities WHERE sub = $1', [sub]);
ok(dbAv2 === null && !fs.existsSync(path.join(AVATAR_DIR, up2.avatar)), '12a. cleared in DB + file removed');
r = await fetch(BFF + '/api/me', { headers: { cookie: cookie() } });
ok(((await r.json()) as { profile: { picture: string | null } }).profile.picture === null,
   '12b. /api/me picture null again');

// 13. self-service gate: profile.picture.set deny -> 403 on upload AND delete
{
  await pool.query(
    `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'profile.picture.set', 'deny')
       ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'deny'`, [sub]);
  r = await fetch(BFF + '/api/avatar', {
    method: 'POST', headers: { cookie: cookie(), 'content-type': 'image/png' }, body: new Uint8Array(smallPng),
  });
  const b13 = (await r.json()) as { error: string };
  ok(r.status === 403 && b13.error === 'permission_denied', '13. upload denied w/o profile.picture.set', `(${r.status} ${b13.error})`);
  r = await fetch(BFF + '/api/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
  ok(r.status === 403, '13a. delete denied too', `(${r.status})`);
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.picture.set'`, [sub]);
  r = await fetch(BFF + '/api/avatar', {
    method: 'POST', headers: { cookie: cookie(), 'content-type': 'image/png' }, body: new Uint8Array(smallPng),
  });
  const b13b = (await r.json()) as { avatar: string };
  ok(r.status === 200 && FILE_RE.test(b13b.avatar), '13b. grant restored -> upload works');
  // clean back to no-avatar baseline
  await fetch(BFF + '/api/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
}

// 14/15. org remove: admin actor takes down a lower user's picture; the
// standard_user role default denies it. Parks tester's org role + the portal
// step-up door; restores both.
{
  const { uuidv7 } = await import('uuidv7');
  const { rows: [{ org_role_slug: origRole }] } = await pool.query(
    'SELECT org_role_slug FROM user_org_roles WHERE user_sub = $1', [sub]);
  const { rows: doorOrig } = await pool.query(
    `SELECT value FROM settings WHERE key = 'stepup_portal_required'`);
  await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_portal_required', 'false')
    ON CONFLICT (key) DO UPDATE SET value = 'false'`);
  await pool.query(`UPDATE user_org_roles SET org_role_slug = 'admin' WHERE user_sub = $1`, [sub]);

  // throwaway target: standard_user with a (physically present) avatar file
  const tSub = uuidv7();
  const tFile = `${tSub}-${crypto.randomBytes(8).toString('hex')}.webp`;
  fs.writeFileSync(path.join(AVATAR_DIR, tFile), await sharp({
    create: { width: 16, height: 16, channels: 3, background: { r: 9, g: 9, b: 9 } } }).webp().toBuffer());
  await pool.query(
    `INSERT INTO identities (sub, username, display_name, avatar) VALUES ($1, $2, 'Avatar Target', $3)`,
    [tSub, 'avt-' + tSub.slice(0, 8), tFile]);
  await pool.query(`INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, 'standard_user')`, [tSub]);
  await new Promise((res) => setTimeout(res, 5500)); // settings memo TTL

  try {
    r = await fetch(BFF + '/api/org/users/' + tSub, { headers: { cookie: cookie() } });
    const det = (await r.json()) as { profile: { avatar: string | null } };
    ok(r.status === 200 && det.profile.avatar === tFile, '14. org detail carries the avatar file');
    r = await fetch(BFF + '/api/org/users?query=avt-' + tSub.slice(0, 8), { headers: { cookie: cookie() } });
    const list = (await r.json()) as { users: { sub: string; avatar: string | null }[] };
    ok(list.users.some((u) => u.sub === tSub && u.avatar === tFile), '14a. org list carries it too');

    r = await fetch(BFF + '/api/org/users/' + sub + '/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
    ok(r.status === 404, '14b. self via org route -> 404 (never self-administer)');

    r = await fetch(BFF + '/api/org/users/' + tSub + '/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
    ok(r.status === 204, '14c. admin removes the picture -> 204', `(${r.status})`);
    const { rows: [{ avatar: tAv }] } = await pool.query('SELECT avatar FROM identities WHERE sub = $1', [tSub]);
    ok(tAv === null && !fs.existsSync(path.join(AVATAR_DIR, tFile)), '14d. cleared in DB + file removed');
    const { rows: aud } = await pool.query(
      `SELECT 1 FROM org_audit_log WHERE action = 'user.avatar_remove' AND target_sub = $1 AND actor_sub = $2`,
      [tSub, sub]);
    ok(aud.length === 1, '14e. audit entry user.avatar_remove');

    // role default deny: back to standard_user -> requirePerm blocks up front
    await pool.query(`UPDATE user_org_roles SET org_role_slug = 'standard_user' WHERE user_sub = $1`, [sub]);
    r = await fetch(BFF + '/api/org/users/' + tSub + '/avatar', { method: 'DELETE', headers: { cookie: cookie() } });
    const b15 = (await r.json()) as { error: string };
    ok(r.status === 403 && b15.error === 'permission_denied', '15. standard_user denied org remove', `(${r.status} ${b15.error})`);
  } finally {
    await pool.query(`UPDATE user_org_roles SET org_role_slug = $2 WHERE user_sub = $1`, [sub, origRole]);
    await pool.query(`DELETE FROM user_org_roles WHERE user_sub = $1`, [tSub]);
    await pool.query(`DELETE FROM identities WHERE sub = $1`, [tSub]);
    if (fs.existsSync(path.join(AVATAR_DIR, tFile))) fs.unlinkSync(path.join(AVATAR_DIR, tFile));
    if (doorOrig[0]) {
      await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_portal_required'`, [doorOrig[0].value]);
    } else {
      await pool.query(`DELETE FROM settings WHERE key = 'stepup_portal_required'`);
    }
  }
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
