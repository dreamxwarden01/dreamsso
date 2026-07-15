// E2E for org management slices 2-4 (users/roles/apps + the guard matrix):
//   visibility: same-or-lower listed, higher hidden; detail = strictly lower,
//     never self
//   org-role grants strictly below the actor; app-role/permission ceilings
//     (hold-it-to-touch-it, current-above -> locked, inherit resolved)
//   app-role override -> account.roles_change -> videosite users.role_id
//   No access -> SSO sign-in gate refuses with access_denied
//   role editor (create/patch/delete/default) + reconciliation on roles.sync
//   suspend/reactivate, set-password, send-reset (mocked mailer), create user
//   MFA reset: plain when step-up off; one-time action ceremony when on
//   self-service change-password keeps ONLY the caller's session
// Actor = tester temporarily promoted to admin; target = the throwaway demo.
// Snapshots and restores EVERYTHING it touches. Run: npx tsx scripts/sso-org-admin-test.ts
import { SignJWT, importJWK } from 'jose';
import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import { execSync } from 'node:child_process';
import { generateSecret, generateSync } from 'otplib';
import { pool } from '../src/db.js';
import { redis } from '../src/redis.js';
import { sealSecret } from '../src/secretbox.js';
import { drainAll, enqueueEvents } from '../src/events.js';
import { answerKmsi, FORM } from './lib/kmsi.mjs';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const REDIRECT = 'https://stream-dev.dreamxwarden.ca/auth/callback';
const KEY = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url), 'utf8')));
const USER = 'tester';
const PASS = 'Test1234!';
const MOCK_PORT = 8899;

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const cookieOf = (r: Response) =>
  (r.headers.getSetCookie?.() ?? []).find((c) => c.startsWith('sso_session='))?.split(';')[0] ?? null;

// SQL rides stdin — two shell layers make inline quoting hopeless.
const mariadb = (sql: string): string =>
  execSync(`docker exec -i dreamsso-videosite-db-1 sh -c 'exec mariadb -uroot -p"$MARIADB_ROOT_PASSWORD" videosite -N'`,
    { encoding: 'utf8', input: sql }).trim();

// mock mailer (cf_api_base) — captures reset/notice emails, no real sends
const mails: { to: string; subject: string; html: string }[] = [];
const mock = http.createServer((q, resp) => {
  let raw = '';
  q.on('data', (c) => (raw += c));
  q.on('end', () => {
    mails.push(JSON.parse(raw || '{}'));
    resp.setHeader('content-type', 'application/json');
    resp.end(JSON.stringify({ success: true, errors: [], result: { delivered: ['x'], permanent_bounces: [], queued: [] } }));
  });
});
await new Promise<void>((r) => mock.listen(MOCK_PORT, '127.0.0.1', r));

async function login(user = USER, pass = PASS) {
  const v = crypto.randomBytes(32).toString('base64url');
  const chal = crypto.createHash('sha256').update(v).digest('base64url');
  const u = new URL(SSO + '/authorize');
  u.search = new URLSearchParams({
    response_type: 'code', client_id: CLIENT, redirect_uri: REDIRECT, scope: 'openid profile email',
    state: 'x', nonce: 'y', code_challenge: chal, code_challenge_method: 'S256', prompt: 'login',
  }).toString();
  let r = await fetch(u, { redirect: 'manual' });
  const txn = new URL(r.headers.get('location')!, SSO).searchParams.get('txn')!;
  r = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrf = ((await r.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  r = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual', headers: FORM,
    body: new URLSearchParams({ txn, csrf, username: user, password: pass }),
  });
  const cookie = cookieOf(r);
  const done = await answerKmsi(SSO, r, txn, csrf, { cookie });
  const loc = done.headers.get('location') || '';
  if (!loc.includes('code=')) return { denied: loc, token: '', sid: '' };
  const code = new URL(loc).searchParams.get('code')!;
  const key = await importJWK(KEY, 'EdDSA');
  const now = Math.floor(Date.now() / 1000);
  const assertion = await new SignJWT({})
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(now).setExpirationTime(now + 60).setJti(crypto.randomUUID()).sign(key);
  const tok = await (await fetch(SSO + '/token', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      grant_type: 'authorization_code', code, redirect_uri: REDIRECT, code_verifier: v,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: assertion,
    }),
  })).json();
  const hash = crypto.createHash('sha256').update(cookie!.split('=')[1]).digest();
  const { rows: [s] } = await pool.query('SELECT sid FROM sessions WHERE token_hash = $1', [hash]);
  return { denied: null, token: tok.access_token as string, sid: s.sid as string };
}

// hand-signed roles.sync envelopes (reconciliation checks) — monotonic, and
// seeded ABOVE the stored last_sync_iat (a fresh container boot-sync would
// otherwise outrank back-dated test envelopes and the ordering guard would
// rightly discard them).
let iatSeq = Math.floor(Date.now() / 1000) - 40;
{
  const { rows: [cat] } = await pool.query(
    `SELECT last_sync_iat FROM app_role_catalogs WHERE client_id = 'videosite'`);
  if (cat) iatSeq = Math.max(iatSeq, Number(cat.last_sync_iat));
}
async function pushSync(roles: { role_id: number; name: string; level: number; is_system?: boolean }[], defaultRole: number | null) {
  const k = await importJWK(KEY, 'EdDSA');
  // a real videosite sync (boot, or the previous run's cleanup restore) may
  // land mid-run and raise the guard — always outbid the CURRENT stored iat
  const { rows: [cur] } = await pool.query(
    `SELECT last_sync_iat FROM app_role_catalogs WHERE client_id = 'videosite'`);
  iatSeq = Math.max(iatSeq + 1, Number(cur?.last_sync_iat ?? 0) + 1);
  const iat = iatSeq;
  const tok = await new SignJWT({
    events: [{ id: crypto.randomUUID(), type: 'roles.sync', payload: { default_role: defaultRole, roles } }],
  })
    .setProtectedHeader({ alg: 'EdDSA', kid: KEY.kid, typ: 'events+jwt' })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(SSO)
    .setIssuedAt(iat).setExpirationTime(iat + 120).setJti(crypto.randomUUID()).sign(k);
  return fetch(SSO + '/backchannel/events', {
    method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ event_token: tok }),
  });
}
const BASE_ROLES = [
  { role_id: 0, name: 'superadmin', level: 0, is_system: true },
  { role_id: 1, name: 'admin', level: 1, is_system: true },
  { role_id: 2, name: 'user', level: 10, is_system: true },
];

// --- snapshots ---
const subOf = async (u: string) => (await pool.query('SELECT sub FROM identities WHERE username = $1', [u])).rows[0]?.sub;
const T = await subOf(USER);
const D = await subOf('demo');
if (!D) { console.error('demo user missing — aborting'); process.exit(1); }
const idSnap = async (s: string) => (await pool.query(
  `SELECT username, display_name, email, email_verified, status, mfa_enabled, password_hash, password_changed_at
     FROM identities WHERE sub = $1`, [s])).rows[0];
const tSnap = await idSnap(T);
const dSnap = await idSnap(D);
const roleSnap = async (s: string) => (await pool.query('SELECT org_role_slug FROM user_org_roles WHERE user_sub = $1', [s])).rows[0]?.org_role_slug ?? null;
const tRole = await roleSnap(T);
const dRole = await roleSnap(D);
const dVideoRole = (() => { try { return mariadb(`SELECT role_id FROM users WHERE user_id = UNHEX(REPLACE('${D}','-',''))`); } catch { return ''; } })();
const userRoleLevel = (await pool.query(`SELECT level FROM org_roles WHERE slug = 'standard_user'`)).rows[0]?.level ?? 10;
const SETTING_KEYS = ['cf_api_base', 'stepup_portal_required'];
const { rows: origSettings } = await pool.query('SELECT key, value FROM settings WHERE key = ANY($1)', [SETTING_KEYS]);
// The guard checks assume the test-admin's effective videosite role is the
// CATALOG default (user). A live org default for the admin role (set via the
// Roles UI) would raise that ceiling — snapshot the row, pin to absent,
// restore verbatim.
const { rows: [advDefSnap] } = await pool.query(
  `SELECT app_role_id FROM org_role_app_defaults WHERE role_slug = 'admin' AND client_id = 'videosite'`);
await pool.query(`DELETE FROM org_role_app_defaults WHERE role_slug = 'admin' AND client_id = 'videosite'`);
const setDb = async (k: string, v: string | null) => {
  await pool.query('DELETE FROM settings WHERE key = $1', [k]);
  if (v != null) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [k, v]);
};
const startedAt = new Date();
const setRole = (s: string, slug: string) => pool.query(
  `INSERT INTO user_org_roles (user_sub, org_role_slug) VALUES ($1, $2)
   ON CONFLICT (user_sub) DO UPDATE SET org_role_slug = $2`, [s, slug]);

try {
  await setDb('cf_api_base', `http://127.0.0.1:${MOCK_PORT}`);
  await setDb('stepup_portal_required', null);
  await setRole(T, 'admin'); // the actor: level 1
  await pool.query('DELETE FROM user_app_role_overrides WHERE user_sub = ANY($1)', [[T, D]]);
  await sleep(5500);

  const a = await login();
  const api = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) =>
    fetch(SSO + '/account/org' + path, {
      method,
      headers: { authorization: 'Bearer ' + a.token, ...(body !== undefined ? { 'content-type': 'application/json' } : {}), ...headers },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });

  // 1. visibility + sort
  let r = await api('GET', '/users?limit=200');
  let d = await r.json();
  const me = d.users.find((u: { sub: string }) => u.sub === T);
  const demo = d.users.find((u: { sub: string }) => u.sub === D);
  ok(r.status === 200 && !!me && me.me === true && me.editable === false,
     '1. self listed, chevron-less (me, not editable)');
  ok(!!demo && demo.editable === true, '1a. lower-privilege target editable');
  ok(!d.users.some((u: { role: { level: number } | null }) => u.role && u.role.level < 1),
     '1b. higher-privilege users hidden entirely');
  const levels = d.users.map((u: { role: { level: number } | null }) => u.role?.level ?? 2147483647);
  ok(levels.every((v: number, i: number) => i === 0 || v >= levels[i - 1]), '1c. sorted by level asc');

  // 2. detail authority
  const superSub = await subOf('dreamxwarden01');
  ok((await api('GET', '/users/' + superSub)).status === 404, '2. higher-privilege detail -> 404');
  ok((await api('GET', '/users/' + T)).status === 404, '2a. self detail -> 404');
  r = await api('GET', '/users/' + D);
  d = await r.json();
  ok(r.status === 200 && d.profile.username === 'demo' && Array.isArray(d.permissions) && Array.isArray(d.app_roles),
     '2b. lower-privilege detail -> 200 with sections');
  const permRow = (k: string) => d.permissions.find((x: { key: string }) => x.key === k);
  ok(permRow('profile.email.change').editable === true && permRow('org.logs.clear').editable === false,
     '2c. override rows: unheld keys view-only (hold-it-to-touch-it)');

  // 3. org-role guards
  r = await api('POST', `/users/${D}/org-role`, { role_slug: 'admin' });
  ok(r.status === 403 && (await r.json()).error === 'role_above_level', '3. grant at own level -> 403 (no peers)');
  r = await api('POST', '/roles', { slug: 'orgtest_role', label: 'Org Test Role', level: 5 });
  ok(r.status === 201, '3a. create role below own level -> 201', `(${r.status})`);
  r = await api('POST', '/roles', { slug: 'orgtest_high', label: 'Too High', level: 1 });
  ok(r.status === 422, '3b. create role at own level -> 422');
  r = await api('POST', `/users/${D}/org-role`, { role_slug: 'orgtest_role' });
  ok(r.status === 204, '3c. assign created role -> 204');

  // 4. role editor guards
  ok((await api('PATCH', '/roles/superadmin', { label: 'Nope' })).status === 403, '4. edit role above own -> 403');
  r = await api('DELETE', '/roles/orgtest_role');
  ok(r.status === 409 && (await r.json()).error === 'role_in_use', '4a. delete role with members -> 409');
  ok((await api('PUT', '/roles-default', { slug: 'orgtest_role' })).status === 204, '4b. move default -> 204');
  r = await api('GET', '/roles');
  ok((await r.json()).default_role === 'orgtest_role', '4c. singular default moved');
  await api('PUT', '/roles-default', { slug: 'standard_user' });

  // 5. permission overrides
  ok((await api('PUT', `/users/${D}/permissions/profile.email.change`, { effect: 'deny' })).status === 204,
     '5. override with a held key -> 204');
  r = await api('PUT', `/users/${D}/permissions/org.logs.clear`, { effect: 'grant' });
  ok(r.status === 403 && (await r.json()).error === 'permission_denied', '5a. override with an UNHELD key -> 403');
  ok((await api('PUT', `/users/${D}/permissions/profile.email.change`, { effect: 'inherit' })).status === 204,
     '5b. inherit removes the override');

  // 6. app roles: ceilings + the event to videosite
  r = await api('PUT', `/users/${D}/app-roles/videosite`, { value: 1 });
  ok(r.status === 403 && (await r.json()).error === 'app_role_above_level',
     '6. grant above own effective app role -> 403');
  ok((await api('PUT', `/users/${D}/app-roles/videosite`, { value: null })).status === 204,
     '6a. No access (below own) -> 204');
  // actor upgrades own footing (DB: superadmin app role), then grants admin
  await pool.query(`INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, 'videosite', 0)`, [T]);
  ok((await api('PUT', `/users/${D}/app-roles/videosite`, { value: 1 })).status === 204,
     '6b. with own footing raised, grant level 1 -> 204');
  if (dVideoRole) {
    let applied = '';
    for (let i = 0; i < 16 && applied !== '1'; i++) {
      await sleep(1000);
      applied = mariadb(`SELECT role_id FROM users WHERE user_id = UNHEX(REPLACE('${D}','-',''))`);
    }
    ok(applied === '1', '6c. account.roles_change applied in videosite (service layer)', `(role_id=${applied})`);
  } else {
    ok(true, '6c. (skipped — demo not present in videosite)');
  }

  // 6d. sign-in gate: tester set to No access -> access_denied at code mint
  await pool.query(`INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, 'videosite', NULL)
                      ON CONFLICT (user_sub, client_id) DO UPDATE SET app_role_id = NULL`, [T]);
  const blocked = await login();
  ok(!!blocked.denied && blocked.denied.includes('error=access_denied'),
     '6d. No access -> sign-in refused with access_denied', `(${blocked.denied?.slice(0, 60)}…)`);
  await pool.query(`UPDATE user_app_role_overrides SET app_role_id = 0 WHERE user_sub = $1 AND client_id = 'videosite'`, [T]);
  ok(!(await login()).denied, '6e. restored -> sign-in works again');

  // 7. org-role app default -> members notified
  const { rows: outBefore } = await pool.query(
    `SELECT count(*)::int AS n FROM event_outbox WHERE kind = 'account.roles_change'`);
  ok((await api('PUT', `/roles/orgtest_role/app-defaults/videosite`, { value: 2 })).status === 204,
     '7. org-role app default set -> 204');
  // demo has an override (1) so the default change alone must NOT notify demo;
  // remove the override -> effective now follows the org default
  ok((await api('PUT', `/users/${D}/app-roles/videosite`, { value: 'inherit' })).status === 204,
     '7a. override -> inherit (falls to org default 2, within ceiling)');

  // 8. reconciliation: removed role moves holders per the level rule
  await (await pushSync([...BASE_ROLES, { role_id: 7, name: 'temp7', level: 5 }], 2)).text();
  ok((await api('PUT', `/users/${D}/app-roles/videosite`, { value: 7 })).status === 204, '8. override to temp role 7');
  r = await pushSync(BASE_ROLES, 2); // role 7 (level 5) removed; outranks default (10) -> moved to default
  ok(r.status === 204, '8a. sync without role 7 accepted');
  const { rows: [ov1] } = await pool.query(
    `SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = 'videosite'`, [D]);
  ok(ov1?.app_role_id === 2, '8b. outranking removed role -> moved to default', `(${ov1?.app_role_id})`);
  await (await pushSync([...BASE_ROLES, { role_id: 9, name: 'temp9', level: 20 }], 2)).text();
  await api('PUT', `/users/${D}/app-roles/videosite`, { value: 9 });
  await pushSync(BASE_ROLES, 2); // role 9 (level 20) below default -> No access
  const { rows: [ov2] } = await pool.query(
    `SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = 'videosite'`, [D]);
  ok(ov2 && ov2.app_role_id === null, '8c. outranked removed role -> No access (deny-safe)');
  const { rows: [sysAudit] } = await pool.query(
    `SELECT actor_label FROM org_audit_log WHERE action = 'roles.reconcile' AND created_at >= $1 LIMIT 1`, [startedAt]);
  ok(sysAudit?.actor_label === 'system (roles.sync)', '8d. reconciliation audited as system');

  // 9. suspend / reactivate
  await login('demo', 'wrong').catch(() => {}); // no-op; just ensure no session needed
  ok((await api('POST', `/users/${D}/suspend`, {})).status === 204, '9. suspend -> 204');
  const { rows: [dStat] } = await pool.query('SELECT status FROM identities WHERE sub = $1', [D]);
  ok(dStat.status === 'disabled', '9a. status disabled');
  ok((await api('POST', `/users/${D}/reactivate`, {})).status === 204, '9b. reactivate -> 204');

  // 10. set-password + send-reset (mocked mailer)
  const n10 = mails.length;
  r = await api('POST', `/users/${D}/password`, { password: 'short' });
  ok(r.status === 422, '10. weak admin-set password -> 422');
  r = await api('POST', `/users/${D}/password`, { password: 'OrgTest1234!' });
  ok(r.status === 204, '10a. set password -> 204');
  const { rows: [dPw] } = await pool.query('SELECT password_changed_at FROM identities WHERE sub = $1', [D]);
  ok(new Date(dPw.password_changed_at) >= startedAt, '10b. password_changed_at bumped');
  r = await api('POST', `/users/${D}/password/send-reset`, {});
  if (dSnap.email) {
    ok(r.status === 204, '10c. send-reset -> 204');
    let got = false;
    for (let i = 0; i < 10 && !got; i++) { await sleep(300); got = mails.slice(n10).some((m) => /reset/i.test(m.subject)); }
    ok(got, '10d. reset email captured by mock');
  } else {
    ok(r.status === 400 && (await r.json()).error === 'no_email', '10c. no email on file -> 400 no_email');
    ok(true, '10d. (skipped — no email)');
  }

  // 11. create user
  r = await api('POST', '/users', {
    username: 'orgtest9', display_name: 'Org Test Nine', password: 'OrgNine1234!', org_role: 'standard_user',
  });
  ok(r.status === 201, '11. create user -> 201', `(${r.status})`);
  const nine = (await r.json()).sub;
  r = await api('POST', '/users', {
    username: 'orgtest9', display_name: 'Dup', password: 'OrgNine1234!', org_role: 'standard_user',
  });
  ok(r.status === 409, '11a. duplicate username -> 409');
  r = await api('POST', '/users', {
    username: 'orgtest10', display_name: 'Too High', password: 'OrgNine1234!', org_role: 'admin',
  });
  ok(r.status === 422, '11b. create with role at own level -> 422');
  await pool.query('DELETE FROM identities WHERE sub = $1', [nine]);

  // 12. MFA reset: plain when the step-up switch is off…
  const dSecret = generateSecret();
  await pool.query(`INSERT INTO totp_credentials (user_sub, label, secret_enc, confirmed_at) VALUES ($1, 'org-e2e', $2, now())`,
    [D, sealSecret(dSecret)]);
  await pool.query('UPDATE identities SET mfa_enabled = true WHERE sub = $1', [D]);
  ok((await api('POST', `/users/${D}/mfa/reset`, {})).status === 204, '12. mfa reset (switch off) -> 204');
  const { rows: [dMfa] } = await pool.query(
    `SELECT mfa_enabled, (SELECT count(*)::int FROM totp_credentials WHERE user_sub = $1) AS n FROM identities WHERE sub = $1`, [D]);
  ok(dMfa.mfa_enabled === false && dMfa.n === 0, '12a. all factors gone, toggle off');

  // …and behind the one-time ceremony when it's on
  await pool.query(`INSERT INTO totp_credentials (user_sub, label, secret_enc, confirmed_at) VALUES ($1, 'org-e2e2', $2, now())`,
    [D, sealSecret(generateSecret())]);
  const tSecret = generateSecret();
  await pool.query(`INSERT INTO totp_credentials (user_sub, label, secret_enc, confirmed_at) VALUES ($1, 'org-actor', $2, now())`,
    [T, sealSecret(tSecret)]);
  await setDb('stepup_portal_required', 'true');
  await sleep(5500);
  // sudo window fresh, with a method the strong-mandatory gate accepts (the actor
  // owns a TOTP here) — stepupSatisfies requires a non-null method, not just a stamp.
  await pool.query(`UPDATE sessions SET stepup_at = now(), stepup_method = 'totp' WHERE sid = $1`, [a.sid]);
  const sidH = { 'x-stepup-sid': a.sid };
  r = await api('POST', `/users/${D}/mfa/reset`, {}, sidH);
  ok(r.status === 403 && (await r.json()).error === 'action_challenge_required',
     '12b. …but the sudo window does NOT satisfy the one-time ceremony');
  r = await api('POST', '/action-token', {
    action: 'mfa.reset', target_sub: D, method: 'totp', code: generateSync({ secret: tSecret, strategy: 'totp' }),
  }, sidH);
  const at = await r.json();
  ok(r.status === 200 && !!at.action_token, '12c. fresh TOTP ceremony mints the action token');
  r = await api('POST', `/users/${D}/mfa/reset`, { action_token: at.action_token }, sidH);
  ok(r.status === 204, '12d. reset with the token -> 204');
  r = await api('POST', `/users/${D}/mfa/reset`, { action_token: at.action_token }, sidH);
  ok(r.status === 403, '12e. token is single-use');
  await setDb('stepup_portal_required', null);
  await sleep(5500);

  // 13. audit trail spot-checks
  const { rows: auditRows } = await pool.query(
    `SELECT DISTINCT action FROM org_audit_log WHERE actor_sub = $1 AND created_at >= $2`, [T, startedAt]);
  const acts = new Set(auditRows.map((x) => x.action));
  ok(['user.role_change', 'user.app_role_change', 'user.password_set', 'user.mfa_reset', 'user.suspend', 'role.create', 'user.create']
      .every((x) => acts.has(x)),
     '13. every mutation audited', `(${auditRows.length} kinds)`);

  // 14. self-service change-password keeps only the caller's session
  const b = await login();
  const c = await login();
  // password change is a fallback-tier step-up (independent of the portal switch);
  // the caller (owns a TOTP) needs a fresh window with an accepted method on b.sid.
  await pool.query(`UPDATE sessions SET stepup_at = now(), stepup_method = 'totp' WHERE sid = $1`, [b.sid]);
  r = await fetch(SSO + '/account/password', {
    method: 'POST',
    headers: { authorization: 'Bearer ' + b.token, 'content-type': 'application/json', 'x-stepup-sid': b.sid },
    body: JSON.stringify({ current_password: PASS, new_password: PASS }),
  });
  ok(r.status === 204, '14. change password -> 204', `(${r.status})`);
  const { rows: after } = await pool.query('SELECT sid FROM sessions WHERE user_sub = $1', [T]);
  ok(after.length === 1 && after[0].sid === b.sid, '14a. only the caller\'s session survives', `(${after.length})`);

  // 15. system-role level is now editable (guard: actor strictly above current
  //     AND target). 'user' is system, level 10; actor is admin (level 1).
  let rr = await api('PATCH', '/roles/standard_user', { level: 9 });
  ok(rr.status === 204, '15. system role level editable -> 204', `(${rr.status})`);
  ok(Number((await pool.query(`SELECT level FROM org_roles WHERE slug = 'standard_user'`)).rows[0].level) === 9, '15a. level applied');
  rr = await api('PATCH', '/roles/standard_user', { level: 1 });
  ok(rr.status === 422, '15b. level at/above own -> 422');
  rr = await api('PATCH', '/roles/admin', { level: 5 });
  ok(rr.status === 403, '15c. editing a role at own level -> 403 (system or not)');
  await api('PATCH', '/roles/standard_user', { level: userRoleLevel }); // restore

  // 16. mfa.disable exemption: admin does NOT hold profile.security.mfa.disable
  //     (denied by default) but MAY set it for a lower user / role.
  rr = await api('GET', '/users/' + D);
  const md = (await rr.json()).permissions.find((x: { key: string }) => x.key === 'profile.security.mfa.disable');
  ok(md.editable === true, '16. mfa.disable shown editable despite actor not holding it');
  rr = await api('PUT', `/users/${D}/permissions/profile.security.mfa.disable`, { effect: 'grant' });
  ok(rr.status === 204, '16a. set mfa.disable on a lower user -> 204', `(${rr.status})`);
  rr = await api('PUT', `/roles/orgtest_role/permissions/profile.security.mfa.disable`, { effect: 'grant' });
  ok(rr.status === 204, '16b. set mfa.disable on a lower role -> 204');
  rr = await api('PUT', `/users/${D}/permissions/org.logs.clear`, { effect: 'grant' });
  ok(rr.status === 403, '16c. a DIFFERENT unheld key is still blocked');
  await api('PUT', `/users/${D}/permissions/profile.security.mfa.disable`, { effect: 'inherit' });

  // 17. new role seeds the default role's permissions
  rr = await api('POST', '/roles', { slug: 'orgtest_seed', label: 'Seeded', level: 6 });
  ok(rr.status === 201, '17. create role -> 201');
  const seeded = (await (await api('GET', '/roles/orgtest_seed')).json()).permissions;
  const defRow = (await pool.query(
    `SELECT perm_key, effect FROM role_permissions WHERE role_slug = 'standard_user' AND perm_key = 'profile.displayname.change'`)).rows[0];
  const seededRow = seeded.find((x: { key: string }) => x.key === 'profile.displayname.change');
  ok(seededRow.effect === defRow.effect && defRow.effect === 'grant', '17a. seeded from default (profile.displayname.change grant)');
  await pool.query(`DELETE FROM org_roles WHERE slug = 'orgtest_seed'`);

  // 18. batch USER access: one atomic request (org role + perms + app roles)
  rr = await api('POST', `/users/${D}/access`, {
    org_role: 'orgtest_role',
    permissions: { 'profile.email.change': 'deny', 'profile.displayname.change': 'grant' },
    app_roles: { videosite: null },
  });
  ok(rr.status === 204, '18. batch user access -> 204', `(${rr.status})`);
  const { rows: [chk] } = await pool.query(
    `SELECT (SELECT org_role_slug FROM user_org_roles WHERE user_sub = $1) AS role,
            (SELECT effect FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.email.change') AS email,
            (SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = 'videosite') AS app`, [D]);
  ok(chk.role === 'orgtest_role' && chk.email === 'deny' && chk.app === null, '18a. all three applied together');

  // 18b. atomicity: a batch with ONE forbidden item applies NOTHING
  await api('PUT', `/users/${D}/permissions/profile.username.change`, { effect: 'inherit' });
  rr = await api('POST', `/users/${D}/access`, {
    permissions: { 'profile.username.change': 'grant', 'org.logs.clear': 'grant' },
  });
  ok(rr.status === 403, '18b. batch with an unheld key -> 403');
  const { rows: [atomic] } = await pool.query(
    `SELECT effect FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.username.change'`, [D]);
  ok(!atomic, '18c. the OK item in the failed batch was NOT applied (atomic)');

  // 19. batch ROLE access
  rr = await api('POST', '/roles/orgtest_role/access', {
    permissions: { 'profile.email.change': 'deny' },
    app_defaults: { videosite: 2 },
  });
  ok(rr.status === 204, '19. batch role access -> 204', `(${rr.status})`);
  const { rows: [rchk] } = await pool.query(
    `SELECT (SELECT effect FROM role_permissions WHERE role_slug = 'orgtest_role' AND perm_key = 'profile.email.change') AS perm,
            (SELECT app_role_id FROM org_role_app_defaults WHERE role_slug = 'orgtest_role' AND client_id = 'videosite') AS app`);
  ok(rchk.perm === 'deny' && rchk.app === 2, '19a. role perms + app defaults applied');

  // 20. inherited-app-role ceiling on an org-role change (regression for the 3a fix).
  //   ASSIGN an existing role -> resulting inherited app level not-higher-than the
  //     actor (equal OK). DEFINE a role's app-default -> strictly below the actor.
  //   Seed a role whose videosite default is 'admin' (app level 1) DIRECTLY, standing
  //   in for a superadmin-defined/legacy role a lower admin must not be able to hand
  //   out (and, per 20f, can no longer even define at their own level).
  await pool.query(`INSERT INTO org_roles (slug, label, level) VALUES ('orgtest_esc', 'Esc', 5)
                    ON CONFLICT (slug) DO UPDATE SET level = 5`);
  await pool.query(`INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id)
                    VALUES ('orgtest_esc', 'videosite', 1)
                    ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = 1`);
  await pool.query(`DELETE FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = 'videosite'`, [D]);
  const dRole20 = await roleSnap(D);
  // actor footing = user (videosite app level 10): assigning orgtest_esc would grant admin (level 1) > actor
  await pool.query(`INSERT INTO user_app_role_overrides (user_sub, client_id, app_role_id) VALUES ($1, 'videosite', 2)
                    ON CONFLICT (user_sub, client_id) DO UPDATE SET app_role_id = 2`, [T]);
  r = await api('POST', `/users/${D}/org-role`, { role_slug: 'orgtest_esc' });
  ok(r.status === 403 && (await r.json()).error === 'app_role_above_level',
     '20. assign a role whose app-default outranks the actor -> 403 (inherited-app ceiling)', `(${r.status})`);
  ok((await roleSnap(D)) === dRole20, '20a. …and the org role was NOT changed');
  r = await api('POST', `/users/${D}/access`, { org_role: 'orgtest_esc' });
  ok(r.status === 403 && (await r.json()).error === 'app_role_above_level',
     '20b. batch bare org-role with the same escalation -> 403');
  ok((await roleSnap(D)) === dRole20, '20c. …batch applied nothing (atomic)');
  // raise actor footing to admin (level 1): the inherited admin now EQUALS the actor -> allowed
  await pool.query(`UPDATE user_app_role_overrides SET app_role_id = 1 WHERE user_sub = $1 AND client_id = 'videosite'`, [T]);
  r = await api('POST', `/users/${D}/org-role`, { role_slug: 'orgtest_esc' });
  ok(r.status === 204, '20d. equal inherited app level is allowed on assignment -> 204', `(${r.status})`);
  const { rows: [d20] } = await pool.query(
    `SELECT (SELECT org_role_slug FROM user_org_roles WHERE user_sub = $1) AS role,
            (SELECT app_role_id FROM user_app_role_overrides WHERE user_sub = $1 AND client_id = 'videosite') AS ov`, [D]);
  ok(d20.role === 'orgtest_esc' && d20.ov == null, '20e. assigned; D inherits the admin app role by the org default');
  // definition surface (actor footing still admin, level 1): equal is now rejected
  r = await api('PUT', `/roles/orgtest_esc/app-defaults/videosite`, { value: 1 });
  ok(r.status === 403 && (await r.json()).error === 'app_role_above_level',
     '20f. defining an app-default at the actor\'s OWN level -> 403 (strictly lower)');
  ok((await api('PUT', `/roles/orgtest_esc/app-defaults/videosite`, { value: 2 })).status === 204,
     '20g. defining an app-default strictly below -> 204');
  r = await api('POST', `/roles/orgtest_esc/access`, { app_defaults: { videosite: 1 } });
  ok(r.status === 403 && (await r.json()).error === 'app_role_above_level',
     '20h. batch role app-default at the actor\'s own level -> 403');
} finally {
  // restore identities verbatim
  for (const [s, snap] of [[T, tSnap], [D, dSnap]] as const) {
    await pool.query(
      `UPDATE identities SET username=$2, display_name=$3, email=$4, email_verified=$5, status=$6,
              mfa_enabled=$7, password_hash=$8, password_changed_at=$9 WHERE sub=$1`,
      [s, snap.username, snap.display_name, snap.email, snap.email_verified, snap.status,
       snap.mfa_enabled, snap.password_hash, snap.password_changed_at]);
  }
  await pool.query(`DELETE FROM totp_credentials WHERE user_sub = ANY($1) AND label LIKE 'org-%'`, [[T, D]]);
  if (tRole) await setRole(T, tRole);
  if (dRole) await setRole(D, dRole); else await pool.query('DELETE FROM user_org_roles WHERE user_sub = $1', [D]);
  await pool.query('DELETE FROM user_app_role_overrides WHERE user_sub = ANY($1)', [[T, D]]);
  await pool.query(`DELETE FROM org_role_app_defaults WHERE role_slug = 'orgtest_role'`);
  await pool.query(`DELETE FROM user_org_roles WHERE org_role_slug IN ('orgtest_role', 'orgtest_esc')`);
  await pool.query('UPDATE org_roles SET level = $2 WHERE slug = $1', ['standard_user', userRoleLevel]);
  await pool.query(`DELETE FROM org_role_app_defaults WHERE role_slug IN ('orgtest_role', 'orgtest_esc')`);
  await pool.query(`DELETE FROM org_roles WHERE slug IN ('orgtest_role', 'orgtest_high', 'orgtest_seed', 'orgtest_esc')`);
  await pool.query(`DELETE FROM identities WHERE username IN ('orgtest9', 'orgtest10')`);
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'profile.email.change'`, [D]);
  await pool.query(
    `DELETE FROM org_audit_log WHERE created_at >= $1 AND (actor_sub = $2 OR actor_label = 'system (roles.sync)')`,
    [startedAt, T]);
  await pool.query('DELETE FROM sessions WHERE user_sub = ANY($1)', [[T, D]]);
  // restore the real videosite catalog + demo's videosite role
  await enqueueEvents(CLIENT, [{ type: 'roles.sync_request', payload: {} }]).catch(() => {});
  await drainAll().catch(() => {});
  if (dVideoRole) {
    try { mariadb(`UPDATE users SET role_id = ${Number(dVideoRole)} WHERE user_id = UNHEX(REPLACE('${D}','-',''))`); } catch { /* logged */ }
  }
  for (const k of SETTING_KEYS) await setDb(k, null);
  for (const row of origSettings) await pool.query('INSERT INTO settings (key, value) VALUES ($1, $2)', [row.key, row.value]);
  if (advDefSnap) {
    await pool.query(
      `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id)
       VALUES ('admin', 'videosite', $1)
       ON CONFLICT (role_slug, client_id) DO UPDATE SET app_role_id = $1`,
      [advDefSnap.app_role_id]);
  }
  mock.close();
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
redis.disconnect();
process.exit(fail ? 1 : 0);
