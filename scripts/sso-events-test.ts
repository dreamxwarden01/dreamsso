// E2E for the bidirectional event channel (/backchannel/events):
//   RP->SSO roles.sync (hand-signed with the videosite client key): full-state
//     upsert + delete, singular default_role validation, envelope-iat ordering
//     guard, per-event dedupe, unknown-type ack, auth failures, batch cap
//   admin role-catalog GET (level-asc sort, default, synced_at)
//   the REAL loop last: admin request-role-sync -> SSO outbound pump (2s
//     debounce) -> videosite /backchannel/events -> videosite outbound pump ->
//     SSO roles.sync — which also RESTORES videosite's true catalog.
// Hand-signed envelopes use iat = now-20 so the real videosite reply (iat=now)
// always beats the ordering guard. Run: npx tsx scripts/sso-events-test.ts
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SignJWT, importJWK, type JWK } from 'jose';
import { pool } from '../src/db.js';
import { answerKmsi } from './lib/kmsi.mjs';

const SSO = 'https://sso-dev.dreamxwarden.ca';
const CLIENT = 'videosite';
const KEY = ((r) => (r.keys?.[0] ?? r))(JSON.parse(fs.readFileSync(new URL('../.videosite-client-key.json', import.meta.url), 'utf8'))) as JWK & { kid?: string };
const USER = 'tester';
const PASS = 'Test1234!';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const gsc = (r: Response, n: string) => {
  for (const c of r.headers.getSetCookie?.() ?? []) {
    const nv = c.split(';')[0];
    const i = nv.indexOf('=');
    if (i > 0 && nv.slice(0, i) === n) return nv.slice(i + 1);
  }
  return null;
};

interface Ev { id?: string; type?: string; payload?: unknown }
// Monotonic iat for hand-signed envelopes: the ordering guard skips any
// envelope not NEWER than the last applied one, and consecutive test calls
// land in the same second. Kept below now so the real videosite reply
// (iat = now) always wins at the end.
let iatSeq = Math.floor(Date.now() / 1000) - 30;
async function envelope(events: Ev[], o: { iat?: number; key?: JWK; iss?: string } = {}): Promise<string> {
  const k = await importJWK(o.key ?? KEY, 'EdDSA');
  // outbid the STORED guard too — a real videosite sync (boot / another
  // suite's cleanup restore) may have landed with iat ~ now
  if (o.iat === undefined) {
    const { rows: [cur] } = await pool.query(
      `SELECT last_sync_iat FROM app_role_catalogs WHERE client_id = 'videosite'`);
    iatSeq = Math.max(iatSeq + 1, Number(cur?.last_sync_iat ?? 0) + 1);
  }
  const iat = o.iat ?? iatSeq;
  const iss = o.iss ?? CLIENT;
  return new SignJWT({ events })
    .setProtectedHeader({ alg: 'EdDSA', kid: (o.key ?? KEY).kid, typ: 'events+jwt' })
    .setIssuer(iss).setSubject(iss).setAudience(SSO)
    .setIssuedAt(iat).setExpirationTime(iat + 120).setJti(crypto.randomUUID())
    .sign(k);
}
const post = async (token: string) =>
  fetch(SSO + '/backchannel/events', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ event_token: token }),
  });
const ev = (payload: unknown): Ev => ({ id: crypto.randomUUID(), type: 'roles.sync', payload });
const dbRoles = async () =>
  (await pool.query('SELECT role_id, name, level, is_system FROM app_roles WHERE client_id = $1 ORDER BY level, role_id', [CLIENT])).rows;
const dbCatalog = async () =>
  (await pool.query('SELECT default_role_id, synced_at, last_sync_iat FROM app_role_catalogs WHERE client_id = $1', [CLIENT])).rows[0];

const BASE = [
  { role_id: 0, name: 'superadmin', level: 0, is_system: true },
  { role_id: 1, name: 'admin', level: 1, is_system: true },
  { role_id: 2, name: 'user', level: 10, is_system: true },
];

const { rows: [{ sub }] } = await pool.query('SELECT sub FROM identities WHERE username = $1', [USER]);
await pool.query(
  `INSERT INTO user_permission_overrides (user_sub, perm_key, effect) VALUES ($1, 'org.siteSettings.sso', 'grant')
     ON CONFLICT (user_sub, perm_key) DO UPDATE SET effect = 'grant'`, [sub]);
// Park the admin step-up door: /admin/api MUTATIONS check the sudo window when
// it's on, and this suite's password-only login never pre-clears it.
const { rows: suOrig } = await pool.query<{ value: string }>(
  `SELECT value FROM settings WHERE key = 'stepup_admin_required'`);
await pool.query(`INSERT INTO settings (key, value) VALUES ('stepup_admin_required', 'false')
  ON CONFLICT (key) DO UPDATE SET value = 'false'`);
await new Promise((r) => setTimeout(r, 5500)); // outwait the settings cache

try {
  // 1. full-state sync: add a role
  let r = await post(await envelope([ev({ default_role: 2, roles: [...BASE, { role_id: 7, name: 'moderator', level: 5, is_system: false }] })]));
  ok(r.status === 204, '1. roles.sync accepted', `(${r.status})`);
  let roles = await dbRoles();
  ok(roles.length === 4 && roles.some((x) => x.role_id === 7 && x.level === 5 && x.is_system === false),
     '1a. new role upserted', `(${roles.length} roles)`);
  ok(JSON.stringify(roles.map((x) => x.role_id)) === '[0,1,7,2]',
     '1b. level-asc, ties by role_id (7@5 before 2@10)', `(${roles.map((x) => x.role_id)})`);

  // 2. full-state sync: role gone from the list -> row deleted
  r = await post(await envelope([ev({ default_role: 2, roles: BASE })]));
  roles = await dbRoles();
  ok(r.status === 204 && roles.length === 3 && !roles.some((x) => x.role_id === 7),
     '2. absent role deleted (full-state semantics)');

  // 3. default_role must exist in the sent list -> otherwise NULL (deny-safe)
  r = await post(await envelope([ev({ default_role: 99, roles: BASE })]));
  ok(r.status === 204 && (await dbCatalog()).default_role_id === null, '3. invalid default_role -> NULL');
  await post(await envelope([ev({ default_role: 2, roles: BASE })]));
  ok((await dbCatalog()).default_role_id === 2, '3a. valid default_role restored');

  // 4. ordering guard: an OLDER envelope can't regress a newer sync
  const cur = await dbCatalog();
  r = await post(await envelope([ev({ default_role: 99, roles: [BASE[0]] })], { iat: Number(cur.last_sync_iat) - 30 }));
  ok(r.status === 204 && (await dbRoles()).length === 3 && (await dbCatalog()).default_role_id === 2,
     '4. stale envelope acked but IGNORED');

  // 5. per-event dedupe: same event id re-delivered -> not reprocessed
  const dup = ev({ default_role: 2, roles: [...BASE, { role_id: 8, name: 'temp', level: 6, is_system: false }] });
  await post(await envelope([dup]));
  ok((await dbRoles()).length === 4, '5. first delivery applied');
  r = await post(await envelope([{ ...dup, payload: { default_role: 2, roles: BASE } }]));
  ok(r.status === 204 && (await dbRoles()).length === 4, '5a. same id redelivered -> deduped (state unchanged)');
  await post(await envelope([ev({ default_role: 2, roles: BASE })])); // clean role 8

  // 6. unknown event type -> acked (forward compat)
  r = await post(await envelope([{ id: crypto.randomUUID(), type: 'future.mystery', payload: {} }]));
  ok(r.status === 204, '6. unknown type acked');

  // 7. auth failures
  const { privateKey } = crypto.generateKeyPairSync('ed25519');
  const wrongKey = { ...(privateKey.export({ format: 'jwk' }) as JWK), kid: KEY.kid };
  r = await post(await envelope([ev({ default_role: 2, roles: BASE })], { key: wrongKey }));
  ok(r.status === 401, '7. wrong signing key -> 401');
  r = await post(await envelope([ev({ default_role: 2, roles: BASE })], { iss: 'nosuch-client' }));
  ok(r.status === 401, '7a. unknown client -> 401');
  r = await post('garbage.token.here');
  ok(r.status === 400 || r.status === 401, '7b. garbage token rejected', `(${r.status})`);

  // 8. batch cap
  const many = Array.from({ length: 101 }, () => ({ id: crypto.randomUUID(), type: 'x', payload: {} }));
  r = await post(await envelope(many));
  ok(r.status === 400, '8. >100 events -> 400');

  // 9. malformed role rows -> 400, nothing applied
  r = await post(await envelope([ev({ default_role: 2, roles: [{ role_id: 'NaN', name: 5 }] })]));
  ok(r.status === 400 && (await dbRoles()).length === 3, '9. malformed payload -> 400, state intact');

  // --- admin surface + the REAL round trip (also restores the true catalog) ---
  let ar = await fetch(SSO + '/admin/start-login', { redirect: 'manual' });
  const txn = new URL(ar.headers.get('location')!, SSO).searchParams.get('txn')!;
  ar = await fetch(SSO + '/login?txn=' + encodeURIComponent(txn));
  const csrfForm = ((await ar.text()).match(/name="csrf" value="([^"]+)"/) || [])[1];
  ar = await fetch(SSO + '/login', {
    method: 'POST', redirect: 'manual',
    headers: { 'content-type': 'application/x-www-form-urlencoded', origin: 'null', 'sec-fetch-site': 'same-origin' },
    body: new URLSearchParams({ txn, csrf: csrfForm, username: USER, password: PASS }),
  });
  const cookie = 'sso_session=' + gsc(ar, 'sso_session');
  await answerKmsi(SSO, ar, txn, csrfForm, { cookie });
  const me = await (await fetch(SSO + '/admin/api/me', { headers: { cookie } })).json();

  // 10. role-catalog endpoint (level-asc order + default + synced_at)
  let cat = await (await fetch(SSO + `/admin/api/clients/${CLIENT}/role-catalog`, { headers: { cookie } })).json();
  ok(cat.default_role_id === 2 && Array.isArray(cat.roles) && cat.roles.length === 3 && !!cat.synced_at,
     '10. role-catalog: roles + default + synced_at', `(${cat.roles?.length})`);

  // 11. manual refresh: request-role-sync -> the REAL videosite replies
  const before = new Date((await dbCatalog()).synced_at).getTime();
  r = await fetch(SSO + `/admin/api/clients/${CLIENT}/request-role-sync`, {
    method: 'POST', headers: { cookie, 'x-csrf-token': me.csrf },
  });
  ok(r.status === 204, '11. request-role-sync -> 204', `(${r.status})`);
  let refreshed = false;
  for (let i = 0; i < 30 && !refreshed; i++) {
    await sleep(1000);
    refreshed = new Date((await dbCatalog()).synced_at).getTime() > before;
  }
  ok(refreshed, '11a. full loop: SSO pump -> videosite -> roles.sync back (catalog refreshed)');
  cat = await (await fetch(SSO + `/admin/api/clients/${CLIENT}/role-catalog`, { headers: { cookie } })).json();
  ok(cat.roles.length === 3 && cat.default_role_id === 2 && cat.roles[0].role_id === 0,
     '11b. restored to videosite\'s true catalog, sorted', `(${JSON.stringify(cat.roles.map((x: { role_id: number }) => x.role_id))})`);

  // 12. outbound archive: the sync_request delivery is recorded
  const { rows: arch } = await pool.query(
    `SELECT status FROM event_outbox WHERE kind = 'roles.sync_request' AND target_client_id = $1 ORDER BY created_at DESC LIMIT 1`,
    [CLIENT]);
  ok(arch[0]?.status === 'delivered', '12. outbound archive row: delivered', `(${arch[0]?.status})`);
} finally {
  await pool.query(`DELETE FROM user_permission_overrides WHERE user_sub = $1 AND perm_key = 'org.siteSettings.sso'`, [sub]);
  if (suOrig[0]) {
    await pool.query(`UPDATE settings SET value = $1 WHERE key = 'stepup_admin_required'`, [suOrig[0].value]);
  } else {
    await pool.query(`DELETE FROM settings WHERE key = 'stepup_admin_required'`);
  }
  await pool.query('DELETE FROM sessions WHERE user_sub = $1', [sub]);
  // app_roles state: the final real round-trip restored videosite's catalog.
}

console.log(fail ? `\n${fail} FAILED ✗` : '\nALL CHECKS PASSED ✓');
await pool.end();
process.exit(fail ? 1 : 0);
