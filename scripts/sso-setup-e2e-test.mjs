// E2E for the first-run /setup installer (slices 1-4). Self-contained: it creates
// a throwaway `dreamsso_setuptest` database and spawns an UNCONFIGURED SSO on a
// test port (empty infra env → setup mode), writing to temp .env/token files, so
// the real database and .env are never touched.
//
// Covers: setup-mode gate (neutral 503 for public routes, token-gated /setup),
// GET /setup/env 3-state + generated key, POST /setup/config validation +
// connectivity failure + happy path (schema apply + in-process configure), POST
// /setup/finish validation + the atomic finish transaction (superadmin, RBAC,
// account client via jwks_uri, settings incl. sealed cf_api_token, session), and
// the gate flip to complete.
//
// Run: npx tsx scripts/sso-setup-e2e-test.mjs
import 'dotenv/config';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import pg from 'pg';

const PORT = 3990;
const BASE = `http://127.0.0.1:${PORT}`;
const ENV_FILE = '/tmp/dxw-e2e.env';
const TOKEN_FILE = '/tmp/dxw-e2e-token';
const base = process.env.DATABASE_URL;
if (!base) { console.error('no DATABASE_URL in .env'); process.exit(1); }
const testUrl = (() => { const u = new URL(base); u.pathname = '/dreamsso_setuptest'; return u.toString(); })();

let fail = 0, pass = 0;
function check(name, cond) { if (cond) { pass++; console.log(`  ✓ ${name}`); } else { fail++; console.error(`  ✗ ${name}`); } }
const j = (o) => ({ method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(o) });
// Every request is time-bounded so a stalled handler fails the check instead of
// hanging the whole run.
function F(path, opts = {}, ms = 9000) { return fetch(BASE + path, { ...opts, signal: AbortSignal.timeout(ms) }); }
async function status(path, opts) { try { return (await F(path, opts)).status; } catch { return 0; } }
async function getJson(path) { return (await F(path)).json(); }
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const admin = new pg.Pool({ connectionString: base });
let child;
async function dropTestDb() {
  // Terminate any lingering backends (the spawned server's pool) before dropping.
  try {
    await admin.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname='dreamsso_setuptest' AND pid <> pg_backend_pid()");
  } catch { /* db may not exist */ }
  await admin.query('DROP DATABASE IF EXISTS dreamsso_setuptest');
}
async function cleanup() {
  if (child) { try { child.kill('SIGKILL'); } catch {} }
  await sleep(600);
  try { await dropTestDb(); } catch (e) { console.error('drop:', e.message); }
  await admin.end().catch(() => {});
  for (const f of [ENV_FILE, TOKEN_FILE]) { try { fs.unlinkSync(f); } catch {} }
}

try {
  // --- fresh DB ---
  await dropTestDb().catch(() => {});
  await admin.query('CREATE DATABASE dreamsso_setuptest');
  for (const f of [ENV_FILE, TOKEN_FILE]) { try { fs.unlinkSync(f); } catch {} }

  // --- spawn an UNCONFIGURED server (empty infra env → setup mode) ---
  child = spawn('npx', ['tsx', 'src/server.ts'], {
    env: {
      ...process.env,
      DATABASE_URL: '', KEY_ENCRYPTION_KEY: '', ISSUER: '', WEBAUTHN_RP_ID: '', WEBAUTHN_ORIGINS: '', REDIS_URL: '',
      PORT: String(PORT), SETUP_ENV_FILE: ENV_FILE, SETUP_TOKEN_FILE: TOKEN_FILE,
    },
    stdio: ['ignore', 'ignore', fs.openSync('/tmp/dxw-e2e-server.log', 'w')],
  });
  // wait for listen
  let up = false;
  for (let i = 0; i < 60; i++) { try { await F('/setup', {}, 2000); up = true; break; } catch { await sleep(500); } }
  check('server booted in setup mode', up);
  const token = fs.readFileSync(TOKEN_FILE, 'utf8').trim();
  check('setup token written to file', !!token);
  const T = `?token=${token}`;

  // --- setup-mode gate ---
  check('/authorize -> 503 (setup mode)', (await status('/authorize?client_id=x')) === 503);
  check('/setup no token -> 503 (hidden)', (await status('/setup')) === 503);
  check('/setup wrong token -> 503', (await status('/setup?token=nope')) === 503);
  check('/setup valid token -> 200', (await status('/setup' + T)) === 200);
  check('/auth-bg.svg -> 200 (whitelisted)', (await status('/auth-bg.svg')) === 200);

  const env0 = await getJson('/setup/env' + T);
  check('env: not configured', env0.configured === false);
  check('env: generated key (64 hex)', /^[0-9a-f]{64}$/.test(env0.generatedKey || ''));
  check('env: all fields absent', !env0.fields.database.present && !env0.fields.issuer.present);

  // --- config: validation + connectivity failure + happy path ---
  check('config bad input -> 422', (await status('/setup/config' + T, j({ databaseUrl: 'x', redisUrl: 'y', issuer: 'z' }))) === 422);
  check('config unreachable DB -> 422',
    (await status('/setup/config' + T, j({ databaseUrl: 'postgresql://u:p@127.0.0.1:5599/no', redisUrl: 'redis://127.0.0.1:6379', issuer: 'https://sso.test' }))) === 422);
  check('config valid -> 204',
    (await status('/setup/config' + T, j({ databaseUrl: testUrl, redisUrl: 'redis://127.0.0.1:6379', issuer: 'https://sso.e2e.test/' }))) === 204);
  const st1 = await getJson('/setup/state' + T);
  check('state: configured after config', st1.configured === true && st1.complete === false);

  // --- finish: validation + happy path ---
  check('finish bad input -> 422', (await status('/setup/finish' + T, j({ username: 'a', email: 'x', password: 'weak', siteName: '', accountPortalUrl: 'http://x' }))) === 422);
  check('finish valid -> 204', (await status('/setup/finish' + T, j({
    username: 'e2e_admin', displayName: 'E2E Admin', email: 'e2e@acme.test', password: 'Sup3r!Secret',
    siteName: 'E2E SSO', accountPortalUrl: 'https://account.e2e.test/',
    emailEnabled: true, mailFrom: 'no-reply@e2e.test', cfAccountId: 'acct123', cfApiToken: 'tok-secret-xyz',
  }))) === 204);

  // --- gate flipped to complete ---
  check('/setup -> 404 after finish', (await status('/setup')) === 404);
  check('/setup/finish -> 404 after finish', (await status('/setup/finish', j({}))) === 404);
  check('/authorize -> not 503 (serving normally)', (await status('/authorize?client_id=account')) !== 503);
  check('/healthz -> 200', (await status('/healthz')) === 200);

  // --- committed DB state ---
  const db = new pg.Pool({ connectionString: testUrl });
  try {
    const { rows: id } = await db.query("SELECT i.username, r.org_role_slug FROM identities i JOIN user_org_roles r ON r.user_sub=i.sub");
    check('superadmin created', id.length === 1 && id[0].username === 'e2e_admin' && id[0].org_role_slug === 'superadmin');
    const { rows: roles } = await db.query('SELECT count(*)::int c FROM org_roles');
    const { rows: perms } = await db.query('SELECT count(*)::int c FROM role_permissions');
    check('RBAC seeded (3 roles, perms)', roles[0].c === 3 && perms[0].c > 0);
    const { rows: cl } = await db.query("SELECT jwks_uri,(jwks IS NULL) jn,is_system,token_endpoint_auth_method m FROM oauth_clients WHERE client_id='account'");
    check('account client via jwks_uri (jwks null, system, private_key_jwt)',
      cl[0] && cl[0].jn === true && cl[0].is_system === true && cl[0].m === 'private_key_jwt' && /jwks\.json$/.test(cl[0].jwks_uri));
    const { rows: se } = await db.query("SELECT key,value FROM settings WHERE key IN ('site_name','account_portal_url','cf_api_token','setup_complete')");
    const settings = Object.fromEntries(se.map((r) => [r.key, r.value]));
    check('settings persisted', settings.site_name === 'E2E SSO' && settings.account_portal_url === 'https://account.e2e.test' && !!settings.setup_complete);
    check('cf_api_token sealed', (settings.cf_api_token || '').startsWith('enc:v1:'));
    const { rows: sess } = await db.query("SELECT amr::text a, acr, stepup_method m FROM sessions");
    check('superadmin session created', sess.length === 1 && sess[0].a === '{pwd}' && sess[0].acr === 'urn:dreamsso:1fa' && sess[0].m === 'password');
  } finally { await db.end().catch(() => {}); }
} catch (e) {
  fail++; console.error('EXCEPTION:', e);
} finally {
  await cleanup();
}

console.log(`\nsso-setup-e2e: ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
