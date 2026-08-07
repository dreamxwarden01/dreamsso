// Migration-runner behaviour, against THROWAWAY databases (never the dev DB).
//
// The stakes are asymmetric and unforgiving, which is why this exists:
//   * Replaying history would be destructive — sso-org-management-2 does
//     DROP TABLE org_role_app_defaults + CREATE, so a blind rerun silently
//     discards every app-role default. Historical files must be STAMPED, never run.
//   * But over-stamping is just as bad: stamping a migration that a database has
//     NOT had applied means the column never appears and the app breaks on a
//     query. Only the pre-runner BASELINE may be stamped; anything newer must run.
// Both directions are asserted below.
//
// Run: npx tsx scripts/sso-migrations-test.ts
import fs from 'node:fs';
import path from 'node:path';
import pg from 'pg';
import { runMigrations } from '../src/db/migrations.js';

let fail = 0;
const ok = (c: boolean, label: string, extra = '') => {
  console.log(`${c ? '✓' : '✗ FAIL'}  ${label}${extra ? '  ' + extra : ''}`);
  if (!c) fail++;
};

const ADMIN = process.env.DATABASE_URL!;
const base = new URL(ADMIN);
const dbName = `mig_test_${Date.now().toString(36)}`;
const admin = new pg.Pool({ connectionString: ADMIN, max: 1 });

const scratchUrl = () => {
  const u = new URL(base.toString());
  u.pathname = '/' + dbName;
  return u.toString();
};

await admin.query(`CREATE DATABASE ${dbName}`);
console.log(`\nscratch database: ${dbName}\n`);

let scratch = new pg.Pool({ connectionString: scratchUrl(), max: 2 });
try {
  // --- 1. fresh install: schema.sql, then the runner ---
  console.log('--- fresh install (schema.sql + runner) ---');
  await scratch.query(fs.readFileSync(path.resolve(process.cwd(), 'db/schema.sql'), 'utf8'));
  let r = await runMigrations({ strict: true, pool: scratch });
  ok(r.baselined.length > 0, 'pre-runner migrations were baselined, not executed', `${r.baselined.length}`);
  ok(r.applied.includes('sso-session-city-region.sql'),
    'a post-baseline migration DOES run on a fresh install', r.applied.join(',') || '(none)');

  const cols = async () => (await scratch.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns WHERE table_name='sessions'`
  )).rows.map((x) => x.column_name);
  ok((await cols()).includes('city'), 'sessions.city exists after the run');

  // --- 2. idempotence: a second run does nothing ---
  console.log('\n--- rerun ---');
  r = await runMigrations({ strict: true, pool: scratch });
  ok(r.applied.length === 0 && r.baselined.length === 0, 'second run is a no-op', JSON.stringify(r));

  // --- 3. the destructive one is never replayed ---
  console.log('\n--- history is never replayed (the destructive case) ---');
  // A real sentinel row, so this proves DATA survives rather than that an empty
  // table stayed empty. Both FKs must exist first.
  await scratch.query(
    `INSERT INTO org_roles (slug, label, level, is_system)
     VALUES ('mig_sentinel_role', 'Sentinel', 500, false) ON CONFLICT DO NOTHING`);
  await scratch.query(
    `INSERT INTO oauth_clients (client_id, name, redirect_uris)
     VALUES ('mig_sentinel_client', 'Sentinel', '{}') ON CONFLICT DO NOTHING`);
  await scratch.query(
    `INSERT INTO org_role_app_defaults (role_slug, client_id, app_role_id)
     VALUES ('mig_sentinel_role', 'mig_sentinel_client', 42) ON CONFLICT DO NOTHING`);
  const sentinel = async () => (await scratch.query(
    `SELECT app_role_id FROM org_role_app_defaults
      WHERE role_slug='mig_sentinel_role' AND client_id='mig_sentinel_client'`)).rows[0]?.app_role_id;
  ok((await sentinel()) === 42, 'sentinel row planted', String(await sentinel()));
  await runMigrations({ strict: true, pool: scratch });
  ok((await sentinel()) === 42,
    'sentinel SURVIVES a rerun (the DROP TABLE migration was not replayed)', String(await sentinel()));

  // --- 4. an existing DB that predates the runner ---
  // Simulate prod: schema WITHOUT the new columns, no schema_migrations table.
  console.log('\n--- adopting an existing pre-runner database ---');
  await scratch.query('DROP TABLE schema_migrations');
  await scratch.query('ALTER TABLE sessions DROP COLUMN city, DROP COLUMN region');
  ok(!(await cols()).includes('city'), 'simulated a pre-migration database');
  r = await runMigrations({ strict: true, pool: scratch });
  ok(r.baselined.length > 0, 'history baselined on adoption', `${r.baselined.length}`);
  ok(r.applied.includes('sso-session-city-region.sql'),
    'the genuinely-missing migration RAN (not stamped over)', r.applied.join(',') || '(none)');
  ok((await cols()).includes('city'), 'sessions.city now exists on the adopted database');

  // --- 5. a failing migration must not be recorded ---
  console.log('\n--- a failing migration ---');
  const bad = path.resolve(process.cwd(), 'db/migrations/zzz-deliberately-broken.sql');
  fs.writeFileSync(bad, 'ALTER TABLE sessions ADD COLUMN city text;\n'); // dupe -> error
  try {
    let threw = false;
    try { await runMigrations({ strict: true, pool: scratch }); } catch { threw = true; }
    ok(threw, 'strict mode surfaces the failure');
    const rec = await scratch.query(
      `SELECT 1 FROM schema_migrations WHERE filename='zzz-deliberately-broken.sql'`);
    ok(rec.rowCount === 0, 'the failed migration is NOT recorded (so a fix can rerun it)');
    const lenient = await runMigrations({ strict: false, pool: scratch });
    ok(lenient.applied.length === 0, 'lenient mode returns without throwing');
  } finally {
    fs.unlinkSync(bad);
  }
} finally {
  await scratch.end().catch(() => {});
  await admin.query(`DROP DATABASE IF EXISTS ${dbName} WITH (FORCE)`);
  console.log(`\nscratch database dropped: ${dbName}`);
  await admin.end().catch(() => {});
}

console.log(fail ? `\n${fail} FAILED\n` : '\nall passed\n');
process.exit(fail ? 1 : 0);
