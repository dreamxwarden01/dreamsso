import fs from 'node:fs';
import path from 'node:path';
import type pg from 'pg';
import { pool as appPool } from '../db.js';

// Schema migrations for the SSO's Postgres.
//
// Files live in db/migrations/ and are applied in lexical filename order, each in
// its own transaction, recorded in `schema_migrations` so it runs exactly once.
// Only that directory is ever executed — migrate/ next door holds one-time data
// scripts (the user import, the user_id->sub rewrite) and videosite's MariaDB
// patches, none of which may ever run automatically.
//
// TO ADD A MIGRATION: drop a file in db/migrations/ named NNN-what-it-does.sql
// (numeric prefix so ordering is explicit) and touch nothing else. Keep it
// IDEMPOTENT — ADD COLUMN IF NOT EXISTS, CREATE TABLE IF NOT EXISTS, guarded
// constraint adds — because a fresh install applies db/schema.sql (which already
// contains everything) and then runs the migration anyway.
//
// Also update db/schema.sql. Unlike videosite, schema.sql here is NOT a frozen
// baseline: it stays the readable current-state definition applied to empty
// databases. Idempotent migrations are what make the two paths converge.
const DIR = process.env.MIGRATIONS_DIR || path.resolve(process.cwd(), 'db/migrations');

// Migrations that predate this runner. They were applied by hand to every
// existing database, and db/schema.sql already contains their effects for fresh
// ones — so on first adoption they are STAMPED, never executed.
//
// This is not tidiness, it is required: several cannot be safely replayed.
// sso-event-channel and sso-mfa-toggle RENAME COLUMN (errors once renamed), and
// sso-org-management-2 does DROP TABLE org_role_app_defaults followed by CREATE
// — replaying it against a live database would silently discard every app-role
// default. Never add to this list; anything new must simply be idempotent.
const BASELINE = new Set([
  'sso-add-session-devices.sql',
  'sso-avatar.sql',
  'sso-clients-disable.sql',
  'sso-email-otp.sql',
  'sso-event-channel.sql',
  'sso-kmsi.sql',
  'sso-mfa-toggle.sql',
  'sso-org-management-2.sql',
  'sso-org-management.sql',
  'sso-rbac.sql',
  'sso-registration-2.sql',
  'sso-registration.sql',
  'sso-settings.sql',
  'sso-stepup-method.sql',
  'sso-stepup.sql',
  'sso-system-client.sql',
]);

// One writer at a time. Several instances booting together (or a boot racing the
// installer) would otherwise run the same file twice — the tracking INSERT is
// not enough on its own, since both would read "not applied" before either
// commits. Advisory locks are connection-scoped and released on unlock/disconnect.
const LOCK_KEY = 8_246_113; // arbitrary, fixed: identifies THIS lock

export interface MigrationResult {
  applied: string[];
  baselined: string[];
}

// strict = the installer: a failure must surface, because reporting a successful
// install on top of a broken schema is worse than failing loudly.
// lenient (boot, the default) = log and keep serving; a running SSO is more
// useful than one that refuses to start over a migration that may not matter yet.
// `pool` is for the installer, which runs before the app's own pool is pointed at
// the freshly configured database.
export async function runMigrations(
  { strict = false, pool = appPool }: { strict?: boolean; pool?: pg.Pool } = {},
): Promise<MigrationResult> {
  const result: MigrationResult = { applied: [], baselined: [] };
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCK_KEY]);
    await client.query(`
      CREATE TABLE IF NOT EXISTS schema_migrations (
        filename    text PRIMARY KEY,
        applied_at  timestamptz NOT NULL DEFAULT now()
      )`);

    const { rows } = await client.query<{ filename: string }>('SELECT filename FROM schema_migrations');
    const done = new Set(rows.map((r) => r.filename));

    let files: string[] = [];
    try {
      files = fs.readdirSync(DIR).filter((f) => f.endsWith('.sql')).sort();
    } catch {
      // No directory (e.g. a trimmed deploy) — nothing to do, and not an error.
      return result;
    }

    for (const file of files) {
      if (done.has(file)) continue;
      if (BASELINE.has(file)) {
        // Pre-runner history: record as applied without executing.
        await client.query('INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING', [file]);
        result.baselined.push(file);
        continue;
      }
      const sql = fs.readFileSync(path.join(DIR, file), 'utf8');
      // Per-migration transaction: a failure leaves that file unrecorded and its
      // statements rolled back, so a fixed rerun starts from a clean slate.
      await client.query('BEGIN');
      try {
        await client.query(sql);
        await client.query('INSERT INTO schema_migrations (filename) VALUES ($1)', [file]);
        await client.query('COMMIT');
        result.applied.push(file);
        console.log(`migration applied: ${file}`);
      } catch (err) {
        await client.query('ROLLBACK').catch(() => {});
        throw new Error(`migration ${file} failed: ${(err as Error).message}`);
      }
    }

    if (result.baselined.length) {
      console.log(`migrations: baselined ${result.baselined.length} pre-existing (not executed)`);
    }
    return result;
  } catch (err) {
    console.error('migrations:', (err as Error).message);
    if (strict) throw err;
    return result;
  } finally {
    await client.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]).catch(() => {});
    client.release();
  }
}
