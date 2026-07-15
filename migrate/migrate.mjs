#!/usr/bin/env node
// DreamSSO user migration: videosite (MariaDB) -> DreamSSO (Postgres).
//
// INPUT  NDJSON (one JSON object per line) exported from videosite.users:
//   docker exec videosite-db mariadb -N -r -uroot -p'PW' DBNAME \
//     -e "SELECT JSON_OBJECT('legacy_id',user_id,'username',username,
//           'display_name',display_name,'email',email,'password_hash',password_hash,
//           'password_changed_at',password_changed_at,'is_active',is_active) FROM users" \
//     > users.ndjson
//   (-N skips headers, -r is raw output so the JSON isn't escaped.)
//
// OUTPUT sub_map.csv  ->  legacy_id,username,sub   (videosite uses this to rewrite user_id)
//
// Moves ONLY username/display_name/email/password_hash (+ is_active -> status).
// Argon2id hashes copy verbatim. MFA is re-enrolled, not migrated.
// Idempotent: a re-run keeps every user's ORIGINAL sub (the ON CONFLICT path
// returns the existing row's sub, ignoring the freshly-minted one).
//
// Connection: standard PG* env vars (PGHOST/PGPORT/PGUSER/PGPASSWORD/PGDATABASE).
//   set -a; source ../.env; set +a
//   node migrate.mjs --in ../users.ndjson --out ../sub_map.csv

import fs from 'node:fs';
import readline from 'node:readline';
import pg from 'pg';
import { uuidv7 } from 'uuidv7';

const args = process.argv.slice(2);
const opt = (name, def) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : def; };
const inPath = opt('--in', 'users.ndjson');
const outPath = opt('--out', 'sub_map.csv');
const assumeVerified = opt('--email-verified', 'true') !== 'false'; // videosite reg is email-verified

const SQL = `
  INSERT INTO identities
    (sub, username, display_name, email, email_verified, password_hash, password_changed_at, status)
  VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
  ON CONFLICT (username) WHERE deleted_at IS NULL DO UPDATE SET
    display_name  = EXCLUDED.display_name,
    email         = EXCLUDED.email,
    password_hash = EXCLUDED.password_hash,
    status        = EXCLUDED.status
  RETURNING sub`;

const csv = (v) =>
  v == null ? '' : /[",\n]/.test(String(v)) ? `"${String(v).replace(/"/g, '""')}"` : String(v);

const pool = new pg.Pool();
const out = fs.createWriteStream(outPath);
out.write('legacy_id,username,sub\n');

const client = await pool.connect();
let ok = 0, bad = 0;
try {
  await client.query('BEGIN');
  const rl = readline.createInterface({ input: fs.createReadStream(inPath), crlfDelay: Infinity });
  for await (const line of rl) {
    const t = line.trim();
    if (!t) continue;
    let u;
    try { u = JSON.parse(t); } catch { console.error('skip unparseable line:', t.slice(0, 80)); bad++; continue; }
    const email = u.email || null;
    const status = (u.is_active === 0 || u.is_active === '0' || u.is_active === false) ? 'disabled' : 'active';
    const { rows } = await client.query(SQL, [
      uuidv7(), u.username, u.display_name, email,
      assumeVerified && email != null,
      u.password_hash, u.password_changed_at || null, status,
    ]);
    out.write(`${csv(u.legacy_id)},${csv(u.username)},${rows[0].sub}\n`);
    ok++;
  }
  await client.query('COMMIT');
} catch (err) {
  await client.query('ROLLBACK');
  console.error('\nMigration FAILED — rolled back, nothing committed.\n', err);
  process.exitCode = 1;
} finally {
  client.release();
  await new Promise((r) => out.end(r));
  await pool.end();
}
if (!process.exitCode) console.log(`Migrated ${ok} users (${bad} skipped) -> ${outPath}`);
