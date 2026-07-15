import pg from 'pg';
import { config } from './config.js';

function makePool(): pg.Pool {
  // Empty connectionString (setup mode) → pg falls back to PG* env / defaults and
  // simply fails on first query; we never query until the DB is configured.
  const p = new pg.Pool(config.databaseUrl ? { connectionString: config.databaseUrl } : {});
  p.on('error', (err) => console.error('Postgres pool error:', err));
  return p;
}

// ES live binding: importers use `pool.query(...)` and transparently see the swap
// performed by reconnectDb().
export let pool = makePool();

// Rebuild the pool against the current config.databaseUrl. The /setup wizard calls
// this after writing .env so the running process adopts the DB with no restart.
export async function reconnectDb(): Promise<void> {
  const old = pool;
  pool = makePool();
  try {
    await old.end();
  } catch {
    /* draining a possibly-never-connected pool */
  }
}
