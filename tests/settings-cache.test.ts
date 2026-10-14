import assert from 'node:assert/strict';
import test from 'node:test';

// No application env, secrets or database connection: replace the lazy pool's
// query boundary before exercising cache behavior.
process.env.DOTENV_CONFIG_PATH = '/dev/null';
process.env.DATABASE_URL = 'postgresql://unused@127.0.0.1:1/unused';
const { pool } = await import('../src/db.js');
const { getSetting, setSetting, invalidateSettingCache } = await import('../src/settings.js');

test('transaction invalidation prevents an earlier read from restoring stale cache data', async () => {
  const original = pool.query;let calls = 0, release!: (value: { rows: { value: string }[] }) => void;
  pool.query = (async () => {
    calls++;
    if (calls === 1) return new Promise(resolve => { release = resolve; });
    return { rows: [{ value: 'new-role' }] };
  }) as typeof pool.query;
  try {
    const older = getSetting('fixture-transaction-pointer');
    invalidateSettingCache('fixture-transaction-pointer');
    assert.equal(await getSetting('fixture-transaction-pointer'), 'new-role');
    release({ rows: [{ value: 'old-role' }] });assert.equal(await older, 'old-role');
    assert.equal(await getSetting('fixture-transaction-pointer'), 'new-role');assert.equal(calls, 2);
  } finally { pool.query = original; }
});

test('ordinary setting writes also fence stale reads that began before their commit', async () => {
  const original = pool.query;let reads = 0, release!: (value: { rows: { value: string }[] }) => void;
  pool.query = (async (sql: string) => {
    if (sql.startsWith('SELECT')) { reads++;return new Promise(resolve => { release = resolve; }); }
    return { rows: [] };
  }) as typeof pool.query;
  try {
    const older = getSetting('fixture-ordinary-pointer');
    await setSetting('fixture-ordinary-pointer', 'new-role');
    release({ rows: [{ value: 'old-role' }] });assert.equal(await older, 'old-role');
    assert.equal(await getSetting('fixture-ordinary-pointer'), 'new-role');assert.equal(reads, 1);
  } finally { pool.query = original;await pool.end(); }
});
