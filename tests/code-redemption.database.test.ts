import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { Redis } from 'ioredis';
import { createCodeStore, type AuthCode } from '../src/oidc/codeStore.js';
import { redeemAuthorizationCode, CodeRedemptionError, type CodeRedemptionDependencies } from '../src/oidc/codeRedemption.js';
import { readAccessStateSnapshot } from '../src/backchannel/accessStateStore.js';

const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
const redisUrl = process.env.DREAMSSO_AUTH_TEST_REDIS_URL;

test('Redis GETDEL and PostgreSQL row locks serialize code redemption with revocation', { skip: !connectionString || !redisUrl }, async t => {
  const url = new URL(connectionString!), redisAddress = new URL(redisUrl!);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test'
    || redisAddress.hostname !== '127.0.0.1' || redisAddress.pathname !== '/15') throw Error('Only isolated loopback auth fixtures are allowed.');
  const schema = 'code_redemption_' + randomUUID().replaceAll('-', '');
  const prefix = schema + ':';
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 1500,
    options: `-c search_path=${schema},public`, application_name: schema + '_redemption' });
  const other = new pg.Pool({ connectionString, max: 1, options: `-c search_path=${schema},public`, application_name: schema + '_revoke' });
  const redis = new Redis(redisUrl!, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const keys: string[] = [];
  const store = createCodeStore({
    save: async (key, value, ttl) => { keys.push(prefix + key);return redis.set(prefix + key, value, 'EX', ttl); },
    getdel: key => redis.getdel(prefix + key),
  });
  const sub = randomUUID(), sid = randomUUID(), verifier = 'synthetic-local-pkce';
  const codeData: AuthCode = { clientId: 'fixture-rp', redirectUri: 'https://rp.example.invalid/callback', userSub: sub, sid,
    scope: 'openid profile email', codeChallenge: createHash('sha256').update(verifier).digest('base64url'), codeChallengeMethod: 'S256', amr: ['pwd'], authTime: 1_000_000 };
  const input = async () => ({ clientId: codeData.clientId, redirectUri: codeData.redirectUri, verifier, code: await store.createCode(codeData) });
  type IdClaims = Parameters<Awaited<ReturnType<CodeRedemptionDependencies['prepare']>>['mintIdToken']>[0];
  let mintedClaims: IdClaims | undefined;
  let signed = 0, pauseSigning: (() => Promise<void>) | undefined;
  const deps: CodeRedemptionDependencies = { database, consumeCode: store.consumeCode, readAccessStateSnapshot,
    prepare: async () => ({ windows: { idleHours: 24, maxHours: 720, transientMaxHours: 24 }, siteName: 'Fixture',
      mintIdToken: async claims => { signed++;mintedClaims = claims;assert.equal(Number.isSafeInteger(claims.extra.sess_exp), true);if (pauseSigning) await pauseSigning();return 'synthetic-id'; },
      mintAccessToken: async () => { signed++;return 'synthetic-access'; } }) };
  const reset = async () => {
    await database.query("UPDATE identities SET status='active' WHERE sub=$1", [sub]);
    await database.query('DELETE FROM sessions WHERE sid=$1', [sid]);
    await database.query("INSERT INTO sessions(sid,user_sub,token_hash,expires_at,persistent) VALUES($1,$2,$3,now()+interval '1 day',true)", [sid, sub, randomBytes(32)]);
    signed = 0;mintedClaims = undefined;pauseSigning = undefined;
  };
  async function waitForLock(applicationName: string) {
    const until = Date.now() + 3000;
    while (Date.now() < until) {
      const result = await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [applicationName]);
      if (result.rows.length) return;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw Error('Expected isolated transaction lock wait was not observed.');
  }
  try {
    await redis.connect();
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'code-fixture','Code fixture')", [sub]);
    await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES('fixture-rp','Fixture','{}')");

    await t.test('Redis7 consumes one stored code once across concurrent consumers', async () => {
      const code = await store.createCode(codeData);
      const results = await Promise.all(Array.from({ length: 32 }, () => store.consumeCode(code)));
      assert.equal(results.filter(Boolean).length, 1);assert.equal(await store.consumeCode(code), null);
    });
    await t.test('normal RP redemption reads state on its sole pool connection', async () => {
      await reset();const result = await redeemAuthorizationCode(await input(), deps);
      assert.equal(result.access_token, 'synthetic-access');assert.equal(signed, 2);
      assert.deepEqual((await database.query('SELECT clients FROM sessions WHERE sid=$1', [sid])).rows[0].clients, ['fixture-rp']);
      assert.equal(database.waitingCount, 0);
    });
    await t.test('fractional DB timestamps produce conservative integer expiry for transient and near-end persistent sessions', async () => {
      for (const [persistent, ageHours, capHours] of [[false, 0, 24], [true, 719, 720]] as const) {
        await reset();
        const { rows: [clock] } = await database.query<{ precise: string; floored: string }>(
          `UPDATE sessions SET persistent=$2,created_at=date_trunc('second',clock_timestamp())-($3::integer*interval '1 hour')-interval '10 seconds'+interval '0.9 seconds'
           WHERE sid=$1 RETURNING EXTRACT(EPOCH FROM created_at)::text AS precise,floor(EXTRACT(EPOCH FROM created_at))::text AS floored`,
          [sid, persistent, ageHours]);
        assert.equal(Number.isInteger(Number(clock.precise)), false, 'fixture must retain fractional PostgreSQL seconds');
        await redeemAuthorizationCode(await input(), deps);
        assert.ok(mintedClaims);
        const expiry = mintedClaims.extra.sess_exp as number;
        assert.equal(Number.isSafeInteger(expiry), true);
        assert.equal(mintedClaims.extra.sess_persistent, persistent);
        assert.equal(expiry, Number(clock.floored) + capHours * 3600);
        assert.ok(expiry <= Number(clock.precise) + capHours * 3600, 'never extend the underlying absolute window');
        const remaining = expiry - Math.floor(Date.now() / 1000);
        assert.ok(remaining > 0 && remaining < 86400, 'exercise the Account TTL branch capped by SSO expiry');
      }
    });
    await t.test('redemption owns session lock until both signatures and commit; logout waits', async () => {
      await reset();let enter!: () => void, release!: () => void;
      const entered = new Promise<void>(resolve => { enter = resolve; }), gate = new Promise<void>(resolve => { release = resolve; });
      pauseSigning = async () => { enter();await gate; };
      const redemption = redeemAuthorizationCode(await input(), deps);await entered;
      let deleted = false;
      const deletion = other.query('DELETE FROM sessions WHERE sid=$1 RETURNING sid', [sid]).then(result => { deleted = true;return result; });
      try { await waitForLock(schema + '_revoke');assert.equal(deleted, false); }
      finally { release(); }
      await redemption;assert.equal((await deletion).rowCount, 1);assert.equal(signed, 2);
      assert.equal((await database.query('SELECT 1 FROM sessions WHERE sid=$1', [sid])).rowCount, 0);
    });
    await t.test('logout holding the row first wins; outstanding code cannot mint afterward', async () => {
      await reset();const revoke = await other.connect();
      try {
        await revoke.query('BEGIN');await revoke.query('DELETE FROM sessions WHERE sid=$1', [sid]);
        const redemption = redeemAuthorizationCode(await input(), deps);
        // Observe rejection immediately to avoid an unhandled promise if a lock times out.
        const rejected = assert.rejects(redemption, (error: unknown) => error instanceof CodeRedemptionError && error.code === 'invalid_grant');
        try { await waitForLock(schema + '_redemption'); }
        finally { await revoke.query('COMMIT'); }
        await rejected;assert.equal(signed, 0);
      } finally { await revoke.query('ROLLBACK').catch(() => {});revoke.release(); }
    });
    await t.test('identity disable before redemption rejects even a previously issued code', async () => {
      await reset();await database.query("UPDATE identities SET status='disabled' WHERE sub=$1", [sub]);
      await assert.rejects(redeemAuthorizationCode(await input(), deps), (error: unknown) => error instanceof CodeRedemptionError && error.status === 403);
      assert.equal(signed, 0);
    });
    await t.test('expired idle and absolute windows reject the original session', async () => {
      for (const mutation of ["last_seen=now()-interval '25 hours'", "created_at=now()-interval '721 hours'"]) {
        await reset();await database.query('UPDATE sessions SET ' + mutation + ' WHERE sid=$1', [sid]);
        await assert.rejects(redeemAuthorizationCode(await input(), deps), (error: unknown) => error instanceof CodeRedemptionError && error.code === 'invalid_grant');assert.equal(signed, 0);
      }
    });
  } finally {
    if (keys.length) await redis.del(...keys).catch(() => {});
    await redis.quit().catch(() => redis.disconnect());await database.end();await other.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
