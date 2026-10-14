import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { SignJWT, generateKeyPair, exportJWK } from 'jose';
import type { AuthedRequest } from '../src/resourceAuth.js';

test('transactional org proof never needs a second pool connection and rechecks current proof', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  const issuer = 'https://proof.example.invalid';
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = connectionString;process.env.ISSUER = issuer;
  const { assertOrgRoleProof } = await import('../src/rbac/orgProof.js');
  const { RoleAccessError } = await import('../src/rbac/roleAdministration.js');
  const { withRoleTransaction } = await import('../src/rbac/roleChanges.js');
  const { getSetting, invalidateSettingCache } = await import('../src/settings.js');
  const { pool: globalPool } = await import('../src/db.js');
  const schema = 'org_proof_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 1000,
    options: `-c search_path=${schema},public`, application_name: schema });
  const actor = randomUUID(), other = randomUUID(), sid = randomUUID(), otherSid = randomUUID();
  const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-proof-key';
  const sign = async (scope = 'profile', expired = false) => {
    const now = Math.floor(Date.now() / 1000);
    return new SignJWT({ scope }).setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid }).setIssuer(issuer).setAudience(issuer)
      .setSubject(actor).setIssuedAt(now - (expired ? 120 : 0)).setExpirationTime(now + (expired ? -1 : 600)).sign(keys.privateKey);
  };
  const request = async (scope = 'profile', expired = false, session = sid): Promise<AuthedRequest> =>
    ({ headers: { authorization: 'Bearer ' + await sign(scope, expired), 'x-stepup-sid': session }, auth: { sub: actor, scopes: ['profile'] } }) as AuthedRequest;
  const denied = (error: string, status = 403) => (e: unknown) => e instanceof RoleAccessError && e.status === status && e.body.error === error;
  const originalQuery = globalPool.query;
  let escapedReads = 0;
  globalPool.query = (async () => { escapedReads++;throw new Error('Proof escaped the transaction connection.'); }) as typeof globalPool.query;
  const proof = async (req: AuthedRequest) => withRoleTransaction(db => assertOrgRoleProof(db, req), database);
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'proof-actor','Proof actor'),($2,'proof-other','Proof other')", [actor, other]);
    // Verification reads only the generated public JWK. The private-key column
    // deliberately contains unusable synthetic bytes and is never decrypted.
    await database.query("INSERT INTO signing_keys(kid,public_jwk,private_key_enc,status) VALUES($1,$2,$3,'current')", [jwk.kid, jwk, Buffer.from('synthetic-not-a-private-key')]);
    for (const [session, sub] of [[sid, actor], [otherSid, other]]) await database.query(`INSERT INTO sessions(sid,user_sub,token_hash,stepup_at,stepup_method,expires_at)
      VALUES($1,$2,$3,now(),'totp',now()+interval '1 day')`, [session, sub, randomBytes(32)]);
    await database.query("INSERT INTO totp_credentials(user_sub,secret_enc,confirmed_at) VALUES($1,$2,now())", [actor, Buffer.from('synthetic-not-a-totp-secret')]);
    await database.query("INSERT INTO settings(key,value) VALUES('stepup_portal_required','true'),('stepup_validity_minutes','30')");

    await t.test('generated public-key verification and TOTP proof complete with max one connection', async () => {
      await proof(await request());assert.equal(escapedReads, 0);assert.equal(database.waitingCount, 0);
    });
    await t.test('expiry, current scope, subject and session ownership fail closed', async () => {
      await assert.rejects(proof(await request('profile', true)), denied('invalid_token', 401));
      await assert.rejects(proof(await request('email')), denied('insufficient_scope'));
      const wrongSubject = await request();wrongSubject.auth!.sub = other;
      await assert.rejects(proof(wrongSubject), denied('invalid_token', 401));
      await assert.rejects(proof(await request('profile', false, otherSid)), denied('step_up_required'));
      await assert.rejects(proof(await request('profile', false, '')), denied('step_up_required'));assert.equal(escapedReads, 0);
    });
    await t.test('owned passkey preempts TOTP, unconfirmed factors and weak proof do not satisfy org access', async () => {
      await database.query('INSERT INTO webauthn_credentials(user_sub,credential_id,public_key) VALUES($1,$2,$3)', [actor, randomBytes(32), Buffer.from('synthetic-public-key')]);
      await assert.rejects(proof(await request()), denied('step_up_required'));
      await database.query("UPDATE sessions SET stepup_method='passkey' WHERE sid=$1", [sid]);await proof(await request());
      for (const method of ['email', 'password']) {
        await database.query('UPDATE sessions SET stepup_method=$2 WHERE sid=$1', [sid, method]);await assert.rejects(proof(await request()), denied('step_up_required'));
      }
      await database.query('DELETE FROM webauthn_credentials WHERE user_sub=$1', [actor]);
      await database.query("UPDATE sessions SET stepup_method='totp' WHERE sid=$1", [sid]);
      await database.query('UPDATE totp_credentials SET confirmed_at=NULL WHERE user_sub=$1', [actor]);
      await assert.rejects(proof(await request()), denied('step_up_required'));
      await database.query('UPDATE totp_credentials SET confirmed_at=now() WHERE user_sub=$1', [actor]);
    });
    await t.test('transactional policy reads ignore an earlier permissive process cache value', async () => {
      await database.query("UPDATE settings SET value='false' WHERE key='stepup_portal_required'");
      globalPool.query = database.query.bind(database) as typeof globalPool.query;
      invalidateSettingCache('stepup_portal_required');assert.equal(await getSetting('stepup_portal_required'), 'false');
      globalPool.query = (async () => { escapedReads++;throw new Error('Proof escaped the transaction connection.'); }) as typeof globalPool.query;
      await database.query("UPDATE settings SET value='true' WHERE key='stepup_portal_required'");
      assert.equal(await getSetting('stepup_portal_required'), 'false');
      await assert.rejects(proof(await request('profile', false, '')), denied('step_up_required'));
      await database.query("UPDATE sessions SET stepup_at=now()-interval '45 minutes' WHERE sid=$1", [sid]);
      await database.query("UPDATE settings SET value='60' WHERE key='stepup_validity_minutes'");await proof(await request());
      await database.query("UPDATE settings SET value='30' WHERE key='stepup_validity_minutes'");await assert.rejects(proof(await request()), denied('step_up_required'));
      await database.query('UPDATE sessions SET stepup_at=now() WHERE sid=$1', [sid]);assert.equal(escapedReads, 0);
    });
    await t.test('a failed final proof recheck rolls the intervening mutation back', async () => {
      const req = await request();
      await assert.rejects(withRoleTransaction(async db => {
        await assertOrgRoleProof(db, req);
        await db.query("INSERT INTO settings(key,value) VALUES('proof-test-mutation','changed')");
        await db.query("UPDATE sessions SET stepup_at=now()-interval '2 hours' WHERE sid=$1", [sid]);
        await assertOrgRoleProof(db, req);
      }, database), denied('step_up_required'));
      assert.equal((await database.query("SELECT 1 FROM settings WHERE key='proof-test-mutation'")).rowCount, 0);
      await proof(await request());assert.equal(escapedReads, 0);
    });
    await t.test('public-JWK storage failure propagates as unavailable and rolls back instead of becoming invalid-token', async () => {
      const req = await request();
      await assert.rejects(withRoleTransaction(async db => {
        await db.query("INSERT INTO settings(key,value) VALUES('proof-storage-mutation','changed')");
        await db.query('ALTER TABLE signing_keys RENAME TO signing_keys_unavailable');
        await assertOrgRoleProof(db, req);
      }, database), (error: unknown) => !(error instanceof RoleAccessError) && (error as { code?: string }).code === '42P01');
      assert.equal((await database.query("SELECT 1 FROM settings WHERE key='proof-storage-mutation'")).rowCount, 0);
      assert.equal((await database.query('SELECT 1 FROM signing_keys')).rowCount, 1);
      await proof(await request());assert.equal(escapedReads, 0);
    });
  } finally {
    globalPool.query = originalQuery;await database.end();await globalPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
