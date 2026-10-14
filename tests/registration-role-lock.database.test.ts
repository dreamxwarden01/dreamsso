import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { readAccessStateSnapshot } from '../src/backchannel/accessStateStore.js';

test('registration and catalog publication serialize initial membership with role authority', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = connectionString;
  const { resolveRegistrationRole } = await import('../src/registrationRole.js');
  const { withRoleTransaction, publishRoleChanges } = await import('../src/rbac/roleChanges.js');
  const { pool: globalPool } = await import('../src/db.js');
  const schema = 'registration_roles_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 6, options: `-c search_path=${schema},public`, application_name: schema });
  const registration = async (sub: string, invited: string | null, inside?: () => Promise<void>) => {
    const db = await database.connect();
    try {
      await db.query('BEGIN');
      const role = await resolveRegistrationRole(db, invited);
      await db.query('INSERT INTO identities(sub,username,display_name) VALUES($1,$2::text,$2::text)', [sub, 'user-' + sub]);
      await db.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)', [sub, role]);
      await inside?.();await db.query('COMMIT');return role;
    } catch (error) { await db.query('ROLLBACK');throw error; }
    finally { db.release(); }
  };
  const waitForLock = async () => {
    const deadline = Date.now() + 2000;
    while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [schema])).rowCount) {
      if (Date.now() > deadline) throw new Error('Competing operation did not reach the shared role lock.');
      await new Promise(resolve => setTimeout(resolve, 5));
    }
  };
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO org_roles(slug,label,level) VALUES('member','Member',100),('candidate','Candidate',150),('standard_user','Standard',100)");
    await database.query("INSERT INTO settings(key,value) VALUES('default_org_role','member')");
    await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES('rp','RP','{}')");
    await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('rp',2,'Member',10),('rp',3,'Guest',20)");
    await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES('rp',2)");
    await database.query(await readFile(new URL('../db/migrations/001-role-event-consistency.sql', import.meta.url), 'utf8'));

    await t.test('registration commits first: waiting catalog publication includes the new subject', async () => {
      const sub = randomUUID();let release!: () => void, staged!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { staged = resolve; });
      const registering = registration(sub, null, async () => { staged();await gate; });
      await Promise.race([ready, registering]);let catalogEntered = false;
      const catalog = withRoleTransaction(async db => {
        catalogEntered = true;await db.query("UPDATE app_role_catalogs SET default_role_id=3 WHERE client_id='rp'");
        await publishRoleChanges(db, ['rp']);
      }, database);
      try { await waitForLock();assert.equal(catalogEntered, false);assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [sub])).rowCount, 0); }
      finally { release(); }
      assert.equal(await registering, 'member');await catalog;
      const state = await readAccessStateSnapshot(database, 'rp', [sub]);
      assert.equal(state.states[0].rp.role_id, 3);assert.equal(state.authority?.revision, '1');
      const out = (await database.query("SELECT payload FROM event_outbox WHERE target_client_id='rp' AND kind='account.roles_change' AND payload->>'sub'=$1", [sub])).rows;
      assert.equal(out.length, 1);assert.equal(out[0].payload.role_id, 3);assert.equal(out[0].payload.authority_revision, state.authority?.revision);
    });

    await t.test('catalog commits first: registration waits, reads current default and its first snapshot sees new authority', async () => {
      const sub = randomUUID();let release!: () => void, staged!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), ready = new Promise<void>(resolve => { staged = resolve; });
      assert.equal((await database.query("SELECT value FROM settings WHERE key='default_org_role'")).rows[0].value, 'member');
      const catalog = withRoleTransaction(async db => {
        await db.query("UPDATE settings SET value='candidate' WHERE key='default_org_role'");
        await db.query("UPDATE app_role_catalogs SET default_role_id=NULL WHERE client_id='rp'");
        await publishRoleChanges(db, ['rp']);staged();await gate;
      }, database);
      await Promise.race([ready, catalog]);let registered = false;
      const registering = registration(sub, null).then(role => { registered = true;return role; });
      try { await waitForLock();assert.equal(registered, false);assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [sub])).rowCount, 0); }
      finally { release(); }
      await catalog;assert.equal(await registering, 'candidate');
      const state = await readAccessStateSnapshot(database, 'rp', [sub]);
      assert.equal(state.authority?.revision, '2');assert.equal(state.states[0].rp.role_id, null);assert.equal(state.states[0].allowed, false);
    });

    await t.test('validated invitation choice and absent/empty default fallback preserve existing behavior', async () => {
      assert.equal(await registration(randomUUID(), 'member'), 'member');
      await database.query("UPDATE settings SET value='' WHERE key='default_org_role'");
      assert.equal(await registration(randomUUID(), null), 'standard_user');
      await database.query("DELETE FROM settings WHERE key='default_org_role'");
      assert.equal(await registration(randomUUID(), null), 'standard_user');
      const rejected = randomUUID();
      await assert.rejects(registration(rejected, 'deleted-invitation-role'), (error: unknown) => (error as { code?: string }).code === '23503');
      assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [rejected])).rowCount, 0);
    });
  } finally {
    await database.end();await globalPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
