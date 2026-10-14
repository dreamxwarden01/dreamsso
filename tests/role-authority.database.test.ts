import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { readAccessStateSnapshot, readAccessStates } from '../src/backchannel/accessStateStore.js';

test('role authority snapshots remain coherent across concurrent PostgreSQL mutations', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = connectionString;
  const { withRoleTransaction, publishRoleChanges } = await import('../src/rbac/roleChanges.js');
  const { pool: unusedDefaultPool } = await import('../src/db.js');
  const schema = 'role_authority_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 8, options: `-c search_path=${schema},public`, application_name: schema });
  const [catalogUser, orgUser, deniedUser, unknownRoleUser, missingUser] = Array.from({ length: 5 }, () => randomUUID());
  const subjects = [deniedUser, catalogUser, missingUser, orgUser, unknownRoleUser];
  const snapshot = () => readAccessStateSnapshot(database, 'managed', subjects);
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO org_roles(slug,label,level) VALUES('member','Member',100)");
    for (const [i, sub] of [catalogUser, orgUser, deniedUser, unknownRoleUser].entries()) {
      await database.query('INSERT INTO identities(sub,username,display_name) VALUES($1,$2::text,$2::text)', [sub, 'authority-user-' + i]);
    }
    await database.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'member')", [orgUser]);
    for (const client of ['managed', 'unmanaged']) await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES($1,$1,'{}')", [client]);
    await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('managed',0,'Root',0),('managed',2,'Member',10),('managed',3,'Guest',20)");
    await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES('managed',2)");
    await database.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('member','managed',3)");
    await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'managed',NULL),($2,'managed',999)", [deniedUser, unknownRoleUser]);
    await database.query(await readFile(new URL('../db/migrations/001-role-event-consistency.sql', import.meta.url), 'utf8'));
    const initial = await snapshot();assert.ok(initial.authority);
    const epoch = initial.authority.epoch;

    await t.test('legacy JSON roles, explicit NULL, missing accounts and unknown-role denial are preserved', async () => {
      assert.deepEqual(initial.states.map(s => s.sub), subjects);
      assert.deepEqual(initial.states.map(s => [s.rp.role_id, s.rp.access, s.allowed]),
        [[null, 'no_access', false], [2, 'allowed', true], [null, 'no_access', false], [3, 'allowed', true], [999, 'unknown_role', false]]);
      assert.deepEqual(initial.authority, { epoch, revision: '0' });
      assert.deepEqual(await readAccessStates(database, 'managed', subjects), initial.states);
      assert.deepEqual(Object.keys(initial.states[0]).sort(), ['account', 'allowed', 'rp', 'sub']);
    });

    await t.test('uncommitted role, ledger and revision changes are invisible together', async () => {
      let release!: () => void, ready!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), staged = new Promise<void>(resolve => { ready = resolve; });
      const mutation = withRoleTransaction(async db => {
        await db.query("UPDATE app_role_catalogs SET default_role_id=3 WHERE client_id='managed'");
        await db.query("UPDATE org_role_app_defaults SET app_role_id=2 WHERE role_slug='member' AND client_id='managed'");
        assert.equal(await publishRoleChanges(db, ['managed']), 2);ready();await gate;
      }, database);
      try {
        await Promise.race([staged, mutation.then(() => { throw new Error('Mutation finished before the staged snapshot check.'); })]);
        assert.deepEqual(await snapshot(), initial);
      }
      finally { release(); }
      await mutation;
      const after = await snapshot();assert.deepEqual(after.authority, { epoch, revision: '1' });
      assert.equal(after.states.find(s => s.sub === catalogUser)?.rp.role_id, 3);
      assert.equal(after.states.find(s => s.sub === orgUser)?.rp.role_id, 2);
      const events = (await database.query("SELECT payload,version::text FROM event_outbox WHERE target_client_id='managed' ORDER BY sequence")).rows;
      assert.equal(events.length, 2);assert.ok(events.every(e => e.version === '1' && e.payload.authority_revision === '1' && e.payload.authority_epoch === epoch));
      for (const event of events) assert.equal(event.payload.role_id, after.states.find(s => s.sub === event.payload.sub)?.rp.role_id);
    });

    await t.test('commit between database result materialization and response cannot mix new version with old roles', async () => {
      const before = await snapshot();let switched = false;
      const interleaved = await readAccessStateSnapshot({
        async query(sql, parameters) {
          const result = await database.query(sql, parameters);
          if (!switched) {
            switched = true;
            await withRoleTransaction(async db => {
              await db.query("UPDATE app_role_catalogs SET default_role_id=0 WHERE client_id='managed'");
              await publishRoleChanges(db, ['managed']);
            }, database);
          }
          return result;
        },
      }, 'managed', subjects);
      assert.deepEqual(interleaved, before);
      const after = await snapshot();assert.deepEqual(after.authority, { epoch, revision: '2' });
      assert.equal(after.states.find(s => s.sub === catalogUser)?.rp.role_id, 0);
      assert.equal(after.states.find(s => s.sub === deniedUser)?.rp.role_id, null);
    });

    await t.test('unmanaged clients carry no authority even if a synchronization state row exists', async () => {
      await database.query("INSERT INTO app_role_sync_state(client_id) VALUES('unmanaged')");
      const result = await readAccessStateSnapshot(database, 'unmanaged', [catalogUser, missingUser]);
      assert.equal(result.authority, null);assert.equal(result.states[0].rp.access, 'unmanaged');assert.equal(result.states[0].allowed, true);
      assert.equal(result.states[1].account.status, 'not_found');assert.equal(result.states[1].allowed, false);
    });

    await t.test('missing managed authority fails closed, while bigint revisions remain exact', async () => {
      const original = (await database.query("SELECT authority_epoch,authority_revision::text FROM app_role_sync_state WHERE client_id='managed'")).rows[0];
      await database.query("DELETE FROM app_role_sync_state WHERE client_id='managed'");
      await assert.rejects(snapshot(), /Role authority snapshot is unavailable/);
      await database.query("INSERT INTO app_role_sync_state(client_id,authority_epoch,authority_revision) VALUES('managed',$1,$2::bigint)", [original.authority_epoch, '9007199254740993']);
      assert.deepEqual((await snapshot()).authority, { epoch, revision: '9007199254740993' });
      await database.query("UPDATE app_role_sync_state SET authority_revision=$1::bigint WHERE client_id='managed'", [original.authority_revision]);
    });

    await t.test('disabled, deleted and removed-client snapshots cannot retain an allowed state', async () => {
      await database.query("UPDATE identities SET status='disabled' WHERE sub=$1", [catalogUser]);
      assert.equal((await snapshot()).states.find(s => s.sub === catalogUser)?.allowed, false);
      await database.query('UPDATE identities SET deleted_at=now() WHERE sub=$1', [orgUser]);
      assert.equal((await snapshot()).states.find(s => s.sub === orgUser)?.account.status, 'deleted');
      await database.query("UPDATE oauth_clients SET disabled_at=now() WHERE client_id='managed'");
      assert.deepEqual(await snapshot(), { states: [], authority: null });
      await database.query("DELETE FROM oauth_clients WHERE client_id='unmanaged'");
      assert.deepEqual(await readAccessStateSnapshot(database, 'unmanaged', [catalogUser]), { states: [], authority: null });
    });
  } finally {
    await database.end();await unusedDefaultPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
