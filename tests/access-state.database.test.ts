import assert from 'node:assert/strict';
import test from 'node:test';
import pg from 'pg';
import { readAccessStates } from '../src/backchannel/accessStateStore.js';
const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const C = '33333333-3333-4333-8333-333333333333';
const D = '44444444-4444-4444-8444-444444444444';
const MISSING = '99999999-9999-4999-8999-999999999999';
test('current account and RP state resolution in an isolated real PostgreSQL fixture', async () => {
  const connectionString = process.env.DREAMSSO_LOCAL_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('Run the isolated database test script.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_access_state_test') throw new Error('Only the local fixture database is allowed.');
  const db = new pg.Client({ connectionString });await db.connect();
  try {
    await db.query(`
      CREATE TABLE oauth_clients (client_id text PRIMARY KEY, disabled_at timestamptz);
      CREATE TABLE identities (sub uuid PRIMARY KEY, status text NOT NULL, deleted_at timestamptz);
      CREATE TABLE app_roles (client_id text, role_id integer, PRIMARY KEY(client_id,role_id));
      CREATE TABLE app_role_catalogs (client_id text PRIMARY KEY, default_role_id integer);
      CREATE TABLE user_app_role_overrides (user_sub uuid,client_id text,app_role_id integer,PRIMARY KEY(user_sub,client_id));
      CREATE TABLE user_org_roles (user_sub uuid,org_role_slug text,PRIMARY KEY(user_sub,org_role_slug),UNIQUE(user_sub));
      CREATE TABLE org_role_app_defaults (role_slug text,client_id text,app_role_id integer,PRIMARY KEY(role_slug,client_id));
      INSERT INTO oauth_clients VALUES ('a',NULL),('b',NULL),('unmanaged',NULL);
      INSERT INTO app_roles VALUES ('a',1),('a',2),('b',9);
      INSERT INTO app_role_catalogs VALUES ('a',1),('b',9);
      INSERT INTO org_role_app_defaults VALUES ('member','a',2),('blocked','a',NULL);
    `);
    for (const id of [A,B,C,D]) await db.query("INSERT INTO identities VALUES ($1,'active',NULL)",[id]);
    await db.query("INSERT INTO user_org_roles VALUES ($1,'member'),($2,'member'),($3,'blocked')",[A,B,C]);
    await db.query("INSERT INTO user_app_role_overrides VALUES ($1,'a',NULL)",[B]);
    await assert.rejects(db.query("INSERT INTO user_org_roles VALUES ($1,'another-role')",[A]));
    let result = await readAccessStates(db,'a',[B,A,MISSING,C,D]);
    assert.deepEqual(result.map(s=>s.sub),[B,A,MISSING,C,D]);
    assert.equal(result[0].rp.role_source,'override');assert.equal(result[0].rp.role_id,null);assert.equal(result[0].allowed,false);
    assert.equal(result[1].rp.role_source,'org');assert.equal(result[1].rp.role_id,2);assert.equal(result[1].allowed,true);
    assert.equal(result[2].account.status,'not_found');assert.equal(result[2].allowed,false);
    assert.equal(result[3].rp.role_source,'org');assert.equal(result[3].rp.role_id,null);assert.equal(result[3].allowed,false);
    assert.equal(result[4].rp.role_source,'catalog');assert.equal(result[4].rp.role_id,1);
    assert.equal((await readAccessStates(db,'b',[A]))[0].rp.role_id,9);
    for (const status of ['disabled','locked']) {
      await db.query('UPDATE identities SET status=$1 WHERE sub=$2',[status,A]);
      const state=(await readAccessStates(db,'a',[A]))[0];assert.equal(state.account.status,status);assert.equal(state.rp.role_id,2);assert.equal(state.allowed,false);
    }
    await db.query("UPDATE identities SET status='active',deleted_at=now() WHERE sub=$1",[A]);
    assert.equal((await readAccessStates(db,'a',[A]))[0].account.status,'deleted');
    await db.query("INSERT INTO user_app_role_overrides VALUES ($1,'a',999)",[D]);
    const orphan=(await readAccessStates(db,'a',[D]))[0];assert.equal(orphan.rp.access,'unknown_role');assert.equal(orphan.allowed,false);
    await db.query("INSERT INTO org_role_app_defaults VALUES ('member','unmanaged',2)");
    const unmanaged=(await readAccessStates(db,'unmanaged',[B]))[0];assert.equal(unmanaged.rp.access,'unmanaged');assert.equal(unmanaged.rp.catalog_synced,false);
    const uncatalogued=(await readAccessStates(db,'unmanaged',[A]))[0];assert.equal(uncatalogued.rp.role_id,null);assert.equal(uncatalogued.rp.role_source,'none');
    await db.query("UPDATE oauth_clients SET disabled_at=now() WHERE client_id='a'");
    assert.deepEqual(await readAccessStates(db,'a',[B]),[]);
    await db.query("DELETE FROM oauth_clients WHERE client_id='b'");assert.deepEqual(await readAccessStates(db,'b',[B]),[]);
  } finally { await db.end(); }
});
