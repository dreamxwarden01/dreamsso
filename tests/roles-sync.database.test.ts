import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { processIncomingEvents, validateIncomingEvents, normalizeRoleCatalog, catalogDigest, EventError, type CatalogDependencies } from '../src/backchannel/rolesSync.js';

const EPOCH = '11111111-1111-4111-8111-111111111111';
const subjects = Object.fromEntries(['root', 'rootDenied', 'plain', 'noOrg', 'orgDenied', 'overrideDenied', 'orgFixed', 'overrideFixed'].map(key => [key, randomUUID()]));
const catalog = (revision?: string, defaultRole: number | null = 2, roles = [
  { role_id: 0, name: 'Owner', level: 0 }, { role_id: 2, name: 'Member', level: 10 }, { role_id: 5, name: 'Guest', level: 20 },
]) => ({ roles, default_role: defaultRole, ...(revision ? { catalog_epoch: EPOCH, catalog_revision: revision } : {}) });
const code = (expected: string) => (error: unknown) => error instanceof EventError && error.code === expected;

// This test never accepts the ordinary application DATABASE_URL or a remote host.
test('catalog and inbox changes share real PostgreSQL authority/outbox transactions', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  // The runtime helper has a default pool; disable dotenv and bind even that
  // unused default to this fixture before importing. No existing env file is read.
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = connectionString;
  const { withRoleTransaction, ensureRoleSyncState, publishRoleChanges } = await import('../src/rbac/roleChanges.js');
  const { insertEvents } = await import('../src/events/outboxStore.js');
  const { pool: unusedDefaultPool } = await import('../src/db.js');
  const schema = 'role_sync_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 8, options: `-c search_path=${schema},public`, application_name: schema });
  const deps: CatalogDependencies = { ensureRoleSyncState, publishRoleChanges };
  const at = Math.floor(Date.now() / 1000), clock = () => at * 1000;
  const apply = (client: string, payload: unknown, options: { id?: string; iat?: number; deps?: CatalogDependencies } = {}) => {
    const iat = options.iat ?? at;
    return withRoleTransaction(db => processIncomingEvents(db, client, { iat, exp: iat + 120 },
      validateIncomingEvents([{ id: options.id ?? randomUUID(), type: 'roles.sync', payload }]), options.deps ?? deps, clock), database);
  };
  const events = async (client: string) => (await database.query(`SELECT id,payload,version::text FROM event_outbox WHERE target_client_id=$1 AND kind='account.roles_change' AND status='pending' ORDER BY sequence`, [client])).rows;
  const emptyEvents = (client: string) => database.query('DELETE FROM event_outbox WHERE target_client_id=$1', [client]);
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    const schemaSql = (await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, '');
    await database.query(schemaSql);
    const migration = await readFile(new URL('../db/migrations/001-role-event-consistency.sql', import.meta.url), 'utf8');
    await database.query(migration);await database.query(migration);
    await database.query(`INSERT INTO org_roles(slug,label,level) VALUES ('root','Root',0),('member','Member',100),('blocked','Blocked',100),('fixed','Fixed',100)`);
    for (const [name, sub] of Object.entries(subjects)) await database.query('INSERT INTO identities(sub,username,display_name) VALUES($1,$2::text,$2::text)', [sub, name]);
    for (const [name, role] of [['root', 'root'], ['rootDenied', 'root'], ['plain', 'member'], ['orgDenied', 'blocked'], ['orgFixed', 'fixed']]) {
      await database.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)', [subjects[name], role]);
    }
    for (const client of ['main', 'deny-first', 'legacy', 'collision-a', 'collision-b', 'concurrent', 'rollback', 'removed', 'late', 'seeded', 'root-baseline', 'upgrade-legacy', 'historical-inbox', 'enqueue-lock']) {
      await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES($1,$1,'{}')", [client]);
    }
    await database.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('blocked','main',NULL),('fixed','main',2)");
    for (const [name, role] of [['rootDenied', null], ['overrideDenied', null], ['overrideFixed', 2]] as const) {
      await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'main',$2)", [subjects[name], role]);
    }

    await t.test('first sync emits managed state for every identity and respects explicit NULL/root bootstrap', async () => {
      await apply('main', catalog('1'));
      const out = await events('main');assert.equal(out.length, 8);
      const values = Object.fromEntries(out.map(row => [row.payload.sub, row.payload.role_id]));
      assert.equal(values[subjects.root], 0);assert.equal(values[subjects.rootDenied], null);
      assert.equal(values[subjects.overrideDenied], null);assert.equal(values[subjects.orgDenied], null);
      assert.equal(values[subjects.plain], 2);assert.equal(values[subjects.noOrg], 2);
      assert.ok(out.every(row => row.payload.authority_revision === '1' && row.version === '1'));
      assert.equal(new Set(out.map(row => row.payload.authority_epoch)).size, 1);
      assert.equal((await database.query("SELECT app_role_id FROM org_role_app_defaults WHERE client_id='main' AND role_slug='root'")).rows[0].app_role_id, 0);
      assert.equal((await database.query("SELECT actor_sub,detail FROM org_audit_log WHERE action='roles.reconcile'")).rows[0].actor_sub, null);
      await apply('deny-first', catalog('1', null));
      const denied = await events('deny-first');assert.equal(denied.length, 8);
      assert.equal(denied.find(row => row.payload.sub === subjects.noOrg)?.payload.role_id, null);
      assert.equal((await database.query("SELECT managed FROM app_role_effective WHERE client_id='deny-first' AND user_sub=$1", [subjects.noOrg])).rows[0].managed, true);
    });

    await t.test('default-only changes notify catalog inheritors including a user without an org role', async () => {
      await emptyEvents('main');await apply('main', catalog('2', 5));
      let out = await events('main');assert.deepEqual(out.map(row => row.payload.sub).sort(), [subjects.plain, subjects.noOrg].sort());
      assert.ok(out.every(row => row.payload.role_id === 5 && row.payload.authority_revision === '2'));
      await emptyEvents('main');await apply('main', catalog('3', null));out = await events('main');
      assert.deepEqual(out.map(row => row.payload.sub).sort(), [subjects.plain, subjects.noOrg].sort());
      assert.ok(out.every(row => row.payload.role_id === null && row.payload.authority_revision === '3'));
    });

    await t.test('versioned ordering, immutable event identity and source-scoped UUIDs', async () => {
      const id = randomUUID();await apply('main', catalog('4', 2), { id });await emptyEvents('main');
      await apply('main', catalog('4', 2), { id, iat: at + 1 });assert.equal((await events('main')).length, 0);
      await assert.rejects(apply('main', catalog('5', 5), { id }), code('event_identity_conflict'));
      const conflictId = randomUUID();await assert.rejects(apply('main', catalog('4', 5), { id: conflictId }), code('catalog_revision_conflict'));
      assert.equal((await database.query('SELECT 1 FROM processed_events WHERE source=$1 AND id=$2', ['main', conflictId])).rowCount, 0);
      await apply('main', catalog('2', 5), { iat: at + 3 });assert.equal((await events('main')).length, 0);
      assert.equal((await database.query("SELECT default_role_id FROM app_role_catalogs WHERE client_id='main'")).rows[0].default_role_id, 2);
      await assert.rejects(apply('main', catalog(undefined, 5), { iat: at + 3 }), code('catalog_revision_required'));
      await assert.rejects(apply('main', { ...catalog('10'), catalog_epoch: randomUUID() }), code('catalog_epoch_conflict'));
      const collision = randomUUID();
      for (const client of ['collision-a', 'collision-b']) await apply(client, catalog('1'), { id: collision });
      assert.equal((await database.query('SELECT 1 FROM processed_events WHERE id=$1', [collision])).rowCount, 2);
      const oldUnknown = randomUUID();
      await database.query("INSERT INTO processed_events(source,id) VALUES('collision-a',$1)", [oldUnknown]);
      await withRoleTransaction(db => processIncomingEvents(db, 'collision-a', { iat: at, exp: at + 120 },
        validateIncomingEvents([{ id: oldUnknown, type: 'future.type', payload: { value: 1 } }]), deps, clock), database);
      await assert.rejects(withRoleTransaction(db => processIncomingEvents(db, 'collision-a', { iat: at, exp: at + 120 },
        validateIncomingEvents([{ id: oldUnknown, type: 'future.type', payload: { value: 2 } }]), deps, clock), database), code('event_identity_conflict'));
    });

    await t.test('legacy mutable ID follows iat ordering and ambiguous ties consume no ID', async () => {
      const id = randomUUID();await apply('legacy', catalog(undefined, 2), { id });
      await apply('legacy', catalog(undefined, 5), { id, iat: at + 1 });
      assert.equal((await database.query("SELECT default_role_id FROM app_role_catalogs WHERE client_id='legacy'")).rows[0].default_role_id, 5);
      const conflictId = randomUUID();await assert.rejects(apply('legacy', catalog(undefined, null), { id: conflictId, iat: at + 1 }), code('catalog_order_ambiguous'));
      assert.equal((await database.query('SELECT 1 FROM processed_events WHERE source=$1 AND id=$2', ['legacy', conflictId])).rowCount, 0);
      await apply('legacy', catalog(undefined, null), { id: conflictId, iat: at + 2 });
      await apply('legacy', catalog(undefined, 2), { iat: at });
      assert.equal((await database.query("SELECT default_role_id FROM app_role_catalogs WHERE client_id='legacy'")).rows[0].default_role_id, null);
    });

    await t.test('failure after effects/outbox insertion rolls back inbox, catalog and notifications; retry applies', async () => {
      const id = randomUUID();
      const failedDeps: CatalogDependencies = { ...deps, publishRoleChanges: async (db, clients) => { await publishRoleChanges(db, clients);throw new Error('injected-after-outbox'); } };
      await assert.rejects(apply('rollback', catalog('1'), { id, deps: failedDeps }), /injected-after-outbox/);
      for (const table of ['app_role_catalogs', 'app_roles', 'app_role_sync_state', 'app_role_effective']) {
        assert.equal((await database.query(`SELECT 1 FROM ${table} WHERE client_id='rollback'`)).rowCount, 0);
      }
      assert.equal((await events('rollback')).length, 0);
      assert.equal((await database.query('SELECT 1 FROM processed_events WHERE source=$1 AND id=$2', ['rollback', id])).rowCount, 0);
      await apply('rollback', catalog('1'), { id });assert.equal((await events('rollback')).length, 8);
    });

    await t.test('simultaneous first syncs serialize before reading absent catalog and cannot produce a union', async () => {
      let release!: () => void, entered!: () => void;
      const held = new Promise<void>(resolve => { release = resolve; }), firstEntered = new Promise<void>(resolve => { entered = resolve; });
      const first = withRoleTransaction(async db => {
        entered();await held;
        await processIncomingEvents(db, 'concurrent', { iat: at, exp: at + 120 }, validateIncomingEvents([{ id: randomUUID(), type: 'roles.sync',
          payload: catalog('1', 9, [{ role_id: 9, name: 'First', level: 1 }]) }]), deps, clock);
      }, database);
      await firstEntered;
      let secondEntered = false;
      const second = withRoleTransaction(async db => {
        secondEntered = true;
        await processIncomingEvents(db, 'concurrent', { iat: at, exp: at + 120 }, validateIncomingEvents([{ id: randomUUID(), type: 'roles.sync',
          payload: catalog('2', 10, [{ role_id: 10, name: 'Second', level: 2 }]) }]), deps, clock);
      }, database);
      try {
        const deadline = Date.now() + 2000;
        while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [schema])).rowCount) {
          if (Date.now() > deadline) throw new Error('Second transaction did not reach the advisory lock.');
          await new Promise(resolve => setTimeout(resolve, 5));
        }
        assert.equal(secondEntered, false);
      } finally { release(); }
      await Promise.all([first, second]);
      assert.deepEqual((await database.query("SELECT role_id FROM app_roles WHERE client_id='concurrent' ORDER BY role_id")).rows.map(row => row.role_id), [10]);
      assert.equal((await database.query("SELECT catalog_revision::text FROM app_role_sync_state WHERE client_id='concurrent'")).rows[0].catalog_revision, '2');
    });

    await t.test('catalog client lock permits an ordinary producer holding the destination lock to finish its FK insert', async () => {
      const client='enqueue-lock',ordinary=await database.connect();
      await database.query('INSERT INTO event_destinations(client_id) VALUES($1)',[client]);
      let entered!:()=>void,inboundPid=0;
      const publishing=new Promise<void>(resolve=>{entered=resolve;});
      const observedDeps:CatalogDependencies={...deps,publishRoleChanges:async(db,clients,subs,options)=>{
        inboundPid=(await db.query('SELECT pg_backend_pid() AS pid')).rows[0].pid;entered();
        return publishRoleChanges(db,clients,subs,options);
      }};
      await ordinary.query('BEGIN');await ordinary.query("SET LOCAL lock_timeout='4s'");await ordinary.query("SET LOCAL statement_timeout='5s'");
      await ordinary.query('SELECT client_id FROM event_destinations WHERE client_id=$1 FOR UPDATE',[client]);
      const incoming=apply(client,catalog('1'),{deps:observedDeps});
      // Attach a rejection observer before arranging the competing producer.
      incoming.catch(()=>{});
      try{
        await Promise.race([publishing,incoming.then(()=>{throw Error('Catalog finished before reaching publication.');})]);
        const deadline=Date.now()+2000;
        while(!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE pid=$1 AND wait_event_type='Lock'",[inboundPid])).rowCount){
          if(Date.now()>deadline)throw Error('Catalog did not reach the held destination lock.');
          await new Promise(resolve=>setTimeout(resolve,5));
        }
        const outgoing=(async()=>{await insertEvents(ordinary,client,[{type:'org.settings',payload:{site_name:'Ordinary producer'}}]);await ordinary.query('COMMIT');})();
        await Promise.all([incoming,outgoing]);
        const rows=(await database.query('SELECT kind,sequence FROM event_outbox WHERE target_client_id=$1 ORDER BY sequence',[client])).rows;
        assert.equal(rows[0].kind,'org.settings');assert.equal(rows.filter(row=>row.kind==='account.roles_change').length,8);
        assert.equal((await database.query('SELECT catalog_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0].catalog_revision,'1');
      }finally{
        await ordinary.query('ROLLBACK').catch(()=>{});await incoming.catch(()=>{});ordinary.release();
      }
    });

    await t.test('removed-role policy and root exception remain explicit stored assignments', async () => {
      const roles = [{ role_id: 1, name: 'High', level: 1 }, { role_id: 2, name: 'Middle', level: 10 }, { role_id: 3, name: 'Low', level: 20 }];
      await apply('removed', catalog('1', 2, roles));
      await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'removed',1),($2,'removed',3),($3,'removed',NULL)", [subjects.plain, subjects.noOrg, subjects.rootDenied]);
      await database.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('fixed','removed',1)");
      await withRoleTransaction(db => publishRoleChanges(db, ['removed']), database);
      await apply('removed', catalog('2', 2, [roles[1]]));
      const overrides = (await database.query("SELECT user_sub,app_role_id FROM user_app_role_overrides WHERE client_id='removed'")).rows;
      assert.equal(overrides.find(row => row.user_sub === subjects.plain)?.app_role_id, 2);
      assert.equal(overrides.find(row => row.user_sub === subjects.noOrg)?.app_role_id, null);
      assert.equal(overrides.find(row => row.user_sub === subjects.rootDenied)?.app_role_id, null);
      assert.deepEqual((await database.query("SELECT app_role_id FROM org_role_app_defaults WHERE client_id='removed' ORDER BY role_slug")).rows.map(row => row.app_role_id), [2, 2]);
    });

    await t.test('disabled clients and envelopes that expire while waiting cannot mutate state', async () => {
      await database.query("UPDATE oauth_clients SET disabled_at=now() WHERE client_id='late'");
      await assert.rejects(apply('late', catalog('1')), code('unknown_client'));
      await database.query("UPDATE oauth_clients SET disabled_at=NULL WHERE client_id='late'");
      const id = randomUUID();let calls = 0;
      await assert.rejects(withRoleTransaction(db => processIncomingEvents(db, 'late', { iat: at, exp: at + 120 },
        validateIncomingEvents([{ id, type: 'roles.sync', payload: catalog('1') }]), deps,
        () => (++calls > 1 ? at + 130 : at) * 1000), database), code('invalid_token'));
      assert.equal((await database.query("SELECT 1 FROM processed_events WHERE source='late'")).rowCount, 0);
      assert.equal((await events('late')).length, 0);
    });

    await t.test('migration-seeded legacy digest compares existing state without granting null role zero', async () => {
      await database.query("INSERT INTO app_roles(client_id,role_id,name,level,is_system) VALUES('seeded',0,'Owner',0,false)");
      await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id,last_sync_iat) VALUES('seeded',NULL,$1)", [at]);
      await database.query(migration);
      const id = randomUUID();await apply('seeded', { default_role: null, roles: [{ role_id: 0, name: 'Owner', level: 0 }] }, { id });
      assert.equal((await database.query("SELECT default_role_id FROM app_role_catalogs WHERE client_id='seeded'")).rows[0].default_role_id, null);
      assert.equal((await database.query('SELECT 1 FROM processed_events WHERE source=$1 AND id=$2', ['seeded', id])).rowCount, 1);
    });

    await t.test('migration baseline resends current roles once, with fresh IDs, and revision adoption resends once more', async () => {
      const client='upgrade-legacy',snapshot=catalog(undefined,2,[{role_id:0,name:'Owner',level:0},{role_id:2,name:'Member',level:10}]);
      await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('upgrade-legacy',0,'Owner',0),('upgrade-legacy',2,'Member',10)");
      await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id,last_sync_iat) VALUES('upgrade-legacy',2,$1)",[at]);
      await database.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('root','upgrade-legacy',0)");
      await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'upgrade-legacy',NULL)",[subjects.rootDenied]);
      const lostId=randomUUID(),lostPayload={sub:subjects.noOrg,role_id:0};
      await database.query("INSERT INTO event_outbox(id,kind,target_client_id,payload,status) VALUES($1,'account.roles_change','upgrade-legacy',$2,'dead')",[lostId,lostPayload]);
      await database.query(migration);await database.query(migration);
      assert.equal((await events(client)).length,0);
      assert.equal((await database.query('SELECT count(*)::int AS n FROM app_role_effective WHERE client_id=$1',[client])).rows[0].n,8);
      const retained=await database.query('SELECT payload FROM event_outbox WHERE id=$1',[lostId]);assert.deepEqual(retained.rows[0].payload,lostPayload);
      const staleId=randomUUID();await apply(client,snapshot,{id:staleId,iat:at-1});
      let current=(await database.query('SELECT catalog_digest,authority_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0];
      assert.equal(current.catalog_digest,null);assert.equal(current.authority_revision,'0');assert.equal((await events(client)).length,0);
      // A failure after the repair rows are inserted cannot consume its one-time marker.
      const failedDeps:CatalogDependencies={...deps,publishRoleChanges:async(db,clients,subs,options)=>{
        await publishRoleChanges(db,clients,subs,options);throw Error('upgrade-repair-fault');
      }};
      await assert.rejects(apply(client,snapshot,{id:staleId,deps:failedDeps}),/upgrade-repair-fault/);
      assert.equal((await database.query('SELECT catalog_digest FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0].catalog_digest,null);
      assert.equal((await events(client)).length,0);
      // Re-signed legacy same-state report may reuse the earlier stale event ID.
      await apply(client,snapshot,{id:staleId});
      let out=await events(client);assert.equal(out.length,8);assert.equal(new Set(out.map(row=>row.id)).size,8);
      assert.ok(out.every(row=>row.id!==lostId&&row.id!==staleId&&row.version==='1'));
      assert.equal(out.find(row=>row.payload.sub===subjects.noOrg)!.payload.role_id,2);
      assert.equal(out.find(row=>row.payload.sub===subjects.rootDenied)!.payload.role_id,null);
      assert.equal(out.find(row=>row.payload.sub===subjects.root)!.payload.role_id,0);
      current=(await database.query('SELECT catalog_digest,authority_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0];
      assert.ok(Buffer.isBuffer(current.catalog_digest));assert.equal(current.authority_revision,'1');
      const firstIds=new Set(out.map(row=>row.id));
      await database.query("UPDATE event_outbox SET status='delivered' WHERE target_client_id=$1 AND kind='account.roles_change' AND status='pending'",[client]);
      await apply(client,snapshot,{id:staleId});await apply(client,snapshot,{iat:at+1});assert.equal((await events(client)).length,0);
      // Transition into revisioned delivery also establishes fresh RP watermarks,
      // even though SSO's catalog and durable role ledger already match.
      const versioned={...snapshot,catalog_epoch:EPOCH,catalog_revision:'1'},versionedId=randomUUID();
      await apply(client,versioned,{id:versionedId});out=await events(client);assert.equal(out.length,8);
      assert.ok(out.every(row=>row.version==='2'&&!firstIds.has(row.id)&&row.id!==lostId));
      await database.query("UPDATE event_outbox SET status='delivered' WHERE target_client_id=$1 AND kind='account.roles_change' AND status='pending'",[client]);
      await apply(client,versioned,{id:versionedId});await apply(client,versioned);await apply(client,{...versioned,catalog_revision:'2'});
      assert.equal((await events(client)).length,0);
      assert.equal((await database.query('SELECT authority_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0].authority_revision,'2');
      assert.deepEqual((await database.query('SELECT payload,status FROM event_outbox WHERE id=$1',[lostId])).rows[0],{payload:lostPayload,status:'dead'});
    });

    await t.test('historical unbound inbox IDs use catalog ordering before binding, including multiple pre-upgrade revisions', async () => {
      const client='historical-inbox';
      await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('historical-inbox',0,'Owner',0),('historical-inbox',2,'Member',10),('historical-inbox',5,'Guest',20)");
      await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id,last_sync_iat) VALUES('historical-inbox',2,$1)",[at]);
      await database.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('root','historical-inbox',0)");
      await database.query(migration);
      const oldAt=new Date('2026-01-01T00:00:00Z'),ids=Object.fromEntries(['first','next','stale','same','conflict','foreign','partial'].map(key=>[key,randomUUID()]));
      for(const id of Object.values(ids))await database.query('INSERT INTO processed_events(source,id,processed_at) VALUES($1,$2,$3)',[client,id,oldAt]);
      const receipt=async(id:string)=>(await database.query('SELECT event_type,payload_digest,processed_at FROM processed_events WHERE source=$1 AND id=$2',[client,id])).rows[0];
      const revision=async()=>(await database.query('SELECT catalog_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows[0].catalog_revision;
      await apply(client,catalog('1',2),{id:ids.first});
      assert.equal(await revision(),'1');assert.equal((await receipt(ids.first!)).event_type,'roles.sync');assert.ok(Buffer.isBuffer((await receipt(ids.first!)).payload_digest));
      // First-adoption-only compatibility would strand this second snapshot
      // already ACKed by the old receiver under another unbound ID.
      await apply(client,catalog('2',5),{id:ids.next});assert.equal(await revision(),'2');
      assert.equal((await database.query('SELECT default_role_id FROM app_role_catalogs WHERE client_id=$1',[client])).rows[0].default_role_id,5);
      assert.ok(Buffer.isBuffer((await receipt(ids.next!)).payload_digest));await emptyEvents(client);
      await apply(client,catalog('1',2),{id:ids.stale});
      assert.deepEqual(await receipt(ids.stale!),{event_type:null,payload_digest:null,processed_at:oldAt});
      assert.equal(await revision(),'2');assert.equal((await events(client)).length,0);
      await apply(client,catalog('2',5),{id:ids.same});
      assert.equal((await events(client)).length,0);assert.equal((await receipt(ids.same!)).event_type,'roles.sync');assert.ok(Buffer.isBuffer((await receipt(ids.same!)).payload_digest));
      await assert.rejects(apply(client,catalog('2',null),{id:ids.conflict}),code('catalog_revision_conflict'));
      await assert.rejects(apply(client,{...catalog('99',2),catalog_epoch:randomUUID()},{id:ids.foreign}),code('catalog_epoch_conflict'));
      for(const id of [ids.conflict,ids.foreign])assert.deepEqual(await receipt(id!),{event_type:null,payload_digest:null,processed_at:oldAt});
      // Binding an accepted historical row establishes the ordinary immutable
      // identity contract. Partial metadata is never grandfathered.
      await assert.rejects(apply(client,catalog('3',null),{id:ids.first}),code('event_identity_conflict'));
      await database.query('UPDATE processed_events SET event_type=$3 WHERE source=$1 AND id=$2',[client,ids.partial,'roles.sync']);
      await assert.rejects(apply(client,catalog('3',null),{id:ids.partial}),code('event_identity_conflict'));
      assert.equal(await revision(),'2');assert.equal((await events(client)).length,0);
      await apply(client,catalog('3',null),{id:ids.stale});
      assert.equal(await revision(),'3');assert.ok(Buffer.isBuffer((await receipt(ids.stale!)).payload_digest));
    });

    await t.test('missing stored root default signals once even when migration baseline already inherits catalog top', async () => {
      await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('root-baseline',0,'Owner',0)");
      await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id,last_sync_iat) VALUES('root-baseline',0,$1)", [at]);
      await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'root-baseline',NULL)", [subjects.rootDenied]);
      await database.query(migration);
      assert.equal((await database.query("SELECT role_id FROM app_role_effective WHERE client_id='root-baseline' AND user_sub=$1", [subjects.root])).rows[0].role_id, 0);
      await database.query(`UPDATE app_role_sync_state SET catalog_mode='revisioned',catalog_epoch=$1,catalog_revision=1,catalog_digest=$2
        WHERE client_id='root-baseline'`, [EPOCH, catalogDigest(normalizeRoleCatalog(catalog('1', 0, [{ role_id: 0, name: 'Owner', level: 0 }])))]);
      await apply('root-baseline', catalog('2', 0, [{ role_id: 0, name: 'Owner', level: 0 }]));
      let out = await events('root-baseline');assert.equal(out.length, 1);
      assert.equal(out[0].payload.sub, subjects.root);assert.equal(out[0].payload.role_id, 0);assert.equal(out[0].version, '1');
      await emptyEvents('root-baseline');
      await apply('root-baseline', catalog('3', 0, [{ role_id: 0, name: 'Owner', level: 0 }]));
      assert.equal((await events('root-baseline')).length, 0);
      // A changed stored default also forces one notification, with a single
      // revision even when the same member belongs to the ordinary role diff.
      await database.query("UPDATE org_role_app_defaults SET app_role_id=NULL WHERE client_id='root-baseline' AND role_slug='root'");
      await database.query("UPDATE app_role_effective SET role_id=NULL WHERE client_id='root-baseline' AND user_sub=$1", [subjects.root]);
      await apply('root-baseline', catalog('4', 0, [{ role_id: 0, name: 'Owner', level: 0 }]));
      out = await events('root-baseline');assert.equal(out.length, 1);
      assert.equal(out[0].payload.sub, subjects.root);assert.equal(out[0].payload.role_id, 0);assert.equal(out[0].version, '2');
    });
  } finally {
    await database.end();await unusedDefaultPool.end();
    await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
