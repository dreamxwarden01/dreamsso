import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { readAccessStateSnapshot } from '../src/backchannel/accessStateStore.js';

test('account status, unchanged raw role, source revision, ledger and outbox share one transaction',async t=>{
  const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if(!connectionString)throw Error('Use the isolated role-sync database fixture.');
  const url=new URL(connectionString);
  if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only the generated loopback fixture database is allowed.');
  process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.DATABASE_URL=connectionString;
  const { withRoleTransaction,publishRoleChanges }=await import('../src/rbac/roleChanges.js');
  const { changeAccountStatus,AccountStatusError }=await import('../src/rbac/accountStatus.js');
  const { revokeSessions }=await import('../src/oidc/sessionRevocation.js');
  const { pool:unusedDefaultPool }=await import('../src/db.js');
  const schema='account_status_source_'+randomUUID().replaceAll('-',''),admin=new pg.Pool({connectionString,max:2});
  const database=new pg.Pool({connectionString,max:6,options:`-c search_path=${schema},public`});
  const target=randomUUID(),historical=randomUUID(),rollbackUser=randomUUID();
  const change=(sub:string,status:'active'|'disabled'|'locked'|'deleted')=>withRoleTransaction(db=>changeAccountStatus(db,sub,status),database);
  const events=async(client='managed')=>(await database.query("SELECT id,payload,version::text FROM event_outbox WHERE kind='account.roles_change' AND target_client_id=$1 ORDER BY sequence",[client])).rows;
  const row=async(sub=target)=>(await database.query('SELECT * FROM identities WHERE sub=$1',[sub])).rows[0];
  const ledger=async(sub=target)=>(await database.query("SELECT * FROM app_role_effective WHERE client_id='managed' AND user_sub=$1",[sub])).rows[0];
  const snapshot=()=>readAccessStateSnapshot(database,'managed',[target]);
  try{
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
    // Recreate the old ledger shape; 001 must remain a historical migration.
    await database.query('ALTER TABLE app_role_effective DROP COLUMN account_status');
    for(const [sub,name,deleted]of [[target,'current',false],[historical,'historical',true],[rollbackUser,'rollback',false]]as const)
      await database.query('INSERT INTO identities(sub,username,display_name,deleted_at) VALUES($1,$2::text,$2::text,$3)',[sub,name,deleted?new Date('2025-01-01T00:00:00Z'):null]);
    for(const client of ['managed','managed-other','account'])await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES($1,$1,'{}')",[client]);
    for(const client of ['managed','managed-other']){
      await database.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES($1,2,'Member',10)",[client]);
      await database.query('INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES($1,2)',[client]);
    }
    await database.query(await readFile(new URL('../db/migrations/001-role-event-consistency.sql',import.meta.url),'utf8'));
    const migration=await readFile(new URL('../db/migrations/003-account-status-authority.sql',import.meta.url),'utf8');
    await t.test('003 is repeatable, leaves old status unknown and does not invent events or versions',async()=>{
      await database.query(migration);await database.query(migration);
      assert.equal((await ledger()).account_status,null);assert.equal((await ledger()).authority_revision,'0');
      assert.equal((await events()).length,0);assert.equal(await ledger(historical),undefined);
    });
    await t.test('an explicit no-op establishes a NULL legacy baseline once, only for managed clients',async()=>{
      const before=(await row()).updated_at;
      assert.deepEqual(await change(target,'active'),{changed:false,published:2});
      assert.deepEqual(await change(target,'active'),{changed:false,published:0});
      assert.deepEqual((await row()).updated_at,before);
      const out=await events();assert.equal(out.length,1);assert.equal(out[0].payload.account_status,'active');assert.equal(out[0].payload.role_id,2);
      assert.equal(out[0].version,'1');assert.equal((await ledger()).account_status,'active');assert.equal((await events('account')).length,0);
      assert.equal((await database.query("SELECT 1 FROM app_role_sync_state WHERE client_id='account'")).rowCount,0);
    });
    await t.test('active -> disabled -> active with unchanged role advances exact coherent snapshots',async()=>{
      const epoch=(await snapshot()).authority!.epoch;
      for(const [status,revision]of [['disabled','2'],['active','3'],['locked','4'],['active','5']]as const){
        assert.deepEqual(await change(target,status),{changed:true,published:2});
        const observed=await snapshot(),event=(await events()).at(-1)!,stored=await ledger();
        assert.deepEqual(observed.authority,{epoch,revision});assert.equal(observed.states[0].account.status,status);
        assert.equal(observed.states[0].rp.role_id,2);assert.equal(observed.states[0].allowed,status==='active');
        assert.equal(event.payload.role_id,observed.states[0].rp.role_id);assert.equal(event.payload.account_status,status);
        assert.equal(event.payload.authority_epoch,epoch);assert.equal(event.payload.authority_revision,revision);assert.equal(event.version,revision);
        assert.equal(stored.role_id,2);assert.equal(stored.account_status,status);assert.equal(stored.authority_revision,revision);
        assert.deepEqual(await change(target,status),{changed:false,published:0});
      }
    });
    await t.test('outbox failure rolls identity, ledger, source version and all clients back together',async()=>{
      await change(rollbackUser,'active');
      const beforeIdentity=await row(rollbackUser),beforeLedger=await ledger(rollbackUser),beforeEvents=await events();
      const beforeState=(await database.query('SELECT client_id,authority_revision::text FROM app_role_sync_state ORDER BY client_id')).rows;
      await database.query(`ALTER TABLE event_outbox ADD CONSTRAINT account_status_fixture_failure
        CHECK(target_client_id<>'managed-other' OR kind<>'account.roles_change' OR payload->>'account_status'<>'disabled') NOT VALID`);
      try{await assert.rejects(change(rollbackUser,'disabled'));}
      finally{await database.query('ALTER TABLE event_outbox DROP CONSTRAINT account_status_fixture_failure');}
      assert.deepEqual(await row(rollbackUser),beforeIdentity);assert.deepEqual(await ledger(rollbackUser),beforeLedger);
      assert.deepEqual(await events(),beforeEvents);
      assert.deepEqual((await database.query('SELECT client_id,authority_revision::text FROM app_role_sync_state ORDER BY client_id')).rows,beforeState);
    });
    await t.test('suspend hook revocation, logout and status events all roll back if later publication fails',async()=>{
      const sid=randomUUID();
      await database.query("INSERT INTO sessions(sid,user_sub,token_hash,amr,clients,expires_at) VALUES($1,$2,$3,'{}',ARRAY['managed','account'],now()+INTERVAL '1 hour')",[sid,rollbackUser,Buffer.alloc(32,7)]);
      const beforeIdentity=await row(rollbackUser),beforeLedger=await ledger(rollbackUser);
      const beforeEvents=(await database.query('SELECT id,kind,target_client_id,payload,version::text FROM event_outbox ORDER BY sequence')).rows;
      await database.query(`ALTER TABLE event_outbox ADD CONSTRAINT account_combined_fixture_failure
        CHECK(target_client_id<>'managed-other' OR kind<>'account.roles_change' OR payload->>'account_status'<>'disabled') NOT VALID`);
      try{
        await assert.rejects(withRoleTransaction(db=>changeAccountStatus(db,rollbackUser,'disabled',async db=>{
          assert.equal(await revokeSessions(db,{subject:rollbackUser}),1);
        }),database));
      }finally{await database.query('ALTER TABLE event_outbox DROP CONSTRAINT account_combined_fixture_failure');}
      assert.deepEqual(await row(rollbackUser),beforeIdentity);assert.deepEqual(await ledger(rollbackUser),beforeLedger);
      assert.equal((await database.query('SELECT 1 FROM sessions WHERE sid=$1',[sid])).rowCount,1);
      assert.deepEqual((await database.query('SELECT id,kind,target_client_id,payload,version::text FROM event_outbox ORDER BY sequence')).rows,beforeEvents);
      assert.deepEqual(await withRoleTransaction(db=>changeAccountStatus(db,rollbackUser,'disabled',async db=>{
        assert.equal(await revokeSessions(db,{subject:rollbackUser}),1);
      }),database),{changed:true,published:2});
      assert.equal((await database.query('SELECT 1 FROM sessions WHERE sid=$1',[sid])).rowCount,0);
      const logout=(await database.query("SELECT target_client_id FROM event_outbox WHERE kind='logout' AND payload->>'sid'=$1 ORDER BY target_client_id",[sid])).rows;
      assert.deepEqual(logout.map(row=>row.target_client_id),['account','managed']);
      await change(rollbackUser,'active');
    });
    await t.test('soft deletion publishes the same raw role/status as a query and cannot be reactivated by this helper',async()=>{
      const before=(await snapshot()).authority!;
      assert.deepEqual(await change(target,'deleted'),{changed:true,published:2});
      const observed=await snapshot(),event=(await events()).at(-1)!;
      assert.equal(observed.states[0].account.status,'deleted');assert.equal(observed.states[0].rp.role_id,2);assert.equal(observed.states[0].allowed,false);
      assert.equal(event.payload.account_status,'deleted');assert.equal(event.payload.role_id,2);
      assert.equal(observed.authority!.revision,(BigInt(before.revision)+1n).toString());
      assert.equal(event.payload.authority_revision,observed.authority!.revision);assert.equal((await row()).status,'active');
      assert.deepEqual(await change(target,'deleted'),{changed:false,published:0});
      await assert.rejects(change(target,'active'),error=>error instanceof AccountStatusError&&error.code==='account_unavailable');
      // Full catalog reconciliation includes known deleted tombstones, but does
      // not introduce unrelated historical deletions into a new grant baseline.
      await withRoleTransaction(db=>publishRoleChanges(db,['managed']),database);
      assert.equal(await ledger(historical),undefined);
      assert.equal((await events()).filter(e=>e.payload.sub===historical).length,0);
    });
    await t.test('uncommitted status and its new source version are invisible until the same commit',async()=>{
      const before=await readAccessStateSnapshot(database,'managed',[rollbackUser]);
      let reached!:()=>void,release!:()=>void;
      const staged=new Promise<void>(done=>{reached=done;}),gate=new Promise<void>(done=>{release=done;});
      const mutation=withRoleTransaction(async db=>{await changeAccountStatus(db,rollbackUser,'disabled');reached();await gate;},database);
      try{await Promise.race([staged,mutation.then(()=>{throw Error('mutation did not wait');})]);assert.deepEqual(await readAccessStateSnapshot(database,'managed',[rollbackUser]),before);}
      finally{release();}
      await mutation;
      const after=await readAccessStateSnapshot(database,'managed',[rollbackUser]);
      assert.equal(after.states[0].account.status,'disabled');assert.equal(after.states[0].rp.role_id,2);
      assert.equal(after.authority!.revision,(BigInt(before.authority!.revision)+1n).toString());
    });
  }finally{await database.end();await unusedDefaultPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();}
});
