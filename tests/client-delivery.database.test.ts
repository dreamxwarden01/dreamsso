import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { insertEvents, PostgresOutboxStore, deliverDestination, EVENT_BYTES_MAX, MAX_ATTEMPTS } from '../src/events/outboxStore.js';
import { recoverClientDelivery, readClientDelivery, setClientEnabled, reconcileChangedEndpoint, ClientDeliveryError } from '../src/events/clientDelivery.js';
import { withRoleTransaction, publishRoleChanges } from '../src/rbac/roleChanges.js';
import { readAccessStateSnapshot } from '../src/backchannel/accessStateStore.js';

const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
test('delivery pause and reconciliation preserve logout facts without replaying historical grants', {skip:!connectionString}, async t=>{
  const url=new URL(connectionString!);assert.equal(url.hostname,'127.0.0.1');assert.equal(url.pathname,'/dreamsso_role_sync_test');
  const schema='delivery_recovery_'+randomUUID().replaceAll('-','');
  const admin=new pg.Pool({connectionString,max:2});
  const db=new pg.Pool({connectionString,max:4,options:`-c search_path=${schema},public`,application_name:schema});
  const actor=randomUUID(),otherActor=randomUUID(),subject=randomUUID();
  const store=new PostgresOutboxStore(db);
  const tx=<T>(work:(c:pg.PoolClient)=>Promise<T>)=>withRoleTransaction(work,db);
  const enqueue=(client:string,kind:string,payload:Record<string,unknown>,id=randomUUID())=>tx(c=>insertEvents(c,client,[{id,type:kind,payload}]));
  const fresh=(client:string)=>db.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,events_uri) VALUES($1,$1,'{}','https://rp.example.invalid/events')",[client]);
  const error=(code:string)=>(e:unknown)=>e instanceof ClientDeliveryError&&e.code===code;
  try{
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');await admin.query(`CREATE SCHEMA ${schema}`);
    await db.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
    const migration=await readFile(new URL('../db/migrations/004-event-delivery-recovery.sql',import.meta.url),'utf8');await db.query(migration);await db.query(migration);
    await db.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'actor','Actor'),($2,'other-actor','Other actor'),($3,'member','Member')",[actor,otherActor,subject]);

    await t.test('migration upgrades the previous destination schema without rewriting queued facts',async()=>{
      await fresh('upgrade');const [id]=await enqueue('upgrade','logout',{sub:subject,sid:randomUUID()});
      const before=(await db.query('SELECT id,payload,sequence::text,status,attempts FROM event_outbox WHERE id=$1',[id])).rows[0];
      await db.query('ALTER TABLE event_destinations DROP COLUMN last_outcome_code,DROP COLUMN last_outcome_at,DROP COLUMN last_recovered_at');
      await db.query('DROP TABLE event_recoveries');await db.query('DROP INDEX event_outbox_client_status');
      await db.query(migration);await db.query(migration);
      assert.deepEqual((await db.query('SELECT id,payload,sequence::text,status,attempts FROM event_outbox WHERE id=$1',[id])).rows[0],before);
      const summary=await readClientDelivery(db,'upgrade');assert.equal(summary.counts.pending,1);assert.equal(summary.last_outcome,null);
    });

    await t.test('disabled or unconfigured destinations pause even oversized heads without burning attempts',async()=>{
      for(const [name,disabled]of [['paused',true],['unconfigured',false]]as const){
        await fresh(name);await enqueue(name,'logout',{sub:subject,sid:randomUUID()});
        await db.query("UPDATE event_outbox SET attempts=49,payload=$2 WHERE target_client_id=$1",[name,JSON.stringify({large:'x'.repeat(EVENT_BYTES_MAX+10)})]);
        await db.query('UPDATE oauth_clients SET disabled_at=CASE WHEN $2 THEN now() ELSE NULL END,events_uri=CASE WHEN $2 THEN events_uri ELSE NULL END WHERE client_id=$1',[name,disabled]);
        assert.ok(!(await store.destinations()).includes(name));
        const before=(await db.query('SELECT id,payload,attempts FROM event_outbox WHERE target_client_id=$1',[name])).rows;
        let calls=0;
        await deliverDestination({store,sign:async()=>{calls++;return'fixture';},send:async()=>{calls++;return 204;}},name);
        assert.equal(calls,0);const after=(await db.query('SELECT id,payload,attempts,status FROM event_outbox WHERE target_client_id=$1',[name])).rows;
        assert.equal(after[0].status,'pending');assert.equal(after[0].attempts,49);assert.deepEqual(after[0].payload,before[0].payload);
        const s=await readClientDelivery(db,name);assert.equal(s.counts.pending,0);assert.equal(s.counts.paused,1);assert.equal(s.counts.dead,0);assert.equal(s.can_recover,false);
      }
    });

    await t.test('enable preserves logout IDs, supersedes old roles, and publishes current forced truth once',async()=>{
      await fresh('managed');
      await db.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('managed',0,'Former',0),('managed',2,'Current',2)");
      await db.query("INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES('managed',0)");
      await tx(c=>publishRoleChanges(c,['managed'],null,{force:true}));
      const old=(await db.query("SELECT id,payload FROM event_outbox WHERE target_client_id='managed'")).rows;
      await db.query("UPDATE event_outbox SET status='dead',attempts=50,last_error_code='http_rejected' WHERE target_client_id='managed'");
      await db.query("UPDATE app_role_catalogs SET default_role_id=2 WHERE client_id='managed'");
      const [logout]=await enqueue('managed','logout',{sub:subject,sid:randomUUID()});
      const payload=(await db.query('SELECT payload,sequence::text FROM event_outbox WHERE id=$1',[logout])).rows[0];
      await db.query("UPDATE event_outbox SET status='dead',attempts=50,last_error_code='delivery_failed' WHERE id=$1",[logout]);
      await enqueue('managed','account.profile_change',{sub:subject,avatar:'synthetic'});
      await db.query("UPDATE event_outbox SET status='dead',last_error_code='http_rejected' WHERE target_client_id='managed' AND kind='account.profile_change'");
      await enqueue('managed','future.event',{diagnostic:'synthetic'});
      await db.query("UPDATE event_outbox SET status='dead',last_error_code='http_rejected' WHERE target_client_id='managed' AND kind='future.event'");
      await tx(c=>setClientEnabled(c,'managed',false));
      await tx(c=>setClientEnabled(c,'managed',true));
      const rows=(await db.query("SELECT id,kind,payload,version::text,status,last_error_code,sequence::text,attempts FROM event_outbox WHERE target_client_id='managed' ORDER BY sequence")).rows;
      for(const previous of old){const current=rows.find(r=>r.id===previous.id);assert.deepEqual(current.payload,previous.payload);assert.equal(current.status,'dead');assert.equal(current.last_error_code,'superseded_by_reconcile');}
      const replay=rows.find(r=>r.id===logout);assert.equal(replay.status,'pending');assert.equal(replay.attempts,MAX_ATTEMPTS-3);assert.deepEqual(replay.payload,payload.payload);assert.equal(replay.sequence,payload.sequence);
      const snapshots=rows.filter(r=>r.kind==='account.roles_change'&&r.status==='pending');assert.equal(snapshots.length,3);assert.ok(snapshots.every(r=>r.payload.role_id===2&&r.payload.account_status==='active'));
      const truth=await readAccessStateSnapshot(db,'managed',[subject]);assert.equal(snapshots.find(r=>r.payload.sub===subject).payload.authority_revision,truth.authority?.revision);
      assert.equal(rows.filter(r=>r.kind==='roles.sync_request'&&r.status==='pending').length,1);
      const profile=rows.find(r=>r.kind==='account.profile_change'&&r.status==='pending');assert.deepEqual(profile.payload,{sub:subject,avatar:null});
      const summary=await readClientDelivery(db,'managed');assert.equal(summary.counts.dead,1);assert.equal(summary.last_outcome?.code,'recovered');
      await tx(c=>setClientEnabled(c,'managed',true));assert.equal((await db.query("SELECT count(*)::int AS n FROM event_outbox WHERE target_client_id='managed'")).rows[0].n,rows.length);
    });

    await t.test('recovered dead logout gets three attempts then releases fresh truth; pending logout retains its budget',async()=>{
      const due=async(client:string)=>{
        await db.query("UPDATE event_outbox SET next_attempt_at=now() WHERE target_client_id=$1 AND status='pending'",[client]);
        await db.query('UPDATE event_destinations SET next_attempt_at=now() WHERE client_id=$1',[client]);
      };
      await fresh('bounded-logout');
      await db.query("INSERT INTO app_roles(client_id,role_id,name,level) VALUES('bounded-logout',2,'Current',2)");
      await db.query("INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES('bounded-logout',2)");
      const [id]=await enqueue('bounded-logout','logout',{sub:subject,sid:randomUUID()});
      await db.query("UPDATE event_outbox SET status='dead',attempts=50,last_error_code='http_rejected' WHERE id=$1",[id]);
      const original=(await db.query('SELECT id,payload,sequence::text FROM event_outbox WHERE id=$1',[id])).rows[0];
      await tx(c=>recoverClientDelivery(c,'bounded-logout',actor,randomUUID()));
      assert.equal((await db.query('SELECT attempts FROM event_outbox WHERE id=$1',[id])).rows[0].attempts,MAX_ATTEMPTS-3);
      const rejected:string[][]=[];
      for(let attempt=1;attempt<=3;attempt++){
        await due('bounded-logout');
        assert.equal(await deliverDestination({store,sign:async(_client,events)=>{rejected.push(events.map(event=>event.id));return'fixture';},send:async()=>400},'bounded-logout'),false);
        const row=(await db.query('SELECT id,payload,sequence::text,status,attempts FROM event_outbox WHERE id=$1',[id])).rows[0];
        assert.equal(row.status,attempt===3?'dead':'pending');assert.equal(row.attempts,MAX_ATTEMPTS-3+attempt);
        assert.deepEqual({id:row.id,payload:row.payload,sequence:row.sequence},original);
      }
      assert.deepEqual(rejected,[[id],[id],[id]]);
      const waiting=(await db.query("SELECT kind,attempts FROM event_outbox WHERE target_client_id='bounded-logout' AND status='pending' ORDER BY sequence")).rows;
      assert.ok(waiting.some(row=>row.kind==='account.roles_change'));assert.ok(waiting.every(row=>row.attempts===0));
      let freshRoleCount=0;
      assert.equal(await deliverDestination({store,sign:async(_client,events)=>{
        assert.ok(events.every(event=>event.id!==id));freshRoleCount=events.filter(event=>event.type==='account.roles_change'&&event.payload.role_id===2).length;return'fixture';
      },send:async()=>204},'bounded-logout'),true);
      assert.equal(freshRoleCount,3);

      await fresh('pending-budget');const [pending]=await enqueue('pending-budget','logout',{sub:subject,sid:randomUUID()});
      await db.query("UPDATE event_outbox SET attempts=49,last_error_code='http_rejected' WHERE id=$1",[pending]);
      const before=(await db.query('SELECT id,payload,sequence::text FROM event_outbox WHERE id=$1',[pending])).rows[0];
      await tx(c=>recoverClientDelivery(c,'pending-budget',actor,randomUUID()));
      assert.equal((await db.query('SELECT attempts FROM event_outbox WHERE id=$1',[pending])).rows[0].attempts,0);
      for(let attempt=1;attempt<=3;attempt++){
        await due('pending-budget');await deliverDestination({store,sign:async()=> 'fixture',send:async()=>400},'pending-budget');
        const row=(await db.query('SELECT id,payload,sequence::text,status,attempts FROM event_outbox WHERE id=$1',[pending])).rows[0];
        assert.equal(row.status,'pending');assert.equal(row.attempts,attempt);
        assert.deepEqual({id:row.id,payload:row.payload,sequence:row.sequence},before);
      }
    });

    await t.test('missing managed catalog atomically refuses manual recovery, enable and endpoint repair',async()=>{
      for(const operation of ['recover','enable','endpoint']as const){
        const client='missing-catalog-'+operation;await fresh(client);
        await db.query('INSERT INTO app_roles(client_id,role_id,name,level) VALUES($1,2,$2,2)',[client,'Fixture']);
        await db.query('INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES($1,2)',[client]);
        await tx(c=>publishRoleChanges(c,[client],null,{force:true}));
        await enqueue(client,'logout',{sub:subject,sid:randomUUID()});
        if(operation==='enable')await tx(c=>setClientEnabled(c,client,false));
        await db.query('DELETE FROM app_role_catalogs WHERE client_id=$1',[client]);
        const snapshot=async()=>({
          client:(await db.query('SELECT disabled_at,events_uri FROM oauth_clients WHERE client_id=$1',[client])).rows,
          destination:(await db.query('SELECT lease_token,lease_until,failures,next_attempt_at,last_outcome_code,last_outcome_at,last_recovered_at FROM event_destinations WHERE client_id=$1',[client])).rows,
          queue:(await db.query('SELECT id,payload,sequence::text,status,attempts,next_attempt_at,last_error_code FROM event_outbox WHERE target_client_id=$1 ORDER BY sequence',[client])).rows,
          authority:(await db.query('SELECT authority_epoch,authority_revision::text FROM app_role_sync_state WHERE client_id=$1',[client])).rows,
          receipts:(await db.query('SELECT request_id FROM event_recoveries WHERE client_id=$1',[client])).rows,
        });
        const before=await snapshot();
        await assert.rejects(tx(async c=>{
          if(operation==='recover')return recoverClientDelivery(c,client,actor,randomUUID());
          if(operation==='enable')return setClientEnabled(c,client,true);
          await c.query('UPDATE oauth_clients SET events_uri=$2 WHERE client_id=$1',[client,'https://changed.example.invalid/events']);
          return reconcileChangedEndpoint(c,client);
        }),error('role_catalog_unavailable'));
        assert.deepEqual(await snapshot(),before);
      }
    });

    await t.test('manual recovery is idempotent per actor/request and fences old lease settlement',async()=>{
      const id=randomUUID();const claim=await store.claim('managed');assert.ok(claim);
      const a=await tx(c=>recoverClientDelivery(c,'managed',actor,id));
      const revision=(await db.query("SELECT authority_revision::text FROM app_role_sync_state WHERE client_id='managed'")).rows[0].authority_revision;
      assert.deepEqual(await tx(c=>recoverClientDelivery(c,'managed',actor,id)),a);
      assert.equal((await db.query("SELECT authority_revision::text FROM app_role_sync_state WHERE client_id='managed'")).rows[0].authority_revision,revision);
      assert.equal(await store.settle(claim,claim.events.map(e=>e.id),{kind:'delivered'}),false);
      await assert.rejects(tx(c=>recoverClientDelivery(c,'managed',otherActor,id)),error('recovery_context_mismatch'));
      const nextId=randomUUID();const [first,second]=await Promise.all([tx(c=>recoverClientDelivery(c,'managed',actor,nextId)),tx(c=>recoverClientDelivery(c,'managed',actor,nextId))]);assert.deepEqual(first,second);
      assert.equal((await db.query('SELECT count(*)::int AS n FROM event_recoveries WHERE client_id=$1 AND request_id=$2',['managed',nextId])).rows[0].n,1);
    });

    await t.test('failed current-snapshot publication rolls back enabling, receipts, retirement and queue changes',async()=>{
      await tx(c=>setClientEnabled(c,'managed',false));
      const before=(await db.query("SELECT id,status,attempts,last_error_code FROM event_outbox WHERE target_client_id='managed' ORDER BY sequence")).rows;
      const rev=(await db.query("SELECT authority_revision::text FROM app_role_sync_state WHERE client_id='managed'")).rows[0].authority_revision;
      await db.query("CREATE FUNCTION fail_recovery() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.kind='account.roles_change' THEN RAISE EXCEPTION 'fixture_recovery_failure'; END IF; RETURN NEW; END $$");
      await db.query('CREATE TRIGGER fail_recovery BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION fail_recovery()');
      try{await assert.rejects(tx(c=>setClientEnabled(c,'managed',true)),/fixture_recovery_failure/);
        assert.ok((await db.query("SELECT disabled_at FROM oauth_clients WHERE client_id='managed'")).rows[0].disabled_at);
        assert.deepEqual((await db.query("SELECT id,status,attempts,last_error_code FROM event_outbox WHERE target_client_id='managed' ORDER BY sequence")).rows,before);
        assert.equal((await db.query("SELECT authority_revision::text FROM app_role_sync_state WHERE client_id='managed'")).rows[0].authority_revision,rev);
      }finally{await db.query('DROP TRIGGER fail_recovery ON event_outbox');}
      await tx(c=>setClientEnabled(c,'managed',true));
    });

    await t.test('configured endpoint repair resumes safe access sync; missing/system/paused actions are explicit',async()=>{
      await fresh('system');await db.query("UPDATE oauth_clients SET is_system=true WHERE client_id='system'");
      await assert.rejects(tx(c=>setClientEnabled(c,'system',false)),error('system_client'));
      await assert.rejects(tx(c=>recoverClientDelivery(c,'missing',actor,randomUUID())),error('not_found'));
      await assert.rejects(tx(c=>recoverClientDelivery(c,'paused',actor,randomUUID())),error('client_disabled'));
      await assert.rejects(tx(c=>recoverClientDelivery(c,'unconfigured',actor,randomUUID())),error('no_events_endpoint'));
      await tx(async c=>{await c.query("UPDATE oauth_clients SET events_uri='https://repaired.example.invalid/events' WHERE client_id='unconfigured'");await reconcileChangedEndpoint(c,'unconfigured');});
      assert.equal((await readClientDelivery(db,'unconfigured')).state,'ready');
      const result=await tx(c=>recoverClientDelivery(c,'system',actor,randomUUID()));assert.equal(result.role_snapshots,0);
      assert.equal((await db.query("SELECT count(*)::int AS n FROM event_outbox WHERE target_client_id='system' AND kind='roles.sync_request'")).rows[0].n,0);
    });

    await t.test('known metadata is regenerated from current values and malformed or unknown facts stay quarantined',async()=>{
      await fresh('metadata');
      await db.query("INSERT INTO settings(key,value) VALUES('site_name','Current name') ON CONFLICT(key) DO UPDATE SET value=excluded.value");
      await db.query("UPDATE identities SET avatar='current.webp' WHERE sub=$1",[subject]);
      await enqueue('metadata','org.settings',{site_name:'Former name'});
      await enqueue('metadata','account.profile_change',{sub:subject,avatar:'former.webp'});
      await enqueue('metadata','roles.sync_request',{});
      await db.query("UPDATE event_outbox SET status='dead',last_error_code='delivery_failed' WHERE target_client_id='metadata'");
      const [invalid]=await enqueue('metadata','logout',{sid:'malformed'});
      const result=await tx(c=>recoverClientDelivery(c,'metadata',actor,randomUUID()));
      assert.equal(result.logout_requeued,0);assert.equal(result.other_retained,1);
      const queued=(await db.query("SELECT kind,payload FROM event_outbox WHERE target_client_id='metadata' AND status='pending' ORDER BY sequence")).rows;
      assert.deepEqual(queued,[{kind:'account.profile_change',payload:{sub:subject,avatar:'current.webp'}},{kind:'org.settings',payload:{site_name:'Current name'}},{kind:'roles.sync_request',payload:{}}]);
      assert.equal((await db.query('SELECT status FROM event_outbox WHERE id=$1',[invalid])).rows[0].status,'dead');
    });

    await t.test('summary is bounded metadata and never exposes endpoint/payload/error text',async()=>{
      await db.query("UPDATE event_destinations SET last_outcome_code='private arbitrary diagnostic',last_outcome_at=now() WHERE client_id='managed'");
      const s=await readClientDelivery(db,'managed'),text=JSON.stringify(s);assert.equal(s.last_outcome?.code,'unknown_error');assert.ok(!text.includes('private'));assert.ok(!text.includes('https://'));assert.ok(!text.includes(subject));
      assert.deepEqual(Object.keys(s.counts).sort(),['dead','delivered','paused','pending']);
    });
  }finally{await db.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();}
});
