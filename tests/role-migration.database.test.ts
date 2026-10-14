import assert from 'node:assert/strict';
import test from 'node:test';
import {readFile,mkdtemp,writeFile,rm} from 'node:fs/promises';
import {tmpdir} from 'node:os';
import {join} from 'node:path';
import {randomUUID} from 'node:crypto';
import pg from 'pg';

// Generated legacy rows and the real migration exercise the upgrade path without
// a historical checkout, runtime configuration import, or an application database.
test('001 upgrades populated legacy tables atomically and preserves history across repeated application',async()=>{
 const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
 if(!connectionString)throw Error('Use the isolated role-sync database fixture.');
 const url=new URL(connectionString);
 if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only the generated loopback fixture database is allowed.');
 const schema='role_upgrade_'+randomUUID().replaceAll('-','');
 const admin=new pg.Client({connectionString});await admin.connect();
 const db=new pg.Client({connectionString,options:`-c search_path=${schema},public`});
 const ids={delivered:randomUUID(),dead:randomUUID(),pending:randomUUID(),processed:randomUUID()};
 const users=Object.fromEntries(['inherit','org','overrideDeny','unknown','deleted'].map(name=>[name,randomUUID()]));
 const oldOutbox=()=>db.query(`SELECT id,kind,target_client_id,payload,version::text,status,attempts,
   next_attempt_at,created_at,delivered_at FROM event_outbox WHERE id=ANY($1::uuid[]) ORDER BY id`,[[ids.delivered,ids.dead,ids.pending]]);
 const oldInbox=()=>db.query('SELECT id,source,processed_at FROM processed_events WHERE id=$1 AND source=$2',[ids.processed,'active-a']);
 const primaryKey=async()=>String((await db.query(`SELECT pg_get_constraintdef(oid) AS definition
   FROM pg_constraint WHERE conrelid='processed_events'::regclass AND contype='p'`)).rows[0].definition);
 const migration=await readFile(new URL('../db/migrations/001-role-event-consistency.sql',import.meta.url),'utf8');
 const apply=async()=>{await db.query('BEGIN');try{await db.query(migration);await db.query('COMMIT');}catch(error){await db.query('ROLLBACK');throw error;}};
 try{
  await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
  await admin.query(`CREATE SCHEMA ${schema}`);await db.connect();
  const sql=(await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,'');await db.query(sql);
  // Explicitly recreate the pre-upgrade shapes, including the old globally
  // unique inbox identity. These are fixture-only transformations.
  await db.query(`DROP TABLE app_role_effective,app_role_sync_state,event_destinations;
    DROP INDEX event_outbox_sequence,event_outbox_client_pending;
    ALTER TABLE event_outbox DROP COLUMN sequence,DROP COLUMN last_error_code,
      DROP COLUMN legacy_redis_member,DROP COLUMN legacy_redis_score;
    ALTER TABLE processed_events DROP CONSTRAINT processed_events_pkey;
    ALTER TABLE processed_events ADD PRIMARY KEY(id);
    ALTER TABLE processed_events DROP COLUMN event_type,DROP COLUMN payload_digest;`);
  for(const [name,sub]of Object.entries(users))await db.query('INSERT INTO identities(sub,username,display_name,deleted_at) VALUES($1,$2::text,$2::text,$3)',[sub,name,name==='deleted'?new Date('2026-01-01T00:00:00Z'):null]);
  await db.query("INSERT INTO org_roles(slug,label,level) VALUES('member','Member',100)");
  await db.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'member')",[users.org]);
  for(const client of ['active-a','active-b','disabled','no-uri','unmanaged']){
   await db.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,events_uri,disabled_at) VALUES($1,$1,'{}',$2,$3)",[
    client,client==='no-uri'?null:`https://${client}.example.invalid/backchannel/events`,client==='disabled'?new Date('2026-01-02T00:00:00Z'):null]);
  }
  for(const [index,client]of ['active-a','active-b','disabled','no-uri'].entries()){
   await db.query('INSERT INTO app_roles(client_id,role_id,name,level) VALUES($1,0,$2,0),($1,2,$3,10)',[client,'Owner','Member']);
   await db.query('INSERT INTO app_role_catalogs(client_id,default_role_id,last_sync_iat,synced_at) VALUES($1,$2,$3,$4)',[client,client==='active-b'?null:2,(index+1)*100,new Date('2026-01-03T00:00:00Z')]);
  }
  await db.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('member','active-a',0)");
  await db.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'active-a',NULL),($2,'active-a',999)",[users.overrideDeny,users.unknown]);
  await db.query('INSERT INTO processed_events(id,source,processed_at) VALUES($1,$2,$3)',[ids.processed,'active-a',new Date('2026-01-04T00:00:00Z')]);
  const rows=[
   {id:ids.delivered,client:'active-a',kind:'account.roles_change',payload:{sub:users.inherit,role_id:0},version:'17',status:'delivered',attempts:7,delivered:new Date('2026-01-08T00:00:00Z')},
   {id:ids.dead,client:'active-b',kind:'account.roles_change',payload:{sub:users.overrideDeny,role_id:null},version:'4',status:'dead',attempts:50,delivered:null},
   {id:ids.pending,client:'unmanaged',kind:'org.settings',payload:{site_name:'Synthetic pending name'},version:'0',status:'pending',attempts:3,delivered:null},
  ];
  for(const row of rows)await db.query(`INSERT INTO event_outbox(id,kind,target_client_id,payload,version,status,attempts,next_attempt_at,created_at,delivered_at)
    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,[row.id,row.kind,row.client,row.payload,row.version,row.status,row.attempts,
    new Date('2026-01-07T00:00:00Z'),new Date('2026-01-05T00:00:00Z'),row.delivered]);
  const preservedOutbox=(await oldOutbox()).rows,preservedInbox=(await oldInbox()).rows;
  const preservedCatalogs=(await db.query('SELECT * FROM app_role_catalogs ORDER BY client_id')).rows;
  const preservedOverrides=(await db.query('SELECT * FROM user_app_role_overrides ORDER BY user_sub')).rows;
  assert.equal(await primaryKey(),'PRIMARY KEY (id)');

  // Exercise the actual runner's transaction boundary: the migration creates
  // both request and destination rows, but a later transaction failure loses
  // neither half of the original schema/history and commits neither new half.
  await db.query('BEGIN');
  try{
   await db.query(migration);
   assert.equal((await db.query("SELECT count(*)::int AS n FROM event_outbox WHERE kind='roles.sync_request'")).rows[0].n,2);
   assert.equal((await db.query('SELECT count(*)::int AS n FROM event_destinations')).rows[0].n,3);
   await assert.rejects(db.query('SELECT 1/0'));
  }finally{await db.query('ROLLBACK');}
  for(const table of ['event_destinations','app_role_sync_state','app_role_effective'])assert.equal((await db.query('SELECT to_regclass($1) AS relation',[`${schema}.${table}`])).rows[0].relation,null);
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM information_schema.columns
    WHERE table_schema=$1 AND table_name='event_outbox' AND column_name IN('sequence','last_error_code','legacy_redis_member','legacy_redis_score')`,[schema])).rows[0].n,0);
  assert.equal((await db.query(`SELECT count(*)::int AS n FROM information_schema.columns
    WHERE table_schema=$1 AND table_name='processed_events' AND column_name IN('event_type','payload_digest')`,[schema])).rows[0].n,0);
  assert.equal(await primaryKey(),'PRIMARY KEY (id)');assert.deepEqual((await oldOutbox()).rows,preservedOutbox);assert.deepEqual((await oldInbox()).rows,preservedInbox);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM event_outbox')).rows[0].n,3);

  await apply();
  assert.equal(await primaryKey(),'PRIMARY KEY (source, id)');
  assert.deepEqual((await oldOutbox()).rows,preservedOutbox);assert.deepEqual((await oldInbox()).rows,preservedInbox);
  assert.deepEqual((await db.query('SELECT * FROM app_role_catalogs ORDER BY client_id')).rows,preservedCatalogs);
  assert.deepEqual((await db.query('SELECT * FROM user_app_role_overrides ORDER BY user_sub')).rows,preservedOverrides);
  assert.deepEqual((await db.query('SELECT event_type,payload_digest FROM processed_events WHERE id=$1',[ids.processed])).rows[0],{event_type:null,payload_digest:null});
  await db.query('INSERT INTO processed_events(source,id) VALUES($1,$2)',['active-b',ids.processed]);
  assert.equal((await db.query('SELECT count(*)::int AS n FROM processed_events WHERE id=$1',[ids.processed])).rows[0].n,2);
  const states=(await db.query('SELECT * FROM app_role_sync_state ORDER BY client_id')).rows;
  assert.deepEqual(states.map(row=>row.client_id),['active-a','active-b','disabled','no-uri']);
  assert.deepEqual(states.map(row=>row.last_sync_iat),['100','200','300','400']);
  assert.ok(states.every(row=>row.catalog_mode==='legacy'&&row.catalog_epoch===null&&row.catalog_revision===null&&row.catalog_digest===null&&row.authority_revision==='0'));
  assert.ok(states.every(row=>/^[0-9a-f-]{36}$/.test(row.authority_epoch)));assert.equal(new Set(states.map(row=>row.authority_epoch)).size,4);
  const ledger=(await db.query('SELECT * FROM app_role_effective ORDER BY client_id,user_sub')).rows;assert.equal(ledger.length,16);
  assert.ok(ledger.every(row=>row.managed===true&&row.authority_revision==='0'&&row.user_sub!==users.deleted));
  const values=Object.fromEntries(ledger.filter(row=>row.client_id==='active-a').map(row=>[row.user_sub,row.role_id]));
  assert.deepEqual(values,{[users.inherit]:2,[users.org]:0,[users.overrideDeny]:null,[users.unknown]:null});
  assert.ok(ledger.filter(row=>row.client_id==='active-b').every(row=>row.role_id===null));
  // Baseline emits no invented historical role changes or authority increments.
  assert.equal((await db.query("SELECT count(*)::int AS n FROM event_outbox WHERE kind='account.roles_change'")).rows[0].n,2);
  const requests=(await db.query("SELECT id,target_client_id,payload,status,version::text,attempts FROM event_outbox WHERE kind='roles.sync_request' ORDER BY target_client_id")).rows;
  assert.deepEqual(requests.map(row=>row.target_client_id),['active-a','active-b']);
  assert.ok(requests.every(row=>row.status==='pending'&&row.version==='0'&&row.attempts===0));
  assert.ok(requests.every(row=>JSON.stringify(row.payload)===JSON.stringify({reason:'role_event_consistency_upgrade'})));
  const destinations=(await db.query('SELECT client_id FROM event_destinations ORDER BY client_id')).rows.map(row=>row.client_id);
  assert.deepEqual(destinations,['active-a','active-b','unmanaged']);
  const sequences=(await db.query('SELECT id,sequence::text FROM event_outbox ORDER BY id')).rows;
  assert.equal(new Set(sequences.map(row=>row.sequence)).size,5);assert.ok(sequences.every(row=>BigInt(row.sequence)>0));
  await db.query("UPDATE event_outbox SET status='delivered',delivered_at=now() WHERE id=$1",[requests[0].id]);
  await apply();
  assert.deepEqual((await oldOutbox()).rows,preservedOutbox);assert.deepEqual((await oldInbox()).rows,preservedInbox);
  assert.deepEqual((await db.query('SELECT * FROM app_role_sync_state ORDER BY client_id')).rows,states);
  assert.deepEqual((await db.query('SELECT * FROM app_role_effective ORDER BY client_id,user_sub')).rows,ledger);
  assert.deepEqual((await db.query('SELECT id,sequence::text FROM event_outbox ORDER BY id')).rows,sequences);
  const repeated=(await db.query("SELECT id,target_client_id,status FROM event_outbox WHERE kind='roles.sync_request' ORDER BY target_client_id")).rows;
  assert.deepEqual(repeated,requests.map((row,index)=>({id:row.id,target_client_id:row.target_client_id,status:index===0?'delivered':'pending'})));
  assert.deepEqual((await db.query('SELECT client_id FROM event_destinations ORDER BY client_id')).rows.map(row=>row.client_id),destinations);
 }finally{
  await db.end().catch(()=>{});await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
 }
});


test('actual migration runner stamps successful work and strict failure rolls back before later files run',async()=>{
 const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
 if(!connectionString)throw Error('Use the isolated role-sync database fixture.');
 const url=new URL(connectionString);
 if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only the generated loopback fixture database is allowed.');
 const directory=await mkdtemp(join(tmpdir(),'sso-migration-runner-'));
 const schema='migration_runner_'+randomUUID().replaceAll('-','');
 const admin=new pg.Client({connectionString});await admin.connect();
 const database=new pg.Pool({connectionString,options:`-c search_path=${schema},public`,max:2});
 let appPool:pg.Pool|undefined;
 try{
  await admin.query(`CREATE SCHEMA ${schema}`);
  await writeFile(join(directory,'001-fixture-success.sql'),"CREATE TABLE migration_probe(id integer PRIMARY KEY,label text NOT NULL); INSERT INTO migration_probe VALUES(1,'committed');\n",{mode:0o600});
  // A pre-runner baseline must be stamped, not replayed. This SQL deliberately
  // fails if it is executed, without touching any real historical schema.
  await writeFile(join(directory,'sso-org-management-2.sql'),'SELECT nonexistent_baseline_fixture_function();\n',{mode:0o600});
  // MIGRATIONS_DIR is captured once at module import. Set it before the first
  // import in this test worker; dotenv reads /dev/null, never an application env.
  process.env.MIGRATIONS_DIR=directory;process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.DATABASE_URL=connectionString;
  const {runMigrations}=await import('../src/db/migrations.js');
  appPool=(await import('../src/db.js')).pool;
  assert.deepEqual(await runMigrations({strict:true,pool:database}),{applied:['001-fixture-success.sql'],baselined:['sso-org-management-2.sql']});
  assert.deepEqual((await database.query('SELECT * FROM migration_probe ORDER BY id')).rows,[{id:1,label:'committed'}]);
  const originalStamps=(await database.query('SELECT filename,applied_at FROM schema_migrations ORDER BY filename')).rows;
  assert.deepEqual(await runMigrations({strict:true,pool:database}),{applied:[],baselined:[]});
  assert.deepEqual((await database.query('SELECT filename,applied_at FROM schema_migrations ORDER BY filename')).rows,originalStamps);

  await writeFile(join(directory,'002-fixture-failure.sql'),"INSERT INTO migration_probe VALUES(2,'must roll back'); CREATE TABLE partial_probe(id integer); SELECT 1/0;\n",{mode:0o600});
  await writeFile(join(directory,'003-fixture-after.sql'),"INSERT INTO migration_probe VALUES(3,'after repair');\n",{mode:0o600});
  await assert.rejects(runMigrations({strict:true,pool:database}),/migration 002-fixture-failure\.sql failed: division by zero/);
  assert.deepEqual((await database.query('SELECT * FROM migration_probe ORDER BY id')).rows,[{id:1,label:'committed'}]);
  assert.equal((await database.query('SELECT to_regclass($1) AS relation',[`${schema}.partial_probe`])).rows[0].relation,null);
  assert.deepEqual((await database.query('SELECT filename,applied_at FROM schema_migrations ORDER BY filename')).rows,originalStamps);
  // Failed migrations remain eligible for a repaired rerun, and only then may
  // later migrations execute. The failed attempt never creates a success stamp.
  await writeFile(join(directory,'002-fixture-failure.sql'),"INSERT INTO migration_probe VALUES(2,'repaired');\n",{mode:0o600});
  assert.deepEqual(await runMigrations({strict:true,pool:database}),{applied:['002-fixture-failure.sql','003-fixture-after.sql'],baselined:[]});
  assert.deepEqual((await database.query('SELECT * FROM migration_probe ORDER BY id')).rows,[{id:1,label:'committed'},{id:2,label:'repaired'},{id:3,label:'after repair'}]);
  assert.deepEqual((await database.query('SELECT filename FROM schema_migrations ORDER BY filename')).rows.map(row=>row.filename),
    ['001-fixture-success.sql','002-fixture-failure.sql','003-fixture-after.sql','sso-org-management-2.sql']);
  // The captured migration directory must remain available at strict startup.
  // Removing this owned fixture directory exercises the actual readdir error,
  // rather than mocking a directory listing or claiming a listener was started.
  const completedStamps=(await database.query('SELECT filename,applied_at FROM schema_migrations ORDER BY filename')).rows;
  await rm(directory,{recursive:true,force:true});
  await assert.rejects(runMigrations({strict:true,pool:database}),/Migration directory is unavailable\./);
  assert.deepEqual((await database.query('SELECT filename,applied_at FROM schema_migrations ORDER BY filename')).rows,completedStamps);
  assert.deepEqual(await runMigrations({strict:false,pool:database}),{applied:[],baselined:[]});
 }finally{
  await database.end();await appPool?.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();await rm(directory,{recursive:true,force:true});
 }
});
