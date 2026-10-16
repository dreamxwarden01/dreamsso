import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {randomUUID} from 'node:crypto';
import pg from 'pg';
import {SigningKeyRotation,SigningKeyStateError,type SigningKeyMaterial} from '../src/signingKeyRotation.js';

test('signing rotation publishes before arming and serializes activation using PostgreSQL time',async t=>{
  const connectionString=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if(!connectionString)throw Error('An isolated database fixture is required.');
  const url=new URL(connectionString);
  if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only the generated local fixture is allowed.');
  const schema='key_rotation_'+randomUUID().replaceAll('-','');
  const admin=new pg.Pool({connectionString,max:2}),database=new pg.Pool({connectionString,max:10,options:`-c search_path=${schema},public`});
  const migration=await readFile(new URL('../db/migrations/002-staged-signing-keys.sql',import.meta.url),'utf8');
  let generated=0;
  const generate=async():Promise<SigningKeyMaterial>=>{const kid='synthetic-'+(++generated);return{kid,alg:'EdDSA',publicJwk:{kty:'OKP',crv:'Ed25519',x:'synthetic-public',kid},privateKeyEnc:Buffer.from('synthetic-sealed-key')};};
  const store=()=>new SigningKeyRotation(database,generate);
  try{
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query(`CREATE TABLE signing_keys(kid text PRIMARY KEY,alg text NOT NULL DEFAULT 'EdDSA',public_jwk jsonb NOT NULL,
      private_key_enc bytea NOT NULL,status text NOT NULL DEFAULT 'next' CHECK(status IN('current','next','retired')),
      created_at timestamptz NOT NULL DEFAULT now(),activated_at timestamptz,retired_at timestamptz)`);
    await database.query(migration);await database.query(migration);
    await t.test('concurrent initial selection bootstraps once',async()=>{
      const values=await Promise.all(Array.from({length:6},()=>store().current()));
      assert.equal(generated,1);assert.equal(new Set(values.map(x=>x.kid)).size,1);
    });
    const old=(await store().current()).kid;
    await t.test('stage commit visibility precedes the marker and leaves old signer active',async()=>{
      let commits=0,visibleAt=0,observedUnarmed=false;
      const wrapped={query:database.query.bind(database),connect:async()=>{
        const db=await database.connect(),query=db.query.bind(db);
        return{query:async(sql:string,args?:unknown[])=>{
          const result=await query(sql,args);
          if(sql==='COMMIT'&&++commits===1){
            const snapshot=(await database.query("SELECT published_at,activate_after,clock_timestamp() AS at FROM signing_keys WHERE status='next'")).rows[0];
            observedUnarmed=snapshot.published_at===null&&snapshot.activate_after===null;visibleAt=snapshot.at.getTime();
            await new Promise(resolve=>setTimeout(resolve,75));
          }
          return result;
        },release:()=>db.release()};
      }} as unknown as pg.Pool;
      const status=await new SigningKeyRotation(wrapped,generate).schedule();
      assert.equal(observedUnarmed,true);assert.equal(status.kid,old);assert.equal(status.state,'pending');
      assert.ok(Date.parse(status.rotation!.published_at!)>=visibleAt);
      assert.ok(Date.parse(status.rotation!.activate_after!)-Date.parse(status.rotation!.published_at!)>=300000);
    });
    const first=(await store().status()).rotation!;
    await t.test('concurrent repeats preserve exactly one pending operation',async()=>{
      const values=await Promise.all(Array.from({length:6},()=>store().schedule()));
      assert.equal(generated,2);assert.ok(values.every(x=>x.rotation?.id===first.id&&x.rotation.kid===first.kid));
      assert.equal((await store().current()).kid,old);
      await assert.rejects(database.query(`INSERT INTO signing_keys(kid,public_jwk,private_key_enc,status,rotation_id)
        VALUES('extra','{}','x','next',$1)`,[randomUUID()]),e=>(e as {code:string}).code==='23505');
    });
    await t.test('due activation happens once, retirement time starts then',async()=>{
      await database.query("UPDATE signing_keys SET published_at=clock_timestamp()-interval '301 seconds',activate_after=clock_timestamp()-interval '1 second' WHERE status='next'");
      const values=await Promise.all(Array.from({length:6},()=>store().current()));
      assert.ok(values.every(x=>x.kid===first.kid));assert.equal(generated,2);
      const retired=(await database.query("SELECT retired_at,clock_timestamp()-retired_at<interval '10 seconds' AS recent FROM signing_keys WHERE kid=$1",[old])).rows[0];
      assert.equal(retired.recent,true);assert.ok(retired.retired_at instanceof Date);
    });
    await t.test('a crash after stage commit recovers same public key with a fresh arm window',async()=>{
      let connections=0;
      const crash={query:database.query.bind(database),connect:async()=>{if(++connections===2)throw Error('synthetic marker interruption');return database.connect();}} as unknown as pg.Pool;
      await assert.rejects(new SigningKeyRotation(crash,generate).schedule(),/synthetic marker interruption/);
      const pending=(await database.query("SELECT kid,rotation_id,published_at,activate_after FROM signing_keys WHERE status='next'")).rows[0];
      assert.equal(pending.published_at,null);assert.equal(pending.activate_after,null);
      const status=await store().status();assert.equal(status.kid,first.kid);assert.equal(status.rotation!.kid,pending.kid);assert.equal(status.rotation!.id,pending.rotation_id);
      assert.ok(Date.parse(status.rotation!.activate_after!)>Date.now()+295000);assert.equal(generated,3);
    });
    await t.test('failed reconciliation keeps signing on freshly read durable authority; status exposes the error',async()=>{
      await database.query("UPDATE signing_keys SET published_at=NULL,activate_after=NULL WHERE status='next'");
      const failing={query:database.query.bind(database),connect:async()=>{throw Error('synthetic_lock_failure');}} as unknown as pg.Pool;
      assert.equal((await new SigningKeyRotation(failing,generate).current()).kid,first.kid);
      await assert.rejects(new SigningKeyRotation(failing,generate).status(),/synthetic_lock_failure/);
    });
    await t.test('unknown marker commit acknowledgment does not create another key',async()=>{
      await database.query("UPDATE signing_keys SET published_at=NULL,activate_after=NULL WHERE status='next'");
      let firstCommit=true;
      const uncertain={query:database.query.bind(database),connect:async()=>{
        const db=await database.connect(),query=db.query.bind(db);
        return{query:async(sql:string,args?:unknown[])=>{const result=await query(sql,args);if(sql==='COMMIT'&&firstCommit){firstCommit=false;throw Error('synthetic lost ACK');}return result;},release:()=>db.release()};
      }} as unknown as pg.Pool;
      await assert.rejects(new SigningKeyRotation(uncertain,generate).status(),/synthetic lost ACK/);
      const status=await store().status();assert.equal(status.state,'pending');assert.equal(generated,3);assert.equal(status.kid,first.kid);
    });
    await t.test('missing current with retained history never regenerates a replacement',async()=>{
      await database.query("DELETE FROM signing_keys WHERE status='next'");
      await database.query("UPDATE signing_keys SET status='retired',retired_at=clock_timestamp() WHERE status='current'");
      await assert.rejects(store().current(),e=>e instanceof SigningKeyStateError);assert.equal(generated,3);
    });
    await t.test('migration refuses pre-existing duplicate signers or unmanaged pending keys',async()=>{
      for(const statuses of [['current','current'],['next']]){
        const db=await admin.connect();
        try{
          await db.query('BEGIN');await db.query(`CREATE SCHEMA ${schema}_invalid`);
          await db.query(`SET LOCAL search_path=${schema}_invalid,public`);
          await db.query(`CREATE TABLE signing_keys(kid text PRIMARY KEY,alg text NOT NULL DEFAULT 'EdDSA',public_jwk jsonb NOT NULL,
            private_key_enc bytea NOT NULL,status text NOT NULL DEFAULT 'next',created_at timestamptz NOT NULL DEFAULT now(),activated_at timestamptz,retired_at timestamptz)`);
          for(let i=0;i<statuses.length;i++)await db.query("INSERT INTO signing_keys(kid,public_jwk,private_key_enc,status) VALUES($1,'{}','synthetic',$2)",['old-'+i,statuses[i]]);
          await assert.rejects(db.query(migration),error=>['23505','23514'].includes((error as {code:string}).code));
        }finally{await db.query('ROLLBACK');db.release();}
      }
    });
  }finally{await database.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();}
});
