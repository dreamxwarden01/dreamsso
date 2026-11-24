import test from 'node:test';
import assert from 'node:assert/strict';
import {randomUUID,randomBytes,createHash} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';

test('SQL email operations fence stale proofs and preserve final identity uniqueness in isolated PostgreSQL/Redis',async t=>{
 const source=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL,redisSource=process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
 if(!source||!redisSource)throw Error('Generated local PostgreSQL and Redis fixtures are mandatory.');
 const url=new URL(source),redisUrl=new URL(redisSource);
 if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test'||redisUrl.hostname!=='127.0.0.1'||redisUrl.pathname!=='/15')throw Error('Only generated loopback fixtures are allowed.');
 const schema='email_operations_'+randomUUID().replaceAll('-','');
 const admin=new pg.Pool({connectionString:source,max:2});
 const database=new pg.Pool({connectionString:source,max:6,options:`-c search_path=${schema},public`,application_name:schema,connectionTimeoutMillis:5000});
 url.searchParams.set('options',`-c search_path=${schema},public`);
 process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.DATABASE_URL=url.href;process.env.REDIS_URL=redisSource;
 process.env.KEY_ENCRYPTION_KEY=randomBytes(32).toString('hex');process.env.ISSUER='https://email-operations.example.invalid';
 const {pool:defaultPool}=await import('../src/db.js'),{redis}=await import('../src/redis.js');
 const {getEmailChangeState,issueEmailChange,resendEmailChange,cancelEmailChange,completeEmailChange,sweepEmailChanges,assertEmailChangeSchema,EmailChangeError}=await import('../src/emailChange.js');
 const {openSecret}=await import('../src/secretbox.js');
 const {identityConflict}=await import('../src/identityConflicts.js');
 const owned=new Set<string>();let created=false;
 const hash=(token:string)=>createHash('sha256').update(token).digest();
 const mailbox=()=>`email-operation-${randomUUID()}@example.invalid`;
 const own=(key:string)=>{owned.add(key);return key;};
 const clearLimit=async(email:string)=>{await redis.del(own('reg:rl:'+email.toLowerCase()));};
 const denied=(code:string,status?:number)=>(error:unknown)=>error instanceof EmailChangeError&&error.code===code&&(status===undefined||error.status===status);
 const user=async(options:{email?:string|null;verified?:boolean}={})=>{
  const sub=randomUUID(),email=options.email===undefined?mailbox():options.email;
  await database.query(`INSERT INTO identities(sub,username,display_name,email,email_verified,password_hash)
    VALUES($1,$2,'Fixture user',$3,$4,'synthetic-original-password-hash')`,[sub,'mail_'+sub.slice(0,12),email,options.verified??true]);
  await database.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'email-member')",[sub]);
  return{sub,email};
 };
 const state=(sub:string)=>getEmailChangeState(sub,database);
 const issue=async(sub:string,target=mailbox(),kind:'change'|'confirm'='change',input?:{requestId:string;expectedRevision:string})=>{
  own('reg:rl:'+target.trim().toLowerCase());
  const request=input??{requestId:randomUUID(),expectedRevision:(await state(sub))!.revision};
  return{...(await issueEmailChange(sub,kind,target,request,database)),initialRevision:request.expectedRevision};
 };
 const operation=async(sub:string)=>(await database.query('SELECT * FROM email_change_operations WHERE user_sub=$1',[sub])).rows[0];
 const auditCount=async(sub:string)=>(await database.query("SELECT count(*)::int AS n FROM org_audit_log WHERE actor_sub=$1 AND action IN('email.change','email.verify')",[sub])).rows[0].n;
 const identity=async(sub:string)=>(await database.query('SELECT email,email_verified,email_change_revision::text AS revision FROM identities WHERE sub=$1',[sub])).rows[0];
 const checkUntil=async(check:()=>Promise<boolean>,message:string)=>{
  const deadline=Date.now()+2500;while(!(await check())){if(Date.now()>deadline)throw Error(message);await new Promise(resolve=>setTimeout(resolve,5));}
 };
 try{
  await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
  await admin.query(`CREATE SCHEMA ${schema}`);created=true;
  await database.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
  await database.query("INSERT INTO org_roles(slug,label,level) VALUES('email-member','Fixture member',100)");
  for(const permission of ['profile.email.add','profile.email.change'])await database.query("INSERT INTO role_permissions(role_slug,perm_key,effect) VALUES('email-member',$1,'grant')",[permission]);

  await t.test('real citext uniqueness reports exact email/username index names for case variants',async()=>{
   const original=await user(),username=(await database.query('SELECT username FROM identities WHERE sub=$1',[original.sub])).rows[0].username;
   for(const [field,constraint] of [['email','uq_identities_email'],['username','uq_identities_username']] as const){
    await assert.rejects(database.query(`INSERT INTO identities(sub,username,display_name,email) VALUES($1,$2,'Fixture collision',$3)`,
     [randomUUID(),field==='username'?username.toUpperCase():'unique_'+randomUUID().slice(0,8),field==='email'?original.email!.toUpperCase():mailbox()]),
     (error:unknown)=>{const sql=error as {code?:string;constraint?:string};return sql.code==='23505'&&sql.constraint===constraint&&identityConflict(error)===field;});
   }
  });

  await t.test('the same request UUID is owner-scoped and case-normalized, not a cross-user reservation',async()=>{
   const a=await user(),b=await user(),requestId=randomUUID();
   const first=await issue(a.sub,mailbox(),'change',{requestId:requestId.toUpperCase(),expectedRevision:(await state(a.sub))!.revision});
   const second=await issue(b.sub,mailbox(),'change',{requestId,expectedRevision:(await state(b.sub))!.revision});
   assert.equal(first.requestId,requestId);assert.equal(second.requestId,requestId);
   assert.equal((await database.query('SELECT count(*)::int AS n FROM email_change_operations WHERE request_id=$1',[requestId])).rows[0].n,2);
   await clearLimit(first.newEmail);
   await assert.rejects(issueEmailChange(a.sub,'change',first.newEmail,{requestId,expectedRevision:first.revision},database),denied('email_change_changed',409));
   const retry=await issueEmailChange(a.sub,'change',first.newEmail,{requestId:requestId.toUpperCase(),expectedRevision:first.initialRevision},database);
   assert.equal(retry.requestId,requestId);assert.equal(retry.reused,true);assert.ok(retry.token===first.token);
  });

  await t.test('same-ID replay rechecks current target occupancy before charging shared mail quota',async()=>{
   const u=await user(),first=await issue(u.sub),before=await operation(u.sub),key=own('reg:rl:'+first.newEmail);
   const beforeQuota=await redis.hgetall(key);assert.ok(Object.keys(beforeQuota).length>0);
   await user({email:first.newEmail.toUpperCase()});
   await assert.rejects(issueEmailChange(u.sub,'change',first.newEmail,{requestId:first.requestId,expectedRevision:first.initialRevision},database),denied('email_taken',409));
   assert.deepEqual(await redis.hgetall(key),beforeQuota);
   const after=await operation(u.sub);assert.deepEqual(after,before);assert.equal(await auditCount(u.sub),0);
  });

  await t.test('disabled invalidation trigger fails schema admission and completion rolls back with503',async()=>{
   const u=await user(),pending=await issue(u.sub),before=await operation(u.sub);
   await assertEmailChangeSchema(database);
   await database.query('ALTER TABLE identities DISABLE TRIGGER trg_identity_email_operation');
   try{
    await assert.rejects(assertEmailChangeSchema(database),/email_operation_trigger_unavailable/);
    await assert.rejects(completeEmailChange(pending.token,database),denied('email_change_unavailable',503));
    assert.deepEqual(await operation(u.sub),before);
    assert.equal((await identity(u.sub)).email,u.email);assert.equal((await identity(u.sub)).revision,pending.revision);
    assert.equal(await auditCount(u.sub),0);
   }finally{await database.query('ALTER TABLE identities ENABLE TRIGGER trg_identity_email_operation');}
   await assertEmailChangeSchema(database);assert.equal((await completeEmailChange(pending.token,database)).replayed,false);
  });

  await t.test('issue encrypts the new proof; public state is coherent and legacy Redis cannot authorize',async()=>{
   const u=await user(),target=mailbox(),legacy=randomBytes(32).toString('base64url');
   const legacyHash=hash(legacy).toString('hex'),now=Math.floor(Date.now()/1000);
   await redis.set(own('emailchg:user:'+u.sub),legacyHash,'EX',1800);
   await redis.set(own('emailchg:tok:'+legacyHash),JSON.stringify({sub:u.sub,token:legacy,newEmail:target,kind:'change',createdAt:now,lastSent:now}),'EX',1800);
   await redis.set(own('emailchg:addr:'+target),u.sub,'EX',1800);
   const before=await state(u.sub);assert.equal(before!.pending,null);
   await assert.rejects(completeEmailChange(legacy,database),denied('invalid_token',422));
   const pending=await issue(u.sub,target),row=await operation(u.sub),current=await state(u.sub);
   assert.match(pending.token,/^ec1\.[A-Za-z0-9_-]{43}$/);assert.ok(Buffer.isBuffer(row.token_enc));
   assert.ok(openSecret(row.token_enc)===pending.token);assert.ok(row.token_hash.equals(hash(pending.token)));
   assert.equal(row.token_enc.includes(Buffer.from(pending.token)),false);
   assert.equal(current!.revision,pending.revision);assert.equal(current!.pending!.request_id,pending.requestId);
   assert.equal(current!.pending!.new_email,target);assert.equal(current!.pending!.expires_at,pending.expiresAt);
   assert.equal(JSON.stringify(current).includes(pending.token),false);
   assert.equal(JSON.stringify(current).includes('token_hash'),false);assert.equal(JSON.stringify(current).includes('token_enc'),false);
  });

  await t.test('cancel and replacement use exact request/revision; stale IDs or fresh IDs with stale revision cannot resurrect',async()=>{
   const u=await user(),first=await issue(u.sub);await cancelEmailChange(u.sub,first.requestId,database);
   const cancelled=await state(u.sub);assert.equal(cancelled!.pending,null);assert.ok(BigInt(cancelled!.revision)>BigInt(first.revision));
   await clearLimit(first.newEmail);
   for(const requestId of [first.requestId,randomUUID()])await assert.rejects(issueEmailChange(u.sub,'change',first.newEmail,
    {requestId,expectedRevision:first.initialRevision},database),denied('email_change_changed',409));
   const replacement=await issue(u.sub);assert.notEqual(replacement.requestId,first.requestId);
   await assert.rejects(cancelEmailChange(u.sub,first.requestId,database),denied('email_change_changed',409));
   await assert.rejects(resendEmailChange(u.sub,first.requestId,database),denied('email_change_changed',409));
   await assert.rejects(completeEmailChange(first.token,database),denied('invalid_token',422));
   assert.equal((await state(u.sub))!.pending!.request_id,replacement.requestId);
  });

  await t.test('identity trigger fences admin ABA/target assignment/clear/verification/status/deletion/password changes',async()=>{
   for(const kind of ['aba','target','clear','verified','status','deleted','password']){
    const u=await user(),pending=await issue(u.sub);
    if(kind==='aba'){await database.query('UPDATE identities SET email=$2 WHERE sub=$1',[u.sub,mailbox()]);await database.query('UPDATE identities SET email=$2 WHERE sub=$1',[u.sub,u.email]);}
    if(kind==='target')await database.query('UPDATE identities SET email=$2,email_verified=false WHERE sub=$1',[u.sub,pending.newEmail]);
    if(kind==='clear')await database.query('UPDATE identities SET email=NULL,email_verified=false WHERE sub=$1',[u.sub]);
    if(kind==='verified')await database.query('UPDATE identities SET email_verified=false WHERE sub=$1',[u.sub]);
    if(kind==='status'){await database.query("UPDATE identities SET status='disabled' WHERE sub=$1",[u.sub]);await database.query("UPDATE identities SET status='active' WHERE sub=$1",[u.sub]);}
    if(kind==='deleted')await database.query('UPDATE identities SET deleted_at=clock_timestamp() WHERE sub=$1',[u.sub]);
    if(kind==='password')await database.query("UPDATE identities SET password_hash='synthetic-replacement-password-hash',password_changed_at=clock_timestamp() WHERE sub=$1",[u.sub]);
    assert.equal(await operation(u.sub),undefined,kind);assert.ok(BigInt((await identity(u.sub)).revision)>BigInt(pending.revision),kind);
    await assert.rejects(completeEmailChange(pending.token,database),denied('invalid_token',422));
    if(kind==='target')assert.equal((await identity(u.sub)).email_verified,false);
   }
  });

  await t.test('resend and same-start retry reuse the proof without extending its absolute deadline; expired operations cannot act',async()=>{
   const u=await user(),first=await issue(u.sub),before=await operation(u.sub);
   await clearLimit(first.newEmail);const resend=await resendEmailChange(u.sub,first.requestId,database);
   assert.ok(resend.token===first.token);assert.equal(resend.expiresAt,first.expiresAt);
   await clearLimit(first.newEmail);const retry=await issueEmailChange(u.sub,'change',first.newEmail,{requestId:first.requestId,expectedRevision:first.initialRevision},database);
   assert.equal(retry.reused,true);assert.ok(retry.token===first.token);assert.equal(retry.expiresAt,first.expiresAt);assert.equal(retry.revision,first.revision);
   const after=await operation(u.sub);assert.deepEqual(after.created_at,before.created_at);assert.deepEqual(after.expires_at,before.expires_at);
   await database.query("UPDATE email_change_operations SET created_at=clock_timestamp()-interval '31 minutes',expires_at=clock_timestamp()-interval '1 second' WHERE user_sub=$1",[u.sub]);
   await assert.rejects(resendEmailChange(u.sub,first.requestId,database),denied('no_pending',404));
   await assert.rejects(completeEmailChange(first.token,database),denied('invalid_token',422));
   assert.equal((await state(u.sub))!.pending,null);await sweepEmailChanges(database);assert.equal(await operation(u.sub),undefined);
  });

  await t.test('a real late SQL email uniqueness violation rolls back trigger consumption, then the same proof can retry',async()=>{
   const u=await user(),pending=await issue(u.sub),before=await operation(u.sub),revision=(await identity(u.sub)).revision;
   // This BEFORE UPDATE fixture creates a competing identity after available()
   // passed. The real index, mapper and transaction rollback arbitrate the write.
   await database.query(`CREATE FUNCTION inject_email_conflict() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.sub='${u.sub}'::uuid AND NEW.email IS DISTINCT FROM OLD.email THEN
      INSERT INTO identities(sub,username,display_name,email) VALUES(gen_random_uuid(),'late-conflict-fixture','Fixture collision',upper(NEW.email::text));
    END IF; RETURN NEW; END $$;
    CREATE TRIGGER zzz_inject_email_conflict BEFORE UPDATE OF email ON identities FOR EACH ROW EXECUTE FUNCTION inject_email_conflict()`);
   try{await assert.rejects(completeEmailChange(pending.token,database),denied('email_taken',409));}
   finally{await database.query('DROP TRIGGER zzz_inject_email_conflict ON identities; DROP FUNCTION inject_email_conflict()');}
   const restored=await operation(u.sub);assert.ok(restored.token_hash.equals(before.token_hash));assert.ok(restored.token_enc);assert.equal(restored.completed_at,null);
   assert.equal((await identity(u.sub)).email,u.email);assert.equal((await identity(u.sub)).revision,revision);assert.equal(await auditCount(u.sub),0);
   const completed=await completeEmailChange(pending.token,database);assert.equal(completed.replayed,false);assert.equal((await identity(u.sub)).email,pending.newEmail);
  });

  await t.test('different users may hold the same target; concurrent completion has exactly one final owner',async()=>{
   const a=await user(),b=await user(),target=mailbox(),first=await issue(a.sub,target);
   // Quota is a separate policy; clear only this fixture key to reach the
   // intended duplicate-pending/concurrent-final-ownership scenario immediately.
   await clearLimit(target);const second=await issue(b.sub,target);
   assert.equal((await database.query('SELECT count(*)::int AS n FROM email_change_operations WHERE new_email=$1 AND completed_at IS NULL',[target])).rows[0].n,2);
   const results=await Promise.allSettled([completeEmailChange(first.token,database),completeEmailChange(second.token,database)]);
   assert.equal(results.filter(result=>result.status==='fulfilled').length,1);
   const failure=results.find(result=>result.status==='rejected') as PromiseRejectedResult;assert.ok(denied('email_taken',409)(failure.reason));
   assert.equal((await database.query('SELECT count(*)::int AS n FROM identities WHERE email=$1 AND deleted_at IS NULL',[target.toUpperCase()])).rows[0].n,1);
   const loser=results[0].status==='rejected'?a:b;assert.equal((await operation(loser.sub)).completed_at,null);
  });

  await t.test('duplicate/lost-reply completion returns one receipt, one revision change and one audit',async()=>{
   const u=await user(),pending=await issue(u.sub);
   const result=await Promise.all([completeEmailChange(pending.token,database),completeEmailChange(pending.token,database)]);
   assert.equal(result.filter(item=>!item.replayed).length,1);assert.equal(result.filter(item=>item.replayed).length,1);
   assert.equal((await identity(u.sub)).revision,(BigInt(pending.revision)+1n).toString());assert.equal(await auditCount(u.sub),1);
   assert.equal((await operation(u.sub)).token_enc,null);
   await assert.rejects(cancelEmailChange(u.sub,pending.requestId,database),denied('no_pending',404));
   assert.equal((await completeEmailChange(pending.token,database)).replayed,true);assert.equal(await auditCount(u.sub),1);
   await database.query("UPDATE email_change_operations SET completed_at=clock_timestamp()-interval '11 minutes' WHERE user_sub=$1",[u.sub]);
   await assert.rejects(completeEmailChange(pending.token,database),denied('invalid_token',422));await sweepEmailChanges(database);assert.equal(await operation(u.sub),undefined);
  });

  await t.test('a transient audit failure rolls back email/revision/receipt and preserves the pending proof',async()=>{
   const u=await user(),pending=await issue(u.sub),before=await operation(u.sub);
   await database.query(`CREATE FUNCTION reject_email_audit() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.actor_sub='${u.sub}'::uuid AND NEW.action='email.change' THEN RAISE EXCEPTION 'synthetic email audit failure'; END IF; RETURN NEW; END $$;
    CREATE TRIGGER reject_email_audit BEFORE INSERT ON org_audit_log FOR EACH ROW EXECUTE FUNCTION reject_email_audit()`);
   try{await assert.rejects(completeEmailChange(pending.token,database),(error:unknown)=>(error as {code?:string}).code==='P0001');}
   finally{await database.query('DROP TRIGGER reject_email_audit ON org_audit_log; DROP FUNCTION reject_email_audit()');}
   const restored=await operation(u.sub);assert.ok(restored.token_hash.equals(before.token_hash));assert.equal(restored.completed_at,null);
   assert.equal((await identity(u.sub)).email,u.email);assert.equal((await identity(u.sub)).revision,pending.revision);assert.equal(await auditCount(u.sub),0);
   assert.equal((await completeEmailChange(pending.token,database)).replayed,false);assert.equal(await auditCount(u.sub),1);
  });

  await t.test('expiry while the actual identity UPDATE is blocked rolls back the write and trigger deletion',async()=>{
   const u=await user(),pending=await issue(u.sub),holder=await database.connect();
   const delayLock=927400912;
   await database.query(`CREATE FUNCTION gate_email_update() RETURNS trigger LANGUAGE plpgsql AS $$
    BEGIN IF NEW.sub='${u.sub}'::uuid AND NEW.email IS DISTINCT FROM OLD.email THEN PERFORM pg_advisory_xact_lock(${delayLock}::bigint); END IF; RETURN NEW; END $$;
    CREATE TRIGGER zzz_gate_email_update BEFORE UPDATE OF email ON identities FOR EACH ROW EXECUTE FUNCTION gate_email_update()`);
   let attempt:Promise<unknown>|undefined,rejected:Promise<void>|undefined;
   try{
    await holder.query('BEGIN');await holder.query('SELECT pg_advisory_xact_lock($1::bigint)',[delayLock]);
    const {rows:[deadline]}=await database.query("UPDATE email_change_operations SET created_at=clock_timestamp()-interval '29 minutes',expires_at=clock_timestamp()+interval '700 milliseconds' WHERE user_sub=$1 RETURNING expires_at",[u.sub]);
    attempt=completeEmailChange(pending.token,database);rejected=assert.rejects(attempt,denied('invalid_token',422));
    // Register a rejection handler now as well as awaiting below: a failed gate
    // synchronization must still release the fixture lock without an unhandled promise.
    void rejected.catch(()=>{});
    await checkUntil(async()=>!!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory' AND query LIKE 'UPDATE identities SET email=%'",[schema])).rowCount,'Completion did not reach the actual UPDATE gate.');
    await checkUntil(async()=>!!(await admin.query('SELECT 1 WHERE clock_timestamp()>$1::timestamptz',[deadline.expires_at])).rowCount,'Fixture deadline did not pass.');
    await holder.query('COMMIT');await rejected;
   }finally{await holder.query('ROLLBACK').catch(()=>{});holder.release();await attempt?.catch(()=>{});await rejected?.catch(()=>{});await database.query('DROP TRIGGER zzz_gate_email_update ON identities; DROP FUNCTION gate_email_update()');}
   assert.equal((await identity(u.sub)).email,u.email);assert.equal((await identity(u.sub)).revision,pending.revision);
   assert.equal((await operation(u.sub)).completed_at,null);assert.equal(await auditCount(u.sub),0);
  });

  await t.test('add and confirm-current paths use the same SQL-authoritative generation and completed receipt',async()=>{
   const missing=await user({email:null,verified:false}),added=await issue(missing.sub);await completeEmailChange(added.token,database);
   assert.equal((await identity(missing.sub)).email,added.newEmail);assert.equal((await identity(missing.sub)).email_verified,true);
   const unverified=await user({verified:false}),confirmation=await issue(unverified.sub,unverified.email!,'confirm');
   const result=await completeEmailChange(confirmation.token,database);assert.equal(result.kind,'confirm');assert.equal(result.oldEmail,null);
   assert.equal((await identity(unverified.sub)).email,unverified.email);assert.equal((await identity(unverified.sub)).email_verified,true);
   assert.equal((await completeEmailChange(confirmation.token,database)).replayed,true);assert.equal(await auditCount(unverified.sub),1);
  });

  await t.test('migration007 replays safely without resetting revision, pending token or fixed deadline',async()=>{
   const u=await user(),pending=await issue(u.sub),before=await state(u.sub),migration=await readFile(new URL('../db/migrations/007-email-change-operations.sql',import.meta.url),'utf8');
   await database.query(migration);await database.query(migration);
   const after=await state(u.sub);assert.deepEqual(after,before);assert.equal(after!.pending!.expires_at,pending.expiresAt);
   assert.equal((await completeEmailChange(pending.token,database)).replayed,false);
  });
 }finally{
  try{if(owned.size)await redis.del(...owned);}finally{await redis.quit().catch(()=>{});redis.disconnect();}
  await database.end();await defaultPool.end();if(created)await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
 }
});
