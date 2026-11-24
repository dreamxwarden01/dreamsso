import test from 'node:test';
import assert from 'node:assert/strict';
import {randomBytes,randomUUID} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';

// Dedicated generated native fixtures only. No runtime server/mail provider is started.
test('registered email ownership gates new invitation work without reserving unregistered addresses',async t=>{
 const source=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
 if(!source)throw Error('An isolated database is required.');
 const url=new URL(source);
 if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only generated local fixtures are allowed.');
 const redisSource=process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
 if(!redisSource)throw Error('An isolated Redis fixture is required.');
 const redisUrl=new URL(redisSource);
 if(redisUrl.hostname!=='127.0.0.1'||redisUrl.pathname!=='/15')throw Error('Only generated local Redis fixtures are allowed.');
 const schema='invite_email_'+randomUUID().replaceAll('-',''),owner=randomUUID();
 const admin=new pg.Pool({connectionString:source,max:2});
 await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
 await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
 await admin.query(`CREATE SCHEMA ${schema}`);
 url.searchParams.set('options',`-c search_path=${schema},public`);
 process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.DATABASE_URL=url.href;process.env.REDIS_URL=redisSource;
 process.env.KEY_ENCRYPTION_KEY=randomBytes(32).toString('hex');
 const {pool}=await import('../src/db.js'),{redis}=await import('../src/redis.js');
 const {withRoleTransaction}=await import('../src/rbac/roleChanges.js');
 const {createInvitation,requestInvitationResend,lockInvitation,InvitationError}=await import('../src/invitations.js');
 const {queueInvitationMail,dispatchInvitationMailJob,settleInvitationMail}=await import('../src/invitationMail.js');
 let sequence=0;const ownedEmails=new Set<string>();
 const mailbox=()=>{const address=`fixture-${++sequence}-${randomUUID().slice(0,8)}@example.invalid`;ownedEmails.add(address);return address;};
 const tx=<T>(work:(db:pg.PoolClient)=>Promise<T>)=>withRoleTransaction(work,pool);
 const input=(email:string|null,extra:Record<string,unknown>={})=>({request_id:randomUUID(),role_slug:'member',delivery:'link',email,...extra});
 const create=async(email:string|null,extra:Record<string,unknown>={})=>(await tx(db=>createInvitation(db,owner,input(email,extra)))).invitation;
 const account=async(email:string,status='active',deleted=false)=>{
  const sub=randomUUID(),username='fixture_'+(++sequence);
  await pool.query(`INSERT INTO identities(sub,username,display_name,email,status,deleted_at)
    VALUES($1,$2::text,$2::text,$3::citext,$4::text,CASE WHEN $5::boolean THEN clock_timestamp() END)`,[sub,username,email,status,deleted]);
  return sub;
 };
 const emailTaken=(error:unknown)=>error instanceof InvitationError&&error.status===422&&error.code==='email_taken'&&(error.body.errors as any)?.email==='email_taken';
 const snapshot=async(email:string)=>{
  const counts:Record<string,number>={};
  for(const table of ['invitation_codes','invitation_requests','org_audit_log','invitation_mail_jobs','invitation_mail_requests'])
   counts[table]=Number((await pool.query(`SELECT count(*)::int AS n FROM ${table}`)).rows[0].n);
  return {counts,quota:await redis.hgetall('reg:rl:'+email.toLowerCase())};
 };
 try{
  await pool.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
  await pool.query("INSERT INTO org_roles(slug,label,level) VALUES('manager','Manager',10),('member','Member',100)");
  await pool.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'owner','Owner')",[owner]);
  await pool.query("INSERT INTO user_org_roles VALUES($1,'manager')",[owner]);
  for(const key of ['org.invites.create','org.invites.view'])await pool.query("INSERT INTO role_permissions VALUES('manager',$1,'grant')",[key]);
  await pool.query("INSERT INTO settings(key,value) VALUES('enable_registration','true')");

  await t.test('active, disabled and locked registered mailboxes reject both bound delivery modes without records or quota',async()=>{
   for(const status of ['active','disabled','locked']){
    const email=mailbox();await account(email,status);const before=await snapshot(email);
    for(const delivery of ['link','email'])await assert.rejects(create(email.toUpperCase(),{delivery}),emailTaken);
    assert.deepEqual(await snapshot(email),before);
   }
  });
  await t.test('duplicate bound invitations remain allowed for an unregistered mailbox; soft-deleted owners do not occupy it',async()=>{
   const email=mailbox(),first=await create(email),second=await create(email.toUpperCase());
   assert.notEqual(first.id,second.id);assert.equal(first.bound_email,email);assert.equal(second.bound_email,email);
   const deletedEmail=mailbox();await account(deletedEmail,'active',true);
   assert.equal((await create(deletedEmail)).bound_email,deletedEmail);
  });
  await t.test('create and resend receipt replays survive later account ownership but new resend receipts are rejected',async()=>{
   const email=mailbox(),body=input(email),created=await tx(db=>createInvitation(db,owner,body));
   const resendId=randomUUID();await tx(db=>requestInvitationResend(db,owner,created.invitation.id,resendId));
   await account(email);const before=await snapshot(email);
   assert.equal((await tx(db=>createInvitation(db,owner,body))).replayed,true);
   assert.equal((await tx(db=>requestInvitationResend(db,owner,created.invitation.id,resendId))).replayed,true);
   await assert.rejects(tx(db=>requestInvitationResend(db,owner,created.invitation.id,randomUUID())),emailTaken);
   assert.deepEqual(await snapshot(email),before);
  });
  await t.test('new queue receipts and pending-job attachments check ownership before quota or durable writes; prior receipts replay',async()=>{
   const occupied=mailbox(),fresh=await create(occupied);await account(occupied);const noJobBefore=await snapshot(occupied);
   await assert.rejects(tx(db=>queueInvitationMail(db,fresh,{actorSub:owner,requestId:randomUUID()})),emailTaken);
   assert.deepEqual(await snapshot(occupied),noJobBefore);
   const email=mailbox(),invitation=await create(email),requestId=randomUUID();
   const first=await tx(db=>queueInvitationMail(db,invitation,{actorSub:null,requestId,requireQueued:true}));
   await account(email);const before=await snapshot(email);
   const replay=await tx(db=>queueInvitationMail(db,invitation,{actorSub:null,requestId,requireQueued:true}));
   assert.equal(replay.jobId,first.jobId);assert.equal(replay.queued,true);
   await assert.rejects(tx(db=>queueInvitationMail(db,invitation,{actorSub:null,requestId:randomUUID(),requireQueued:true})),emailTaken);
   assert.deepEqual(await snapshot(email),before);
  });
  await t.test('a queued job whose mailbox acquired an account fails email_taken before any provider call or new quota',async()=>{
   const email=mailbox(),invitation=await create(email);
   const queued=await tx(db=>queueInvitationMail(db,invitation,{actorSub:owner,requestId:randomUUID()}));
   await account(email);const before=await snapshot(email);let providerCalls=0;
   const result=await dispatchInvitationMailJob(queued.jobId!,{database:pool,deadline:Date.now()+2000,send:async()=>{providerCalls++;return {ok:true};}});
   assert.equal(result?.state,'failed');assert.equal(result?.error_code,'email_taken');assert.equal(providerCalls,0);
   assert.deepEqual(await snapshot(email),before);
   const row=await tx(db=>lockInvitation(db,invitation.id));
   assert.equal(row!.mail_state,'failed');assert.equal(row!.mail_error_code,'email_taken');
   assert.equal(row!.voided_at,null);assert.equal(row!.invalidated_at,null);assert.equal(row!.used_at,null);
   assert.equal((await pool.query('SELECT payload_enc FROM invitation_mail_jobs WHERE id=$1',[queued.jobId])).rows[0].payload_enc,null);
  });
  await t.test('freeing the registered address permits a new resend without transferring or ending the existing invitation',async()=>{
   const email=mailbox(),invitation=await create(email),sub=await account(email);
   await assert.rejects(tx(db=>requestInvitationResend(db,owner,invitation.id,randomUUID())),emailTaken);
   await pool.query('UPDATE identities SET email=$2 WHERE sub=$1',[sub,mailbox()]);
   const resendId=randomUUID(),resend=await tx(db=>requestInvitationResend(db,owner,invitation.id,resendId));
   assert.equal(resend.replayed,false);assert.equal(resend.invitation.bound_email,email);
   const queued=await tx(db=>queueInvitationMail(db,resend.invitation,{actorSub:owner,requestId:resendId}));let providerCalls=0;
   const result=await dispatchInvitationMailJob(queued.jobId!,{database:pool,deadline:Date.now()+2000,send:async(args)=>{providerCalls++;assert.equal(args.to,email);return {ok:true};}});
   assert.equal(result?.state,'sent');assert.equal(providerCalls,1);
   const row=await tx(db=>lockInvitation(db,invitation.id));assert.equal(row!.bound_email,email);assert.equal(row!.voided_at,null);assert.equal(row!.invalidated_at,null);
  });
 }finally{
  await settleInvitationMail();
  for(const email of ownedEmails)await redis.del('reg:rl:'+email,'reg:pending:'+email);
  await pool.end();await redis.quit();await admin.query(`DROP SCHEMA ${schema} CASCADE`);await admin.end();
 }
});
