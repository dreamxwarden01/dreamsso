import assert from 'node:assert/strict';
import test from 'node:test';
import {randomUUID,randomBytes} from 'node:crypto';
import {readFile} from 'node:fs/promises';
import pg from 'pg';
import {SignJWT,generateKeyPair,exportJWK} from 'jose';
import type {Router} from 'express';
import {createServer} from 'node:http';

test('invitation mail and account creation share durable single-use state',async t=>{
 const source=process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
 if(!source)throw Error('An isolated database is required.');
 const url=new URL(source);
 if(url.hostname!=='127.0.0.1'||url.pathname!=='/dreamsso_role_sync_test')throw Error('Only generated local fixtures are allowed.');
 const schema='invite_register_'+randomUUID().replaceAll('-','');
 const admin=new pg.Pool({connectionString:source,max:2});
 await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
 await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
 await admin.query(`CREATE SCHEMA ${schema}`);
 url.searchParams.set('options',`-c search_path=${schema},public`);
 const redisSource=process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
 if(!redisSource)throw Error('An isolated Redis fixture is required.');
 const redisUrl=new URL(redisSource);if(redisUrl.hostname!=='127.0.0.1'||redisUrl.pathname!=='/15')throw Error('Only generated local Redis fixtures are allowed.');
 const issuer='https://invitation-routes.example.invalid';
 process.env.ISSUER=issuer;process.env.ACCOUNT_CLIENT_ID='account';
 process.env.DATABASE_URL=url.href;process.env.REDIS_URL=redisSource;
 process.env.DOTENV_CONFIG_PATH='/dev/null';process.env.KEY_ENCRYPTION_KEY=randomBytes(32).toString('hex');
 const {pool}=await import('../src/db.js'),{redis}=await import('../src/redis.js');
 const {createInvitation,lockInvitation,validateLockedInvitation,revokeInvitation,readInvitationPreview}=await import('../src/invitations.js');
 const {withRoleTransaction}=await import('../src/rbac/roleChanges.js');
 const {queueInvitationMail,drainInvitationMail,dispatchInvitationMailJob,settleInvitationMail,readInvitationProof,invitationProofHash}=await import('../src/invitationMail.js');
 const {commitRegistration}=await import('../src/registrationStore.js');
 const {registerRouter}=await import('../src/routes/register.js');
 const {setSetting,setSecretSetting}=await import('../src/settings.js');
 const {orgRouter}=await import('../src/routes/org.js');
 // Execute the actual Express route's complete middleware stack. Only the HTTP
 // transport is replaced: auth, signed operation checks, SQL and Redis are real.
 const route=async(router:Router,pattern:string,path:string,body:Record<string,unknown>,
  headers:Record<string,string>={},params:Record<string,string>={})=>{
  const layer=(router as unknown as {stack:any[]}).stack.find(l=>l.route?.path===pattern&&l.route.methods.post);
  assert.ok(layer,`Missing POST route ${pattern}`);
  const req:any={method:'POST',path,body,headers,params,query:{}};
  const res:any={statusCode:200,body:undefined,status(code:number){this.statusCode=code;return this;},
   set(){return this;},json(value:unknown){this.body=value;return this;},end(){return this;}};
  for(const middleware of layer.route.stack){
   let advanced=false,problem:unknown;
   await middleware.handle(req,res,(error?:unknown)=>{advanced=true;problem=error;});
   if(problem)throw problem;
   if(!advanced){assert.notEqual(res.body,undefined,'Handler did not produce JSON');return res;}
  }
  throw Error('Route exhausted without a response.');
 };
 const accountKeys=await generateKeyPair('EdDSA'),accountJwk=await exportJWK(accountKeys.publicKey);
 accountJwk.kid='generated-invitation-account';
 const tokenKeys=await generateKeyPair('EdDSA'),tokenJwk=await exportJWK(tokenKeys.publicKey);
 tokenJwk.kid='generated-invitation-resource';
 const assertion=async(path:string)=>{
  const now=Math.floor(Date.now()/1000);
  return {client_assertion_type:'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
   client_assertion:await new SignJWT({method:'POST',path}).setProtectedHeader({alg:'EdDSA',kid:accountJwk.kid})
    .setIssuer('account').setSubject('account').setAudience(issuer).setIssuedAt(now).setExpirationTime(now+60).setJti(randomUUID()).sign(accountKeys.privateKey)};
 };
 const sid=randomUUID();
 const adminHeaders=async()=>{
  const now=Math.floor(Date.now()/1000);
  const token=await new SignJWT({scope:'profile',client_id:'account',sid}).setProtectedHeader({alg:'EdDSA',typ:'at+jwt',kid:tokenJwk.kid})
   .setIssuer(issuer).setAudience(issuer).setSubject(actor).setIssuedAt(now).setExpirationTime(now+600).sign(tokenKeys.privateKey);
  return {authorization:'Bearer '+token,'x-stepup-sid':sid};
 };
 const actor=randomUUID();let seq=0;const mailbox=()=>`fixture-${++seq}-${randomUUID()}@example.invalid`;
 const tx=<T>(work:(db:pg.PoolClient)=>Promise<T>)=>withRoleTransaction(work,pool);
 const make=async(email=mailbox())=>tx(async db=>{
  const result=await createInvitation(db,actor,{request_id:randomUUID(),role_slug:'member',email,delivery:'email',validity_hours:72,note:'Test invite'});
  await queueInvitationMail(db,result.invitation,{actorSub:actor,requestId:randomUUID()});return result.invitation;
 });
 const delivered=new Map<string,string>();let sends=0;
 const send=async(args:{to:string;text:string})=>{sends++;const match=/https?:\/\/[^\s]+/.exec(args.text);assert.ok(match);delivered.set(args.to,new URL(match[0]).searchParams.get('token')!);return {ok:true as const};};
 let providerCalls=0;let providerHold:(()=>Promise<void>)|null=null;
 let providerReply: {status:number;body:unknown}|null=null;
 const provider=createServer(async(req,res)=>{
  try{
   providerCalls++;if(providerHold)await providerHold();
   let body='';for await(const chunk of req){body+=chunk;if(body.length>65536)throw Error('oversized fixture');}
   const data=JSON.parse(body);
   if(providerReply){res.writeHead(providerReply.status,{'Content-Type':'application/json'}).end(JSON.stringify(providerReply.body));return;}
   await send(data);res.writeHead(200,{'Content-Type':'application/json'}).end(JSON.stringify({success:true}));
  }catch{res.writeHead(500).end();}
 });
 await new Promise<void>(resolve=>provider.listen(0,'127.0.0.1',resolve));
 const providerPort=(provider.address() as {port:number}).port;
 const finish=async(inv:any,token:string,username='user_'+randomUUID().slice(0,8),requestHash=randomBytes(32))=>tx(db=>commitRegistration(db,{
  sub:randomUUID(),username,displayName:'Fixture',email:inv.bound_email,passwordHash:'synthetic-argon-hash',proofHash:invitationProofHash(token),requestHash,
  code:inv.code,proofExpiresAt:new Date(inv.expires_at),modernProof:true}));
 try {
  await pool.query((await readFile(new URL('../db/schema.sql',import.meta.url),'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm,''));
  await pool.query("INSERT INTO org_roles(slug,label,level) VALUES('admin','Admin',10),('member','Member',100)");
  await pool.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'creator','Creator')",[actor]);
  await pool.query("INSERT INTO user_org_roles VALUES($1,'admin')",[actor]);
  for(const permission of ['org.invites.create','org.invites.view','org.invites.void'])await pool.query("INSERT INTO role_permissions VALUES('admin',$1,'grant')",[permission]);
  await pool.query("INSERT INTO settings(key,value) VALUES('enable_registration','true'),('account_portal_url','https://account.example.invalid'),('default_org_role','member')");
  await pool.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,jwks) VALUES('account','Fixture account','{}',$1)",[{keys:[accountJwk]}]);
  await pool.query("INSERT INTO signing_keys(kid,public_jwk,private_key_enc,status) VALUES($1,$2,$3,'current')",[tokenJwk.kid,tokenJwk,Buffer.from('synthetic-unused-private-key')]);
  await pool.query("INSERT INTO sessions(sid,user_sub,token_hash,expires_at) VALUES($1,$2,$3,now()+interval '1 day')",[sid,actor,randomBytes(32)]);
  await pool.query("INSERT INTO settings(key,value) VALUES('stepup_portal_required','false')");
  await setSetting('mail_from','fixture@example.invalid');await setSetting('cf_account_id','fixture');
  await setSetting('cf_api_base',`http://127.0.0.1:${providerPort}`);await setSecretSetting('cf_api_token','synthetic-provider-credential');
  await t.test('plain code details are retired and wrong-address first submit has no side effects or recipient disclosure',async()=>{
   const inv=await make(),wrong=mailbox(),rid=randomUUID(),path='/internal/register/start';
   const snapshot=async()=>({
    invitation:(await pool.query('SELECT * FROM invitation_codes WHERE id=$1',[inv.id])).rows[0],
    jobs:(await pool.query('SELECT * FROM invitation_mail_jobs WHERE invitation_id=$1 ORDER BY id',[inv.id])).rows,
    requests:(await pool.query('SELECT * FROM invitation_mail_requests WHERE invitation_id=$1 ORDER BY request_id',[inv.id])).rows,
    wrongQuota:await redis.get('reg:rl:'+wrong),
   });
   const before=await snapshot();
   const denied=await route(registerRouter,path,path,{...await assertion(path),code:inv.code,email:wrong,request_id:rid});
   assert.equal(denied.statusCode,403);assert.deepEqual(denied.body,{request_id:rid,error:'email_mismatch',errors:{email:'email_mismatch'}});
   assert.ok(!JSON.stringify(denied.body).includes(inv.bound_email!));assert.deepEqual(await snapshot(),before);
   assert.equal((await pool.query('SELECT 1 FROM identities WHERE email=$1',[wrong])).rowCount,0);
   const old='/internal/register/invitation';
   const retired=await route(registerRouter,old,old,{code:inv.code,email:wrong,request_id:rid});
   assert.equal(retired.statusCode,404);assert.deepEqual(retired.body,{error:'not_found'});
  });
  await t.test('synchronous public send requires UUID and preserves proof-only locked-email prefill',async()=>{
   const inv=await make(),start='/internal/register/start',rid=randomUUID(),before=sends;
   const missing=await route(registerRouter,start,start,{...await assertion(start),code:inv.code,email:inv.bound_email});
   assert.equal(missing.statusCode,422);assert.equal(missing.body.error,'invalid_request_id');assert.equal(sends,before);
   const accepted=await route(registerRouter,start,start,{...await assertion(start),code:inv.code,email:inv.bound_email,request_id:rid});
   assert.equal(accepted.statusCode,200);assert.equal(accepted.body.request_id,rid);assert.equal(accepted.body.result,'sent');
   assert.equal(accepted.body.mail.state,'sent');assert.equal(sends,before+1);
   assert.ok(!JSON.stringify(accepted.body).includes(inv.bound_email!));assert.equal(accepted.body.invitation,undefined);
   const proofPath='/internal/register/validate',token=delivered.get(inv.bound_email!)!;
   const valid=await route(registerRouter,proofPath,proofPath,{...await assertion(proofPath),email:inv.bound_email,token});
   assert.equal(valid.statusCode,200);assert.equal(valid.body.bound_email,inv.bound_email);assert.equal(valid.body.invitation.bound_email,inv.bound_email);
   const invalid=await route(registerRouter,proofPath,proofPath,{...await assertion(proofPath),email:mailbox(),token});
   assert.equal(invalid.statusCode,422);assert.equal(invalid.body.error,'invalid_token');assert.ok(!JSON.stringify(invalid.body).includes(inv.bound_email!));
   assert.ok(!(registerRouter as any).stack.some((layer:any)=>layer.route?.path==='/internal/register/status'));
  });
  await t.test('same-UUID concurrent sends reuse one provider result and replays read their exact job',async()=>{
   const inv=await make(),path='/internal/register/start',rid=randomUUID(),before=sends;
   const start=async(id:string)=>route(registerRouter,path,path,{...await assertion(path),code:inv.code,email:inv.bound_email,request_id:id});
   const replies=await Promise.all([start(rid),start(rid)]);
   for(const reply of replies){assert.equal(reply.statusCode,200);assert.equal(reply.body.result,'sent');}
   assert.equal(sends,before+1);
   await pool.query('UPDATE invitation_codes SET mail_next_retry_at=NULL WHERE id=$1',[inv.id]);await redis.del('reg:rl:'+inv.bound_email);
   const newer=await tx(db=>queueInvitationMail(db,inv,{actorSub:null,requestId:randomUUID(),requireQueued:true}));
   const failed=await dispatchInvitationMailJob(newer.jobId!,{database:pool,send:async()=>({ok:false,reason:'rejected'}),deadline:Date.now()+2000});
   assert.equal(failed?.state,'failed');assert.equal(failed?.error_code,'rejected');
   assert.equal((await pool.query('SELECT mail_state FROM invitation_codes WHERE id=$1',[inv.id])).rows[0].mail_state,'failed');
   const replay=await start(rid);assert.equal(replay.statusCode,200);assert.equal(replay.body.mail.state,'sent');assert.equal(sends,before+1);
  });
  await t.test('different public request UUIDs coalesce while provider acceptance is still in flight',async()=>{
   const inv=await make(),path='/internal/register/start';let release!:()=>void,entered!:()=>void;
   const gate=new Promise<void>(r=>{release=r;}),ready=new Promise<void>(r=>{entered=r;});
   providerHold=async()=>{entered();await gate;};const before=providerCalls;
   const start=async()=>route(registerRouter,path,path,{...await assertion(path),code:inv.code,email:inv.bound_email,request_id:randomUUID()});
   const first=start();let second:ReturnType<typeof start>|undefined;
   try{
    await ready;second=start();
    const deadline=Date.now()+2000;
    while((await pool.query("SELECT count(*)::int AS n FROM invitation_mail_requests WHERE invitation_id=$1 AND actor_key=$2",[inv.id,'public:'+inv.id])).rows[0].n<2){
     assert.ok(Date.now()<deadline,'second transaction proceeds while provider call has no role/row lock');await new Promise(r=>setTimeout(r,10));
    }
    assert.equal(providerCalls,before+1);
   }finally{providerHold=null;release();}
   assert.equal((await first).body.result,'sent');assert.equal((await second!).body.result,'sent');assert.equal(providerCalls,before+1);
  });
  await t.test('provider rejection, bounce/configuration and ambiguous outcomes keep precise durable response classes',async()=>{
   const path='/internal/register/start';
   for(const item of [
    {http:422,body:{success:false},status:502,error:'send_failed',code:'rejected'},
    {http:200,body:{success:true,result:{permanent_bounces:['synthetic@example.invalid']}},status:502,error:'send_failed',code:'bounced'},
    {http:401,body:{success:false},status:503,error:'email_not_configured',code:'email_not_configured'},
    {http:503,body:{success:false},status:202,error:null,code:'delivery_unknown'},
   ]){
    const inv=await make(),rid=randomUUID(),before=providerCalls;providerReply={status:item.http,body:item.body};
    try{
     const invoke=async()=>route(registerRouter,path,path,{...await assertion(path),code:inv.code,email:inv.bound_email,request_id:rid});
     const result=await invoke();assert.equal(result.statusCode,item.status);assert.equal(result.body.mail.error_code,item.code);
     if(item.error)assert.equal(result.body.error,item.error);else assert.equal(result.body.result,'unknown');
     assert.equal(providerCalls,before+1);const again=await invoke();assert.equal(again.statusCode,item.status);assert.equal(providerCalls,before+1);
    }finally{providerReply=null;}
   }
  });
  await t.test('open-registration ambiguous delivery retains its quota and never claims definite failure',async()=>{
   const path='/internal/register/start',email=mailbox();await setSetting('require_invitation_code','false');providerReply={status:503,body:{success:false}};
   try{
    const result=await route(registerRouter,path,path,{...await assertion(path),email});
    assert.equal(result.statusCode,202);assert.equal(result.body.result,'unknown');assert.equal(result.body.mail.error_code,'delivery_unknown');
    const quota=await redis.hgetall('reg:rl:'+email);assert.equal(Number(quota.count),1);
   }finally{providerReply=null;await setSetting('require_invitation_code','true');}
  });
  await t.test('targeted sends and terminal replays never claim an unrelated older queued job',async()=>{
   const older=await make(),target=await make();
   const job=(await pool.query('SELECT id FROM invitation_mail_jobs WHERE invitation_id=$1',[target.id])).rows[0];
   const sentTo:string[]=[];const deliver=async(args:any)=>{sentTo.push(args.to);return {ok:true as const};};
   assert.equal((await dispatchInvitationMailJob(job.id,{database:pool,send:deliver,deadline:Date.now()+2000}))?.state,'sent');
   assert.deepEqual(sentTo,[target.bound_email]);
   assert.equal((await pool.query('SELECT state FROM invitation_mail_jobs WHERE invitation_id=$1',[older.id])).rows[0].state,'queued');
   assert.equal((await dispatchInvitationMailJob(job.id,{database:pool,send:deliver,deadline:Date.now()+2000}))?.state,'sent');
   assert.deepEqual(sentTo,[target.bound_email]);
   assert.equal((await pool.query('SELECT state FROM invitation_mail_jobs WHERE invitation_id=$1',[older.id])).rows[0].state,'queued');
  });
  await t.test('a foreign worker lease is awaited to its actual terminal state without another provider call',async()=>{
   const inv=await make(),job=(await pool.query('SELECT id FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];
   await pool.query("UPDATE invitation_mail_jobs SET state='sending',lease_id=$2,lease_until=clock_timestamp()+interval '45 seconds' WHERE id=$1",[job.id,randomUUID()]);
   let finished=false,count=0;const wait=dispatchInvitationMailJob(job.id,{database:pool,send:async()=>{count++;return {ok:true};},deadline:Date.now()+2000}).then(result=>{finished=true;return result;});
   await new Promise(r=>setTimeout(r,30));assert.equal(finished,false);assert.equal(count,0);
   await pool.query("UPDATE invitation_mail_jobs SET state='sent',payload_enc=NULL,finished_at=clock_timestamp(),lease_id=NULL,lease_until=NULL WHERE id=$1",[job.id]);
   assert.equal((await wait)?.state,'sent');assert.equal(count,0);
  });
  await t.test('a worker-owned send and targeted duplicate waiters serialize on one provider operation',async()=>{
   // Drain preceding independent fixtures, then make this job the worker's head.
   while((await pool.query("SELECT 1 FROM invitation_mail_jobs WHERE state='queued' LIMIT 1")).rowCount)await drainInvitationMail({database:pool,send});
   const inv=await make(),job=(await pool.query('SELECT id FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];
   let release!:()=>void,entered!:()=>void;const gate=new Promise<void>(r=>{release=r;}),ready=new Promise<void>(r=>{entered=r;});let count=0;
   const worker=drainInvitationMail({database:pool,send:async()=>{count++;entered();await gate;return {ok:true};}});
   await ready;
   const first=dispatchInvitationMailJob(job.id,{database:pool,send:async()=>{count++;return {ok:true};},deadline:Date.now()+2000});
   const second=dispatchInvitationMailJob(job.id,{database:pool,send:async()=>{count++;return {ok:true};},deadline:Date.now()+2000});
   await new Promise(r=>setTimeout(r,20));assert.equal(count,1);release();
   await worker;assert.equal((await first)?.state,'sent');assert.equal((await second)?.state,'sent');assert.equal(count,1);
  });
  await t.test('deadline responses do not cancel delivery and shutdown settlement joins the real send',async()=>{
   const inv=await make(),job=(await pool.query('SELECT id FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];
   let release!:()=>void,entered!:()=>void;const gate=new Promise<void>(r=>{release=r;}),ready=new Promise<void>(r=>{entered=r;});let count=0;
   const result=dispatchInvitationMailJob(job.id,{database:pool,send:async()=>{count++;entered();await gate;return {ok:true};},deadline:Date.now()+100});
   await ready;assert.equal(await result,null);assert.equal(count,1);
   let settled=false;const closing=settleInvitationMail().then(()=>{settled=true;});await new Promise(r=>setTimeout(r,20));assert.equal(settled,false);
   release();await closing;assert.equal((await pool.query('SELECT state FROM invitation_mail_jobs WHERE id=$1',[job.id])).rows[0].state,'sent');
   const replay=await dispatchInvitationMailJob(job.id,{database:pool,send:async()=>{count++;return {ok:true};},deadline:Date.now()+1000});
   assert.equal(replay?.state,'sent');assert.equal(count,1);
  });
  await t.test('provider acceptance with failed finish stays pending then becomes unknown without re-sending',async()=>{
   const inv=await make(),job=(await pool.query('SELECT id FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];let count=0;
   const database={query:pool.query.bind(pool),connect:async()=>{const db=await pool.connect();return {release:()=>db.release(),query:(sql:string,values?:any[])=>{
    if(sql.startsWith('UPDATE invitation_mail_jobs SET state=$3'))throw Error('synthetic finish outage');return db.query(sql,values);
   }};}} as unknown as pg.Pool;
   const result=await dispatchInvitationMailJob(job.id,{database,send:async()=>{count++;return {ok:true};},deadline:Date.now()+1000});
   assert.equal(result,null);assert.equal(count,1);
   await pool.query("UPDATE invitation_mail_jobs SET lease_until=clock_timestamp()-interval '1 second' WHERE id=$1",[job.id]);
   await drainInvitationMail({database:pool,send:async()=>{count++;return {ok:true};}});
   const row=(await pool.query('SELECT state,payload_enc FROM invitation_mail_jobs WHERE id=$1',[job.id])).rows[0];assert.equal(row.state,'unknown');assert.equal(row.payload_enc,null);assert.equal(count,1);
  });
  await t.test('queue and binding commit together; only encrypted proof is retained before send',async()=>{
   const inv=await make(),job=(await pool.query('SELECT * FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];
   assert.equal(job.state,'queued');assert.ok(Buffer.isBuffer(job.payload_enc));assert.equal(job.proof_hash.length,32);
   assert.ok(!job.payload_enc.toString('utf8').includes('token='));
   await drainInvitationMail({database:pool,send});
   const token=delivered.get(inv.bound_email!)!;assert.match(token,/^[a-f0-9]{96}$/);
   assert.ok(await readInvitationProof(pool,inv.bound_email!,token));
   assert.equal(await readInvitationProof(pool,mailbox(),token),null);
   assert.equal((await pool.query('SELECT payload_enc,state FROM invitation_mail_jobs WHERE id=$1',[job.id])).rows[0].payload_enc,null);
   await assert.rejects(tx(async db=>validateLockedInvitation(db,(await lockInvitation(db,inv.id))!,mailbox(),true)),/email_mismatch/);
  });
  await t.test('two different completions cannot consume one invitation twice',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const token=delivered.get(inv.bound_email!)!;
   const results=await Promise.allSettled([finish(inv,token),finish(inv,token)]);
   assert.equal(results.filter(r=>r.status==='fulfilled').length,1);
   assert.equal((await pool.query('SELECT count(*)::int AS n FROM identities WHERE email=$1',[inv.bound_email])).rows[0].n,1);
   const row=(await pool.query('SELECT used_at,used_username_snapshot FROM invitation_codes WHERE id=$1',[inv.id])).rows[0];assert.ok(row.used_at);assert.ok(row.used_username_snapshot);
  });
  await t.test('same request retry returns durable completion without a second identity',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const token=delivered.get(inv.bound_email!)!,hash=randomBytes(32),name='retry_'+randomUUID().slice(0,8);
   const first=await finish(inv,token,name,hash),again=await finish(inv,token,name,hash);
   assert.equal(again.replayed,true);assert.equal(first.sub,again.sub);
  });
  await t.test('revoked invitation is neither mailed nor accepted',async()=>{
   const inv=await make(),before=sends;
   await tx(db=>revokeInvitation(db,actor,inv.id,randomUUID()));
   await drainInvitationMail({database:pool,send});assert.equal(sends,before);
   assert.equal((await pool.query('SELECT state FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0].state,'failed');
  });
  await t.test('provider uncertainty requires explicit resend and never auto-replays',async()=>{
   const inv=await make();let count=0;
   await drainInvitationMail({database:pool,send:async()=>{count++;return {ok:false,reason:'unreachable'};}});
   await drainInvitationMail({database:pool,send:async()=>{count++;return {ok:true};}});
   assert.equal(count,1);assert.equal((await pool.query('SELECT mail_state FROM invitation_codes WHERE id=$1',[inv.id])).rows[0].mail_state,'unknown');
  });
  await t.test('a crash after send begins marks unknown and clears the encrypted payload',async()=>{
   const inv=await make(),before=sends;
   await pool.query("UPDATE invitation_mail_jobs SET state='sending',lease_id=$2,lease_until=clock_timestamp()-interval '1 second' WHERE invitation_id=$1",[inv.id,randomUUID()]);
   await drainInvitationMail({database:pool,send});assert.equal(sends,before);
   const row=(await pool.query('SELECT state,payload_enc FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0];assert.equal(row.state,'unknown');assert.equal(row.payload_enc,null);
  });
  await t.test('coalesced retries remain idempotent after the queued job finishes',async()=>{
   const inv=await make(),requestId=randomUUID();
   await tx(db=>queueInvitationMail(db,inv,{actorSub:null,requestId}));
   await drainInvitationMail({database:pool,send});
   await pool.query("UPDATE invitation_codes SET mail_next_retry_at=NULL WHERE id=$1",[inv.id]);
   const reply=await tx(db=>queueInvitationMail(db,inv,{actorSub:null,requestId}));
   assert.equal(reply.queued,false);
   assert.equal((await pool.query('SELECT count(*)::int n FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rows[0].n,1);
  });
  await t.test('a failed transaction keeps neither account nor invitation consumption',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const token=delivered.get(inv.bound_email!)!;
   await pool.query(`CREATE FUNCTION reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$
     BEGIN RAISE EXCEPTION 'synthetic receipt failure'; END $$;
     CREATE TRIGGER reject_completion BEFORE INSERT ON registration_completions FOR EACH ROW EXECUTE FUNCTION reject_completion()`);
   try {await assert.rejects(finish(inv,token),/synthetic receipt failure/);}
   finally{await pool.query('DROP TRIGGER reject_completion ON registration_completions;DROP FUNCTION reject_completion()');}
   assert.equal((await pool.query('SELECT 1 FROM identities WHERE email=$1',[inv.bound_email])).rowCount,0);
   assert.equal((await pool.query('SELECT used_at FROM invitation_codes WHERE id=$1',[inv.id])).rows[0].used_at,null);
  });
  await t.test('actual public start handler returns429 with retry details and no irreversible binding',async()=>{
   const email=mailbox(),now=Math.floor(Date.now()/1000),requestId=randomUUID();
   await redis.hset('reg:rl:'+email,{first:now,count:5,last:now});await redis.expire('reg:rl:'+email,86400);
   const inv=await tx(async db=>(await createInvitation(db,actor,{request_id:randomUUID(),role_slug:'member',delivery:'link'})).invitation);
   const path='/internal/register/start';
   const response=await route(registerRouter,path,path,{...await assertion(path),code:inv.code,email,request_id:requestId});
   assert.equal(response.statusCode,429);assert.equal(response.body.error,'rate_limited');
   assert.ok(response.body.retry_after>0);assert.equal(response.body.can_retry,false);
   const row=(await pool.query('SELECT bound_email,bound_at,binding_source FROM invitation_codes WHERE id=$1',[inv.id])).rows[0];
   assert.deepEqual(row,{bound_email:null,bound_at:null,binding_source:null});
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rowCount,0);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_requests WHERE invitation_id=$1',[inv.id])).rowCount,0);
   const other=mailbox();
   const accepted=await route(registerRouter,path,path,{...await assertion(path),code:inv.code,email:other,request_id:requestId});
   assert.equal(accepted.statusCode,200);assert.equal(accepted.body.result,'sent');assert.equal(accepted.body.mail.state,'sent');
   assert.ok(!JSON.stringify(accepted.body).includes(other));
   assert.equal((await pool.query('SELECT bound_email FROM invitation_codes WHERE id=$1',[inv.id])).rows[0].bound_email,other);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rowCount,1);
   await drainInvitationMail({database:pool,send});assert.ok(delivered.get(other));
  });
  await t.test('enabled invitation authority is checked before email validation on the actual route',async()=>{
   const path='/internal/register/start';
   await setSetting('require_invitation_code','true');
   for(const code of ['', 'not-a-code']){
    const response=await route(registerRouter,path,path,{...await assertion(path),email:'not-an-email',code,request_id:randomUUID()});
    assert.equal(response.statusCode,422);assert.equal(response.body.errors.code,'invalid_code');
   }
   const absent=await route(registerRouter,path,path,{...await assertion(path),email:'not-an-email',code:'ZZZZZZZZZZZZ',request_id:randomUUID()});
   assert.equal(absent.statusCode,422);assert.equal(absent.body.error,'invalid_invitation');
   const inv=await tx(async db=>(await createInvitation(db,actor,{request_id:randomUUID(),role_slug:'member',delivery:'link'})).invitation);
   await pool.query("UPDATE invitation_codes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[inv.id]);
   const expired=await route(registerRouter,path,path,{...await assertion(path),email:'not-an-email',code:inv.code,request_id:randomUUID()});
   assert.equal(expired.statusCode,409);assert.equal(expired.body.error,'invitation_expired');
  });
  await t.test('disabled invitations ignore even malformed supplied codes and use email-only registration',async()=>{
   const path='/internal/register/start';await setSetting('require_invitation_code','false');await setSetting('cf_account_id','');
   try{
    const badEmail=await route(registerRouter,path,path,{...await assertion(path),email:'not-an-email',code:'not-a-code'});
    assert.equal(badEmail.statusCode,422);assert.equal(badEmail.body.errors.email,'invalid_email');
    const validEmail=await route(registerRouter,path,path,{...await assertion(path),email:mailbox(),code:'not-a-code',request_id:'ignored'});
    // This isolated fixture deliberately has no provider credentials. Reaching
    // the open-registration mail configuration guard proves the code was ignored.
    assert.equal(validEmail.statusCode,503);assert.equal(validEmail.body.error,'email_not_configured');
   }finally{await setSetting('require_invitation_code','true');await setSetting('cf_account_id','fixture');}
  });
  await t.test('actual admin resend handler returns429 and rolls back receipt/audit, then same request queues once',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const requestId=randomUUID();
   const pattern='/account/org/invites/:id/resend',path=`/account/org/invites/${inv.id}/resend`;
   const invoke=async()=>route(orgRouter,pattern,path,{request_id:requestId},await adminHeaders(),{id:inv.id});
   const response=await invoke();assert.equal(response.statusCode,429);assert.equal(response.body.error,'rate_limited');
   assert.ok(response.body.retry_after>0);assert.equal(response.body.can_retry,true);
   assert.equal((await pool.query('SELECT 1 FROM invitation_requests WHERE actor_sub=$1 AND request_id=$2',[actor,requestId])).rowCount,0);
   assert.equal((await pool.query("SELECT 1 FROM org_audit_log WHERE action='invite.resend' AND detail->>'invitation_id'=$1",[inv.id])).rowCount,0);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rowCount,1);
   await pool.query('UPDATE invitation_codes SET mail_next_retry_at=NULL WHERE id=$1',[inv.id]);await redis.del('reg:rl:'+inv.bound_email);
   const accepted=await invoke();assert.equal(accepted.statusCode,200);assert.equal(accepted.body.invitation.mail.state,'queued');
   assert.equal((await pool.query('SELECT 1 FROM invitation_requests WHERE actor_sub=$1 AND request_id=$2',[actor,requestId])).rowCount,1);
   assert.equal((await pool.query("SELECT 1 FROM org_audit_log WHERE action='invite.resend' AND detail->>'invitation_id'=$1",[inv.id])).rowCount,1);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rowCount,2);
   const retry=await invoke();assert.equal(retry.statusCode,200);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[inv.id])).rowCount,2);
   await drainInvitationMail({database:pool,send});
  });
  await t.test('actual admin create handler accepts sixty emoji code points in a note',async()=>{
   const path='/account/org/invites',note='😀'.repeat(60),requestId=randomUUID();
   const response=await route(orgRouter,path,path,{request_id:requestId,role_slug:'member',delivery:'link',note},await adminHeaders());
   assert.equal(response.statusCode,201);assert.equal(response.body.invitation.note,note);
   assert.equal((await pool.query('SELECT char_length(note)::int AS n FROM invitation_codes WHERE id=$1',[response.body.invitation.id])).rows[0].n,60);
   assert.equal((await pool.query('SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1',[response.body.invitation.id])).rowCount,0);
  });
  await t.test('strict expiry checked after acquiring the shared authority lock',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const token=delivered.get(inv.bound_email!)!;
   await pool.query("UPDATE invitation_codes SET expires_at=clock_timestamp()+interval '150 milliseconds' WHERE id=$1",[inv.id]);
   const hold=await pool.connect();await hold.query('BEGIN');await hold.query('SELECT pg_advisory_xact_lock(1145624915)');
   const attempt=finish(inv,token);const rejected=assert.rejects(attempt,/invitation_expired/);
   await new Promise(r=>setTimeout(r,200));await hold.query('COMMIT');hold.release();await rejected;
   assert.equal((await pool.query('SELECT 1 FROM identities WHERE email=$1',[inv.bound_email])).rowCount,0);
  });
  await t.test('known expired email proof can explain the deadline but cannot authorize registration',async()=>{
   const inv=await make();await drainInvitationMail({database:pool,send});const token=delivered.get(inv.bound_email!)!;
   await pool.query("UPDATE invitation_mail_jobs SET expires_at=clock_timestamp()-interval '1 second' WHERE invitation_id=$1",[inv.id]);
   await pool.query("UPDATE invitation_codes SET expires_at=clock_timestamp()-interval '1 second' WHERE id=$1",[inv.id]);
   assert.equal(await readInvitationProof(pool,inv.bound_email!,token),null);
   assert.ok(await readInvitationProof(pool,inv.bound_email!,token,true));
   await assert.rejects(finish(inv,token),/invalid_token/);
  });
  await t.test('public invitation preview does not wait on the authority writer lock',async()=>{
   const inv=await make();const holder=await pool.connect();await holder.query('BEGIN');await holder.query('SELECT pg_advisory_xact_lock(1145624915)');
   let deadline:ReturnType<typeof setTimeout>|undefined;
   try{const row=await Promise.race([readInvitationPreview(pool,inv.code),new Promise<never>((_,reject)=>{deadline=setTimeout(()=>reject(Error('preview took authority lock')),750);})]);assert.equal(row?.id,inv.id);}
   finally{clearTimeout(deadline);await holder.query('ROLLBACK');holder.release();}
   await drainInvitationMail({database:pool,send});
  });
  await t.test('fresh schema and upgrade migrations are replay-safe',async()=>{
   for(const name of ['005-invitations.sql','006-registration-mail.sql']){
    const sql=await readFile(new URL('../db/migrations/'+name,import.meta.url),'utf8');await pool.query(sql);await pool.query(sql);
   }
  });
 }finally{provider.closeAllConnections();await new Promise<void>(resolve=>provider.close(()=>resolve()));await settleInvitationMail();await pool.end();await redis.quit();await admin.query(`DROP SCHEMA ${schema} CASCADE`);await admin.end();}
});
