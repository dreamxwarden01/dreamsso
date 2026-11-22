import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const code='ABCD1234EFGH',email='submitted@example.invalid',requestId='00000000-0000-4000-8000-000000000001';
const hidden='other-recipient@example.invalid';
const sent=()=>({request_id:requestId,result:'sent',sent:true,mail:{state:'sent',at:'2026-11-22T00:00:00.000Z',error_code:null},expires_at:'2026-11-23T00:00:00.000Z',resend_backoff:60});
function fixture(body:unknown=sent(),status=200,options:{gateMs?:number;error?:unknown}={}){
 const calls:any[]=[];const routes=new Map<string,Function>();let clock=100;
 const source=fs.readFileSync(new URL('../account/server/src/routes/register.ts',import.meta.url),'utf8');
 const dependencies:Record<string,unknown>={
  express:{Router:()=>({post:(path:string,handler:Function)=>routes.set(path,handler)})},
  '../session.js':{getSession:async()=>{calls.push(['session']);return null;}},
  './auth.js':{SESSION_COOKIE:'fixture'},
  './reset.js':{enforceTurnstileGate:async()=>{calls.push(['human']);clock+=options.gateMs??0;return true;},
   s2sPost:async(path:string,input:any,opts?:unknown)=>{calls.push([path,input,opts]);if(options.error)throw options.error;return {status,json:async()=>body};},
   mirror:async(res:any,response:any)=>res.status(response.status).json(await response.json())},
 };
 const output=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 class Clock extends Date{static now(){return clock;}}
 vm.runInNewContext(output,{exports:{},require:(name:string)=>{assert.ok(Object.hasOwn(dependencies,name),name);return dependencies[name];},Date:Clock,console:{error(){}}});
 return {calls,has:(path:string)=>routes.has(path),async request(path:string,input:unknown={}){
  const res:any={statusCode:200,body:null,headers:{},status(n:number){this.statusCode=n;return this;},set(k:string,v:string){this.headers[k]=v;return this;},json(value:unknown){this.body=value;return this;}};
  await routes.get(path)!({body:input,cookies:{}},res);return res;
 }};
}

test('code-only details are retired without upstream reads and no new status endpoint exists',async()=>{
 const h=fixture({invitation:{code,bound_email:hidden,label:hidden}});
 const res=await h.request('/api/register/invitation',{code,email,request_id:requestId});
 assert.equal(res.statusCode,404);assert.equal(res.body.error,'not_found');assert.deepEqual(h.calls,[]);
 assert.equal(h.has('/api/register/status'),false);assert.ok(!JSON.stringify(res.body).includes(hidden));assert.equal(res.headers['Cache-Control'],'no-store');
});
test('start whitelists the synchronous result and never forwards recipient/detail/provider material',async()=>{
 const raw={...sent(),bound_email:hidden,label:hidden,token:'private-fixture',invitation:{code,label:hidden,role:{name:hidden},bound_email:hidden},mail:{...sent().mail,provider_body:hidden}};
 const h=fixture(raw),res=await h.request('/api/register/start',{code,email,request_id:requestId,role:'ignored',bound_email:'ignored'});
 assert.equal(res.statusCode,200);assert.deepEqual(JSON.parse(JSON.stringify(res.body)),sent());
 assert.deepEqual(h.calls.map(c=>c[0]),['human','session','/internal/register/start']);
 assert.deepEqual(JSON.parse(JSON.stringify(h.calls[2][1])),{code,email,request_id:requestId});
 assert.equal(h.calls[2][2].timeoutMs,15000);assert.ok(!JSON.stringify(res.body).includes(hidden));
});
test('pending, unknown and definitive provider errors preserve their distinct safe classes',async()=>{
 const cases=[
  {status:202,body:{request_id:requestId,result:'pending'}},
  {status:202,body:{request_id:requestId,result:'pending',mail:{state:'sending',at:null,error_code:null}}},
  {status:202,body:{request_id:requestId,result:'unknown',mail:{state:'unknown',at:null,error_code:'delivery_unknown'},retry_after:60}},
  {status:502,body:{request_id:requestId,error:'send_failed',mail:{state:'failed',at:null,error_code:'bounced'},retry_after:60}},
  {status:503,body:{request_id:requestId,error:'email_not_configured',mail:{state:'failed',at:null,error_code:'email_not_configured'}}},
 ];
 for(const item of cases){const h=fixture(item.body,item.status),res=await h.request('/api/register/start',{code,email,request_id:requestId});assert.equal(res.statusCode,item.status);assert.deepEqual(JSON.parse(JSON.stringify(res.body)),item.body);}
});
test('unconfirmed arbitrary legacy shapes and conflicting receipts cannot claim successful sending',async()=>{
 for(const raw of [{queued:true,invitation:{bound_email:hidden,mail:{state:'sent'}}},{...sent(),request_id:'00000000-0000-4000-8000-000000000002'},null]){
  const h=fixture(raw),res=await h.request('/api/register/start',{code,email,request_id:requestId});
  assert.equal(res.statusCode,502);assert.ok(!JSON.stringify(res.body).includes(hidden));
 }
});
test('a verified legacy invitation queue acknowledgement becomes pending without disclosing its DTO',async()=>{
 const invitation={code,label:hidden,status:'unused',role:{id:'member',name:'Member'},created_at:'2026-11-22T00:00:00.000Z',expires_at:'2026-11-23T00:00:00.000Z',bound_email:email,bound_at:'2026-11-22T00:00:00.000Z',mail:{state:'queued',at:null,error_code:null}};
 const h=fixture({email,bound_email:email,expires_at:invitation.expires_at,invitation,queued:true,sent:false,resend_backoff:60});
 const res=await h.request('/api/register/start',{code,email,request_id:requestId});
 assert.equal(res.statusCode,202);assert.deepEqual(JSON.parse(JSON.stringify(res.body)),{result:'pending',request_id:requestId,resend_backoff:5});
 assert.ok(!JSON.stringify(res.body).includes(email));assert.ok(!JSON.stringify(res.body).includes(hidden));
});
test('legacy latest-invitation terminal mail states are never mistaken for this receipt provider outcome',async()=>{
 for(const state of ['sent','failed','unknown']){
  const invitation={code,status:'unused',role:{id:'member',name:'Member'},created_at:'2026-11-22T00:00:00.000Z',expires_at:'2026-11-23T00:00:00.000Z',bound_email:email,mail:{state,at:null,error_code:null}};
  const h=fixture({email,bound_email:email,invitation,queued:false,sent:state==='sent',resend_backoff:60});
  const res=await h.request('/api/register/start',{code,email,request_id:requestId});
  assert.equal(res.statusCode,202);assert.equal(res.body.result,'pending');assert.equal(res.body.sent,undefined);assert.equal(res.body.mail,undefined);
 }
});
test('legacy open registration retains its synchronous accepted result without a fake receipt',async()=>{
 const h=fixture({sent:true,resend_backoff:60}),res=await h.request('/api/register/start',{email});
 assert.equal(res.statusCode,200);assert.equal(res.body.result,'sent');assert.equal(res.body.sent,true);assert.equal(res.body.mail.state,'sent');assert.equal(res.body.request_id,undefined);
});
test('slow human gate shrinks the forwarding budget or prevents forwarding entirely; timeouts are explicit504',async()=>{
 const h=fixture(sent(),200,{gateMs:5000});await h.request('/api/register/start',{code,email,request_id:requestId});assert.equal(h.calls[2][2].timeoutMs,14000);
 const slow=fixture(sent(),200,{gateMs:6001}),res=await slow.request('/api/register/start',{code,email,request_id:requestId});
 assert.equal(res.statusCode,504);assert.equal(res.body.error,'upstream_timeout');assert.deepEqual(slow.calls.map(c=>c[0]),['human','session']);
 for(const name of ['AbortError','TimeoutError']){const failed=fixture(null,200,{error:Object.assign(new Error('synthetic'),{name})}),reply=await failed.request('/api/register/start',{code,email,request_id:requestId});assert.equal(reply.statusCode,504);assert.equal(reply.body.error,'upstream_timeout');}
});
test('mail proof retains its bearer contract and mismatches remain field-coded after the human gate',async()=>{
 const validated={email,bound_email:email,invitation:{bound_email:email}};
 const proof=fixture(validated),result=await proof.request('/api/register/validate',{email,token:'synthetic-bearer'});
 assert.equal(result.body.bound_email,email);assert.equal(proof.calls[0][0],'/internal/register/validate');
 const h=fixture({error:'email_mismatch',errors:{email:'email_mismatch'}},403),res=await h.request('/api/register/start',{code,email,request_id:requestId});
 assert.equal(res.statusCode,403);assert.equal(res.body.errors.email,'email_mismatch');assert.deepEqual(h.calls.map(c=>c[0]),['human','session','/internal/register/start']);
});
test('the shared S2S helper keeps its default timeout and permits a narrow registration override',async()=>{
 const source=fs.readFileSync(new URL('../account/server/src/routes/reset.ts',import.meta.url),'utf8');
 const ast=ts.createSourceFile('reset.ts',source,ts.ScriptTarget.Latest,true);
 const declaration=ast.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='s2sPost')!;const calls:any[]=[];
 const context:any={exports:{},config:{internal:'https://fixture.invalid'},s2sAssertion:async()=> 'synthetic',s2sFetch:async(...args:any[])=>{calls.push(args);return {};},AbortSignal:{timeout:(ms:number)=>({ms})}};
 vm.runInNewContext(ts.transpileModule(declaration.getText(ast),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText,context);
 await context.exports.s2sPost('/default',{});await context.exports.s2sPost('/register',{}, {timeoutMs:15000});
 assert.equal(calls[0][1].signal.ms,10000);assert.equal(calls[1][1].signal.ms,15000);
});
