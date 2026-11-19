import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import {generateKeyPair,exportJWK,importJWK,jwtVerify} from 'jose';

const SITEVERIFY='https://challenges.cloudflare.com/turnstile/v0/siteverify';
const ORIGIN='https://account.example.invalid';
const SECRET='synthetic-turnstile-secret';
const transpile=(source:string)=>ts.transpileModule(source,{compilerOptions:{
 target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,esModuleInterop:true,
}}).outputText;

// Compile the actual Worker and the actual BFF gate bodies. No config, Redis,
// environment or production server module is imported. Only settings lookup and
// fetch transport are synthetic; JWT signing/verification and body hashing run.
function loadGate(publicJwk:Awaited<ReturnType<typeof exportJWK>>) {
 const source=fs.readFileSync(new URL('../account/server/src/routes/reset.ts',import.meta.url),'utf8');
 const tree=ts.createSourceFile('reset.ts',source,ts.ScriptTarget.Latest,true,ts.ScriptKind.TS);
 const functionNames=['verifyGateAssertion','verifyTurnstile','enforceTurnstileGate'];
 const pieces:string[]=[];
 for(const name of ['SITEVERIFY_URL','gateKeys']){
  const node=tree.statements.find(statement=>ts.isVariableStatement(statement)&&statement.declarationList.declarations.some(d=>ts.isIdentifier(d.name)&&d.name.text===name));
  assert.ok(node,`Actual BFF declaration ${name} must exist`);pieces.push(node.getText(tree));
 }
 for(const name of functionNames){
  const node=tree.statements.find(statement=>ts.isFunctionDeclaration(statement)&&statement.name?.text===name);
  assert.ok(node,`Actual BFF function ${name} must exist`);pieces.push(node.getText(tree));
 }
 pieces.push('export { verifyGateAssertion };');
 const exports:any={};
 vm.runInNewContext(transpile(pieces.join('\n')),{exports,crypto,Buffer,importJWK,jwtVerify,
  FormData,AbortSignal,fetch:(...args:Parameters<typeof fetch>)=>globalThis.fetch(...args),
  turnstileConfig:async()=>({enabled:true,site_key:'synthetic-site-key',secret_key:SECRET,gate_public_jwk:publicJwk}),
  require:(id:string)=>{throw Error('Unexpected gate dependency '+id);},
 },{filename:'actual-bff-turnstile-gate.cjs'});
 return exports as {
  enforceTurnstileGate(req:any,res:any):Promise<boolean>;
  verifyGateAssertion(assertion:string,jwk:unknown,req:any):Promise<boolean>;
 };
}
function loadWorker(){
 const source=fs.readFileSync(new URL('../cloudflare/workers/turnstile-gate-sso/src/index.js',import.meta.url),'utf8');
 const exports:any={};
 vm.runInNewContext(transpile(source),{exports,crypto:crypto.webcrypto,TextEncoder,btoa,
  Request,Response,Headers,FormData,URL,
  fetch:(...args:Parameters<typeof fetch>)=>globalThis.fetch(...args),
  require:(id:string)=>{throw Error('Unexpected Worker dependency '+id);},
 },{filename:'actual-turnstile-worker.cjs'});
 return exports.default as {fetch(request:Request,env:Record<string,string>):Promise<Response>};
}
const responseRecorder=()=>({statusCode:200,body:undefined as unknown,
 status(code:number){this.statusCode=code;return this;},json(body:unknown){this.body=JSON.parse(JSON.stringify(body));return this;}});

test('actual Worker and BFF gate chain consumes one human proof before registration validation',async t=>{
 const pair=await generateKeyPair('EdDSA'),privateJwk=await exportJWK(pair.privateKey),publicJwk=await exportJWK(pair.publicKey);
 privateJwk.kid=publicJwk.kid='generated-test-gate-key';
 const worker=loadWorker(),gate=loadGate(publicJwk),originalFetch=globalThis.fetch;
 const env={TURNSTILE_SECRET_KEY:SECRET,GATE_SIGNING_KEY:JSON.stringify(privateJwk)};
 let siteverifyCalls=0,originCalls=0,downstreamCalls=0,forwarded: {body:string;headers:Headers;path:string}|null=null;
 const reset=()=>{siteverifyCalls=0;originCalls=0;downstreamCalls=0;forwarded=null;};
 const request=(path:string,body:Record<string,unknown>)=>new Request(ORIGIN+path,{method:'POST',
  headers:{'content-type':'application/json','cf-connecting-ip':'192.0.2.10',
   'x-gate-assertion':'synthetic-forged-inbound','x-gate-debug':'synthetic-untrusted','X-Gate-Other':'synthetic-untrusted'},
  body:JSON.stringify(body,null,2)});
 const bffRequest=(path:string,body:string,headers:Headers)=>({path,rawBody:Buffer.from(body),body:JSON.parse(body),
  headers:Object.fromEntries(headers),ip:'192.0.2.10'});
 globalThis.fetch=(async(input:RequestInfo|URL,init?:RequestInit)=>{
  const address=input instanceof Request?input.url:String(input);
  if(address===SITEVERIFY){
   siteverifyCalls++;assert.equal(init?.method,'POST');assert.ok(init.body instanceof FormData);
   assert.equal(init.body.get('secret'),SECRET);assert.equal(init.body.get('remoteip'),'192.0.2.10');
   return Response.json({success:init.body.get('response')==='synthetic-human-ok'});
  }
  // Any unexpected destination fails instead of escaping to the network.
  assert.ok(input instanceof Request);assert.equal(new URL(address).origin,ORIGIN);originCalls++;
  const body=await input.text(),headers=new Headers(input.headers),path=new URL(address).pathname;
  forwarded={body,headers,path};
  const res=responseRecorder(),accepted=await gate.enforceTurnstileGate(bffRequest(path,body,headers),res);
  if(!accepted)return Response.json(res.body,{status:res.statusCode});
  downstreamCalls++; // Registration code/email validation may run only beyond this point.
  return Response.json({gate_passed:true});
 }) as typeof fetch;
 try{
  await t.test('missing human token never reaches origin, code or email validation',async()=>{
   reset();const result=await worker.fetch(request('/api/register/start',{code:'invalid-code',email:'invalid-email'}),env);
   assert.equal(result.status,403);assert.deepEqual(await result.json(),{error:'turnstile_failed'});
   assert.equal(siteverifyCalls,0);assert.equal(originCalls,0);assert.equal(downstreamCalls,0);
  });
  await t.test('failed Siteverify never reaches origin even with forged incoming gate headers',async()=>{
   reset();const result=await worker.fetch(request('/api/register/start',{turnstile_token:'synthetic-human-invalid',code:'invalid-code',email:'invalid-email'}),env);
   assert.equal(result.status,403);assert.equal(siteverifyCalls,1);assert.equal(originCalls,0);assert.equal(downstreamCalls,0);
  });
  await t.test('start and complete each verify once, strip untrusted headers/token, and authenticate exact forwarded bytes',async()=>{
   for(const path of ['/api/register/start','/api/register/complete']){
    reset();const body={turnstile_token:'synthetic-human-ok',code:'DEMO00000001',email:'fixture@example.invalid',request_id:crypto.randomUUID()};
    const result=await worker.fetch(request(path,body),env);
    assert.equal(result.status,200);assert.deepEqual(await result.json(),{gate_passed:true});
    assert.equal(siteverifyCalls,1,'BFF must not repeat Siteverify after the Worker consumes the token');
    assert.equal(originCalls,1);assert.equal(downstreamCalls,1);assert.ok(forwarded);
    const captured=forwarded as unknown as {body:string;headers:Headers;path:string};
    assert.equal(captured.path,path);assert.deepEqual(JSON.parse(captured.body),{code:body.code,email:body.email,request_id:body.request_id});
    assert.equal(captured.body.includes('turnstile_token'),false);
    assert.deepEqual([...captured.headers.keys()].filter(name=>name.startsWith('x-gate-')),['x-gate-assertion']);
    assert.notEqual(captured.headers.get('x-gate-assertion'),'synthetic-forged-inbound');
    assert.equal(captured.headers.has('content-length'),false);
    assert.equal(await gate.verifyGateAssertion(captured.headers.get('x-gate-assertion')!,publicJwk,
      bffRequest(path,captured.body,captured.headers)),true);
   }
  });
  await t.test('BFF rejects changed path, changed body and even equivalent JSON bytes without a second Siteverify',async()=>{
   reset();await worker.fetch(request('/api/register/start',{turnstile_token:'synthetic-human-ok',code:'DEMO00000001',email:'fixture@example.invalid'}),env);
   assert.ok(forwarded);const captured=forwarded as unknown as {body:string;headers:Headers;path:string};
   for(const changed of [
    bffRequest('/api/register/complete',captured.body,captured.headers),
    bffRequest(captured.path,captured.body.replace('DEMO00000001','DEMO00000002'),captured.headers),
    bffRequest(captured.path,captured.body+' ',captured.headers),
   ]){
    const res=responseRecorder();assert.equal(await gate.enforceTurnstileGate(changed,res),false);
    assert.equal(res.statusCode,403);assert.deepEqual(res.body,{error:'turnstile_failed'});
   }
   assert.equal(siteverifyCalls,1);assert.equal(downstreamCalls,1);
  });
  await t.test('direct-origin token fallback verifies once and returns the gate result',async()=>{
   for(const [token,allowed]of [['synthetic-human-ok',true],['synthetic-human-invalid',false]]as const){
    reset();const raw=JSON.stringify({turnstile_token:token,code:'DEMO00000001',email:'fixture@example.invalid'}),res=responseRecorder();
    assert.equal(await gate.enforceTurnstileGate(bffRequest('/api/register/start',raw,new Headers()),res),allowed);
    assert.equal(siteverifyCalls,1);assert.equal(originCalls,0);
    if(!allowed){assert.equal(res.statusCode,403);assert.deepEqual(res.body,{error:'turnstile_failed'});}
   }
  });
  await t.test('direct origin rejects absent proof or forged edge assertion without network verification',async()=>{
   for(const headers of [new Headers(),new Headers({'x-gate-assertion':'synthetic-forged-inbound'})]){
    reset();const res=responseRecorder();
    assert.equal(await gate.enforceTurnstileGate(bffRequest('/api/register/start','{}',headers),res),false);
    assert.equal(res.statusCode,403);assert.equal(siteverifyCalls,0);assert.equal(originCalls,0);
   }
  });
 }finally{globalThis.fetch=originalFetch;}
});
