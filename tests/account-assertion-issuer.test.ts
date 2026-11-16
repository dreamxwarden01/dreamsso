import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import ts from 'typescript';
import * as jose from 'jose';

test('Account assertions bind exact POST path while retaining the legacy issuer audience', async () => {
  const {privateKey,publicKey}=await jose.generateKeyPair('EdDSA'),jwk=await jose.exportJWK(privateKey);jwk.kid='fixture-key';
  const issuer='https://sso.example.invalid',client='account',requests:{url:string;init:any}[]=[];
  function load(relative:string,dependencies:Record<string,any>){
    const source=fs.readFileSync(new URL('../account/server/src/'+relative,import.meta.url),'utf8');
    const code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022,esModuleInterop:true}}).outputText;
    const exported:any={};vm.runInNewContext(code,{exports:exported,URL,URLSearchParams,Buffer,Date,AbortSignal,console:{error(){}},
      require:(id:string)=>{assert.ok(Object.hasOwn(dependencies,id),id);return dependencies[id];}});return exported;
  }
  const config={issuer,clientId:client,internal:'https://private-sso.example.invalid',redirectUri:'https://account.example.invalid/auth/callback',clientKeyFile:'unused-fixture'};
  const transport={s2sFetch:async(url:string,init:any)=>{requests.push({url,init});return Response.json({id_token:'fixture',access_token:'fixture',expires_in:900});}};
  const oidc=load('oidc.ts',{'node:crypto':crypto,jose,'./config.js':{config},'./s2sFetch.js':transport,
    './client-key-state.js':{selectClientSigningKey:async()=>({kid:jwk.kid,jwk}),getClientKeyStatus(){},getClientPublicJwks(){},scheduleClientKeyRotation(){}}});
  async function verify(token:string,path:string){
    // This is the old verifier contract: added operation claims remain compatible.
    const {payload,protectedHeader}=await jose.jwtVerify(token,publicKey,{issuer:client,audience:issuer,algorithms:['EdDSA']});
    assert.equal(payload.iss,client);assert.equal(payload.sub,client);assert.equal(payload.aud,issuer);
    assert.equal(payload.method,'POST');assert.equal(payload.path,path);assert.equal(protectedHeader.kid,jwk.kid);
    assert.equal(payload.exp!-payload.iat!,60);assert.match(payload.jti!,/^[a-f0-9-]{36}$/);return payload.jti;
  }
  await oidc.exchangeCode('fixture-code','fixture-verifier');
  await verify(requests.pop()!.init.body.get('client_assertion'),'/token');
  for(const route of ['/internal/token/renew','/internal/reset/request','/internal/settings/turnstile','/internal/email-change/verify']){
    const first=await verify(await oidc.s2sAssertion(route),route),second=await verify(await oidc.s2sAssertion(route),route);assert.notEqual(first,second);
  }
  for(const route of ['', '/internal//reset', '/internal/reset?other', 'https://other.invalid/reset'])await assert.rejects(oidc.s2sAssertion(route),/invalid_assertion_path/);
  const reset=load('routes/reset.ts',{express:{Router:()=>({get(){},post(){}})},'node:crypto':crypto,jose,
    '../config.js':{config},'../oidc.js':oidc,'../session.js':{getSession:async()=>null},'../s2sFetch.js':transport,'./auth.js':{SESSION_COOKIE:'acct_sid'}});
  await reset.s2sPost('/internal/reset/validate',{token:'synthetic'});
  await verify(JSON.parse(requests.pop()!.init.body).client_assertion,'/internal/reset/validate');
  const routes:any[]=[];
  load('routes/api.ts',{express:{Router:()=>Object.fromEntries(['get','post','patch','delete','use'].map(method=>[method,(path:string,...handlers:Function[])=>routes.push({method,path,handlers})])),raw:()=>()=>{}},
    '../config.js':{config},'../oidc.js':oidc,'../s2sFetch.js':transport,'./auth.js':{SESSION_COOKIE:'acct_sid'},'../request-source.js':{isTrustedMutation:()=>true},
    '../session.js':{getSession:async()=>({sub:crypto.randomUUID(),ssoSid:crypto.randomUUID(),accessExpiresAt:0}),updateSession:async()=>true}});
  const handler=routes.find(r=>r.path==='/api/me').handlers[0];let next=false;
  await handler({method:'GET',cookies:{acct_sid:'fixture'}},{status(){return this;},json(){return this;}},()=>{next=true;});assert.equal(next,true);
  await verify(JSON.parse(requests.pop()!.init.body).client_assertion,'/internal/token/renew');
});
