import test from 'node:test';
import assert from 'node:assert/strict';
import express from 'express';
import {generateKeyPair,SignJWT} from 'jose';
import type {AddressInfo} from 'node:net';
import {createClientKeyRouter} from '../account/server/src/routes/client-key.js';

test('Account signed GET only reads/reconciles status; schedule is POST-only and nonce protected',async()=>{
  const pair=await generateKeyPair('EdDSA'),other=await generateKeyPair('EdDSA');let schedules=0,reads=0,failNonce=false,failState=false;
  const claimed=new Set<string>();const pending={kid:'old',rotated_at:null,state:'pending' as const,rotation:{id:'op',kid:'new',published_at:'2026-01-01T00:00:00Z',activate_after:'2026-01-01T00:05:00Z'}};
  const app=express();app.use(express.json());app.use(createClientKeyRouter({issuer:()=> 'https://sso.example',audience:()=> 'account',verificationKey:async()=>pair.publicKey,
    claimNonce:async key=>{if(failNonce)throw Error('private redis error');if(claimed.has(key))return false;claimed.add(key);return true;},
    schedule:async()=>{schedules++;if(failState)throw Error('private key error');return pending;},status:async()=>{reads++;if(failState)throw Error('private key error');return pending;},
  }));
  const server=app.listen(0,'127.0.0.1');await new Promise<void>(resolve=>server.once('listening',resolve));
  const base=`http://127.0.0.1:${(server.address() as AddressInfo).port}/internal/rotate-client-key`;
  const signed=(read=true,extra={},privateKey=pair.privateKey)=>new SignJWT(read?{method:'GET',path:'/internal/rotate-client-key',...extra}:extra)
    .setProtectedHeader({alg:'EdDSA',typ:read?'client-key-status+jwt':'rotate+jwt'}).setIssuer('https://sso.example').setAudience('account').setIssuedAt().setExpirationTime('60s').setJti(crypto.randomUUID()).sign(privateKey);
  const send=(method:string,token='')=>fetch(base,{method,headers:method==='POST'?{'Content-Type':'application/json'}:{Authorization:'Bearer '+token},...(method==='POST'?{body:JSON.stringify({token})}:{})});
  try{
    const token=await signed(),r=await send('GET',token);assert.equal(r.status,200);assert.deepEqual(await r.json(),pending);assert.equal(schedules,0);assert.equal(reads,1);assert.equal(r.headers.get('cache-control'),'no-store');
    assert.equal((await send('GET',token)).status,401);
    assert.equal((await send('POST',await signed(false))).status,202);assert.equal(schedules,1);
    for(const method of ['HEAD','PUT','PATCH','DELETE','OPTIONS']){const result=await send(method);assert.equal(result.status,405);assert.equal(result.headers.get('allow'),'GET, POST');assert.equal(result.headers.get('cache-control'),'no-store');}
    for(const bad of [await signed(false),await signed(true,{method:'POST'}),await signed(true,{path:'/wrong'}),await signed(true,{},other.privateKey),'bad'])assert.equal((await send('GET',bad)).status,401);
    assert.equal((await send('POST',await signed())).status,401);assert.equal(schedules,1);assert.equal(reads,1);
    failNonce=true;let unavailable=await send('GET',await signed());assert.equal(unavailable.status,503);assert.deepEqual(await unavailable.json(),{error:'replay_guard_unavailable'});
    failNonce=false;failState=true;unavailable=await send('GET',await signed());assert.equal(unavailable.status,503);assert.deepEqual(await unavailable.json(),{error:'client_key_unavailable'});
  }finally{server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
});


test('SSO relay accepts only bounded public key status and rejects old portal HTML or malformed success',async()=>{
  const {readClientKeyStatus}=await import('../src/clientKeyStatus.js');
  const status={kid:'old',rotated_at:null,state:'pending',rotation:{id:crypto.randomUUID(),kid:'next',published_at:'2026-01-01T00:00:00Z',activate_after:'2026-01-01T00:05:00Z'}};
  assert.deepEqual(await readClientKeyStatus(Response.json({...status,privateKey:'synthetic-must-not-forward'})),status);
  const legacy={kid:'legacy:key.v1',rotated_at:null,state:'active',rotation:null};
  assert.deepEqual(await readClientKeyStatus(Response.json(legacy)),legacy,'relay preserves the store-supported legacy kid syntax');
  for(const response of [new Response('<html>old portal</html>',{headers:{'Content-Type':'text/html'}}),Response.json({kid:'legacy-immediate'}),Response.json({...status,rotation:null}),Response.json({...status,rotation:{...status.rotation,activate_after:'2026-01-01T00:00:01Z'}}),new Response('x'.repeat(8193),{headers:{'Content-Type':'application/json'}})])
    await assert.rejects(readClientKeyStatus(response),/portal_key_status_invalid/);
});
