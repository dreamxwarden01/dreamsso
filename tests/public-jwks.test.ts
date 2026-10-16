import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import {request as httpRequest} from 'node:http';
import type {AddressInfo} from 'node:net';
import type {JSONWebKeySet} from 'jose';
import {createJwksRouter} from '../src/routes/jwks.js';
import {createAccountJwksRouter} from '../account/server/src/routes/jwks.js';

const publicKey=(kid:string)=>({kty:'OKP',crv:'Ed25519',x:'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',kid,alg:'EdDSA',use:'sig'});
const privateKey=(kid:string)=>({...publicKey(kid),d:'synthetic-private',p:'synthetic-p',q:'synthetic-q',dp:'synthetic-dp',dq:'synthetic-dq',qi:'synthetic-qi',k:'synthetic-k'});
for(const component of ['sso','account'] as const){
  test(component+' public JWKS is GET-only, cacheable on success and never cacheable on failure',async()=>{
    let calls=0,blocked=false,failure=false,invalidProjection=false;
    const expected={keys:component==='sso'?['current','next','retired'].map(publicKey):['current','previous'].map(publicKey)};
    let accountFile=JSON.stringify({keys:['current','previous'].map(privateKey),rotated_at:'2026-01-01T00:00:00Z'});
    const app=express();app.disable('etag');
    const gate:express.RequestHandler=(_req,res,next)=>{if(blocked){res.set('Cache-Control','no-store').status(503).end();return;}next();};
    const path=component==='sso'?'/jwks':'/.well-known/jwks.json';
    // The production routes resolve JWKS methods after their setup gate and
    // before global body parsing; unrelated routes still use the normal parsers.
    if(component==='sso'){
      app.use(gate);
      app.use(createJwksRouter(async()=>{
        calls++;if(failure)throw Error('synthetic-private-database-error');
        if(invalidProjection){const circular:Record<string,unknown>={};circular.keys=circular;return circular as unknown as JSONWebKeySet;}
        return expected;
      }));
    }else app.use(createAccountJwksRouter(async()=>{calls++;await Promise.resolve();if(failure)throw Error('synthetic-private-file-error');return accountFile;},gate));
    app.use(express.json({limit:'1kb'}));app.post('/ordinary',(_req,res)=>{res.status(204).end();});
    app.use((error:{status?:number},_req:express.Request,res:express.Response,_next:express.NextFunction)=>{res.set('Cache-Control','no-store').status(error.status??500).json({error:'invalid_request'});});
    const server=app.listen(0,'127.0.0.1');await new Promise<void>(r=>server.once('listening',r));
    const port=(server.address() as AddressInfo).port;
    const send=(method='GET',body?:string,url=path)=>new Promise<{status:number;headers:Record<string,unknown>;body:string}>((resolve,reject)=>{
      const req=httpRequest({hostname:'127.0.0.1',port,path:url,method,headers:body===undefined?{}:{'Content-Type':'application/json','Content-Length':String(Buffer.byteLength(body))}},res=>{
        const chunks:Buffer[]=[];res.on('data',chunk=>chunks.push(Buffer.from(chunk)));res.on('end',()=>resolve({status:res.statusCode!,headers:res.headers,body:Buffer.concat(chunks).toString()}));
      });req.on('error',reject);req.end(body);
    });
    try{
      const good=await send();assert.equal(good.status,200);assert.equal(good.headers['cache-control'],'public, max-age=120, must-revalidate');
      assert.match(String(good.headers['content-type']),/^application\/json/);assert.deepEqual(JSON.parse(good.body),expected);assert.equal(good.headers['set-cookie'],undefined);assert.equal(calls,1);
      for(const method of ['HEAD','POST','PUT','PATCH','DELETE','OPTIONS','TRACE','PROPFIND']){
        // A malformed body must not reach a parser or trigger a key read.
        const denied=await send(method,method==='HEAD'?undefined:'{');
        assert.equal(denied.status,405,method);assert.equal(denied.headers.allow,'GET',method);assert.equal(denied.headers['cache-control'],'no-store',method);
        if(method==='HEAD')assert.equal(denied.body,'');else assert.deepEqual(JSON.parse(denied.body),{error:'method_not_allowed'});
      }
      assert.equal(calls,1);assert.equal((await send('POST','{','/ordinary')).status,400);
      failure=true;const unavailable=await send();assert.equal(unavailable.status,500);assert.equal(unavailable.headers['cache-control'],'no-store');
      assert.deepEqual(JSON.parse(unavailable.body),{error:'keys_unavailable'});assert.doesNotMatch(unavailable.body,/synthetic-private/);failure=false;
      if(component==='sso')invalidProjection=true;else accountFile='{';
      const malformed=await send();assert.equal(malformed.status,500);assert.equal(malformed.headers['cache-control'],'no-store');assert.deepEqual(JSON.parse(malformed.body),{error:'keys_unavailable'});
      if(component==='sso')invalidProjection=false;else accountFile=JSON.stringify(privateKey('legacy-single'));
      const recovered=await send();assert.equal(recovered.status,200);assert.equal(recovered.headers['cache-control'],'public, max-age=120, must-revalidate');
      assert.deepEqual(JSON.parse(recovered.body),component==='sso'?expected:{keys:[publicKey('legacy-single')]});
      blocked=true;const before=calls;
      for(const method of ['GET','HEAD','POST']){const result=await send(method,method==='POST'?'{':undefined);assert.equal(result.status,503);assert.equal(result.headers['cache-control'],'no-store');}
      assert.equal(calls,before);
    }finally{server.closeAllConnections();await new Promise<void>(resolve=>server.close(()=>resolve()));}
  });
}
