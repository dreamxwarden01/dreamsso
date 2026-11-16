import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import ts from 'typescript';
function gate() { let resolve!: () => void, reject!: (e: Error) => void; return { promise: new Promise<void>((a,b) => {resolve=a;reject=b;}), resolve: () => resolve(), reject: () => reject(Error('synthetic_effect_failure')) }; }
function fixture() {
  const events: any[]=[{id:crypto.randomUUID(),type:'logout',payload:{sub:crypto.randomUUID(),sid:crypto.randomUUID()}}];
  const completed=new Map<string,string>(),calls:any[]=[],pending:Promise<void>[]=[];let failReceipt=false;
  const redis={get:async(key:string)=>completed.get(key)||null,set:async(key:string,value:string)=>{if(failReceipt){failReceipt=false;throw Error('synthetic_receipt_failure');}completed.set(key,value);return 'OK';}};
  function reload(){
    let handler!:Function;
    const dependencies:Record<string,any>={express:{Router:()=>({post:(_path:string,fn:Function)=>{handler=fn;}})},
      jose:{jwtVerify:async()=>({payload:{events}}),createRemoteJWKSet:()=>()=>{}},
      '../config.js':{config:{internal:'https://sso.invalid',issuer:'https://sso.invalid',clientId:'account'}},'../redis.js':{redis},
      '../session.js':{revokeBySsoSid:async(...args:any[])=>{calls.push(args);const work=pending.shift();if(work)await work;}}};
    const source=fs.readFileSync(new URL('../account/server/src/routes/backchannel.ts',import.meta.url),'utf8');
    const code=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
    vm.runInNewContext(code,{exports:{},URL,console:{log(){},error(){}},require:(id:string)=>{assert.ok(Object.hasOwn(dependencies,id),id);return dependencies[id];}});
    return async()=>{const res={statusCode:200,ended:false,setHeader(){return this;},status(code:number){this.statusCode=code;return this;},json(){this.ended=true;return this;},end(){this.ended=true;return this;}};await handler({body:{event_token:'verified-fixture'}},res);return res;};
  }
  return{events,completed,calls,pending,reload,failReceipt(){failReceipt=true;}};
}
test('Account duplicate logout waits for its own effect; failed originals are not prematurely acknowledged',async()=>{
  const f=fixture(),a=gate(),b=gate();f.pending.push(a.promise,b.promise);let settled=0;
  const first=f.reload()().then(x=>{settled++;return x;}),second=f.reload()().then(x=>{settled++;return x;});
  await new Promise(resolve=>setImmediate(resolve));assert.equal(f.calls.length,2);assert.equal(settled,0);
  a.reject();b.reject();assert.equal((await first).statusCode,500);assert.equal((await second).statusCode,500);assert.equal(f.completed.size,0);
  assert.equal((await f.reload()()).statusCode,204);assert.equal(f.calls.length,3);
  assert.equal((await f.reload()()).statusCode,204);assert.equal(f.calls.length,3);
});
test('Account ignores legacy seen marker and retries a completed effect whose completion receipt failed',async()=>{
  const f=fixture();f.completed.set('evt:seen:'+f.events[0].id,'1');f.failReceipt();
  assert.equal((await f.reload()()).statusCode,500);assert.equal(f.calls.length,1);
  assert.equal((await f.reload()()).statusCode,204);assert.equal(f.calls.length,2);
  assert.equal((await f.reload()()).statusCode,204);assert.equal(f.calls.length,2);
});
test('Account validates every logout subject/SID before beginning the batch',async()=>{
  const f=fixture();f.events.push({...f.events[0],id:crypto.randomUUID(),payload:{sid:f.events[0].payload.sid,sub:'invalid'}});
  assert.equal((await f.reload()()).statusCode,400);assert.equal(f.calls.length,0);assert.equal(f.completed.size,0);
});
