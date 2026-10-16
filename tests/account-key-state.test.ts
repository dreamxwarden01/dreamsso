import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {applyClientKeyOperationLocked,getClientPublicJwks,selectClientSigningKey,ClientKeyStateError,
  CLIENT_KEY_PROPAGATION_MS,CLIENT_KEY_RETENTION_MS} from '../account/server/src/client-key-state.js';

function fixture() {
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'account-key-state-')));fs.chmodSync(dir,0o700);
  const key=crypto.generateKeyPairSync('ed25519').privateKey.export({format:'jwk'});
  const kid=crypto.createHash('sha256').update(JSON.stringify({crv:key.crv,kty:key.kty,x:key.x})).digest('base64url');
  const file=path.join(dir,'client-key.json');fs.writeFileSync(file,JSON.stringify({...key,kid,alg:'EdDSA',use:'sig'}),{mode:0o600});
  return{dir,file,kid,close:()=>fs.rmSync(dir,{recursive:true,force:true})};
}
test('account rotation publishes first, arms after persistence, and keeps current signer until eligibility',async()=>{
  const f=fixture(),base=Date.now();let clock=base;
  try{
    const phases:string[]=[];
    const staged=applyClientKeyOperationLocked(f.file,'schedule',()=>clock,phase=>{
      phases.push(phase);if(phase==='stage')clock+=60_000;
    });
    assert.deepEqual(phases,['stage','arm']);assert.equal(staged.kid,f.kid);assert.equal(staged.state,'pending');
    assert.equal(Date.parse(staged.rotation!.published_at!),base+60_000);
    assert.equal(Date.parse(staged.rotation!.activate_after!),base+60_000+CLIENT_KEY_PROPAGATION_MS);
    const published=await getClientPublicJwks(f.file,()=>clock);
    assert.deepEqual(published.keys.map(k=>k.kid),[f.kid,staged.rotation!.kid]);
    assert.ok(published.keys.every(k=>!Object.keys(k).some(n=>['d','p','q','dp','dq','qi','k'].includes(n))));
    const repeated=applyClientKeyOperationLocked(f.file,'schedule',()=>clock);
    assert.equal(repeated.rotation!.id,staged.rotation!.id);
    clock=Date.parse(staged.rotation!.activate_after!)-1;
    assert.equal(applyClientKeyOperationLocked(f.file,'reconcile',()=>clock).kid,f.kid);
    clock++;
    const active=applyClientKeyOperationLocked(f.file,'reconcile',()=>clock);
    assert.equal(active.state,'active');assert.equal(active.kid,staged.rotation!.kid);assert.equal(active.rotation,null);
    const selected=await selectClientSigningKey(f.file);assert.equal(selected.kid,active.kid);
    assert.equal(selected.jwk.kid,selected.kid);
    assert.equal((await getClientPublicJwks(f.file,()=>clock+CLIENT_KEY_RETENTION_MS-1)).keys.length,2);
    assert.equal((await getClientPublicJwks(f.file,()=>clock+CLIENT_KEY_RETENTION_MS)).keys.length,1);
    assert.equal(fs.statSync(f.file).mode&0o777,0o600);
  }finally{f.close();}
});
test('interruption after public-key commit recovers the same unarmed key with a fresh full waiting window',async()=>{
  const f=fixture(),base=Date.now();
  try{
    assert.throws(()=>applyClientKeyOperationLocked(f.file,'schedule',()=>base,phase=>{if(phase==='stage')throw Error('synthetic interruption');}));
    const before=await getClientPublicJwks(f.file,()=>base);assert.equal(before.keys.length,2);
    const recovered=applyClientKeyOperationLocked(f.file,'reconcile',()=>base+900_000);
    assert.equal(recovered.state,'pending');assert.equal(recovered.kid,f.kid);assert.equal(recovered.rotation!.kid,before.keys[1]!.kid);
    assert.equal(Date.parse(recovered.rotation!.activate_after!),base+900_000+CLIENT_KEY_PROPAGATION_MS);
    assert.equal(applyClientKeyOperationLocked(f.file,'reconcile',()=>base).state,'pending');
  }finally{f.close();}
});
test('private key and filesystem integrity errors do not regenerate or expose keys',async()=>{
  const f=fixture();
  try{
    const original=fs.readFileSync(f.file);
    const rejects=()=>assert.rejects(getClientPublicJwks(f.file),ClientKeyStateError);
    fs.chmodSync(f.file,0o644);await rejects();fs.chmodSync(f.file,0o600);
    const hard=path.join(f.dir,'hard');fs.linkSync(f.file,hard);await rejects();fs.unlinkSync(hard);
    const target=path.join(f.dir,'original');fs.renameSync(f.file,target);fs.symlinkSync(target,f.file);await rejects();fs.unlinkSync(f.file);fs.renameSync(target,f.file);
    const invalid=JSON.parse(original.toString());invalid.x=crypto.generateKeyPairSync('ed25519').publicKey.export({format:'jwk'}).x;
    fs.writeFileSync(f.file,JSON.stringify(invalid));await rejects();fs.writeFileSync(f.file,original);
    fs.chmodSync(f.dir,0o777);await rejects();fs.chmodSync(f.dir,0o700);
    assert.equal((await getClientPublicJwks(f.file)).keys[0]!.kid,f.kid);
    assert.ok(fs.readFileSync(f.file).equals(original));
    assert.deepEqual(fs.readdirSync(f.dir),['client-key.json']);
  }finally{f.close();}
});

test('orphan cleanup is restricted to the same state-file namespace and never follows links',()=>{
  const f=fixture();try{
    const prefix='.account-key-'+crypto.createHash('sha256').update(f.file).digest('hex').slice(0,24)+'-';
    const orphan=path.join(f.dir,prefix+crypto.randomUUID()+'.tmp');fs.writeFileSync(orphan,'synthetic abandoned state',{mode:0o600});
    const other=path.join(f.dir,'.account-key-'+crypto.createHash('sha256').update(f.file+'.other').digest('hex').slice(0,24)+'-'+crypto.randomUUID()+'.tmp');fs.writeFileSync(other,'another state namespace',{mode:0o600});
    const link=path.join(f.dir,prefix+crypto.randomUUID()+'.tmp');fs.symlinkSync(f.file,link);
    applyClientKeyOperationLocked(f.file,'reconcile');
    assert.equal(fs.existsSync(orphan),false);assert.equal(fs.existsSync(other),true);assert.equal(fs.lstatSync(link).isSymbolicLink(),true);
  }finally{f.close();}
});
test('restrictive umask does not publish unreadable state and v2 metadata cannot be altered inconsistently',async()=>{
  const f=fixture(),old=process.umask();try{
    process.umask(0o777);applyClientKeyOperationLocked(f.file,'schedule');process.umask(old);
    assert.equal(fs.statSync(f.file).mode&0o777,0o600);
    const raw=fs.readFileSync(f.file,'utf8'),value=JSON.parse(raw);
    value.pending.activate_after=new Date(Date.parse(value.pending.activate_after)-1).toISOString();
    fs.writeFileSync(f.file,JSON.stringify(value));await assert.rejects(getClientPublicJwks(f.file),ClientKeyStateError);
    fs.writeFileSync(f.file,raw);value.pending.activate_after=JSON.parse(raw).pending.activate_after;value.keys[0].kid='other';
    fs.writeFileSync(f.file,JSON.stringify(value));await assert.rejects(getClientPublicJwks(f.file),ClientKeyStateError);
  }finally{process.umask(old);f.close();}
});
test('legacy data is accepted only when its staged representation fits the durable state bounds',async()=>{
  const f=fixture();try{
    const first=JSON.parse(fs.readFileSync(f.file,'utf8'));
    const keys=Array.from({length:513},(_v,i)=>({...first,kid:'legacy-'+i,...(i?{d:undefined}:{})}));
    fs.writeFileSync(f.file,JSON.stringify({keys}));await assert.rejects(getClientPublicJwks(f.file),ClientKeyStateError);
    keys.length=500;for(let i=0;i<keys.length;i++)keys[i].kid='a'.repeat(190)+i;
    fs.writeFileSync(f.file,JSON.stringify({keys}));await assert.rejects(getClientPublicJwks(f.file),ClientKeyStateError);
  }finally{f.close();}
});
