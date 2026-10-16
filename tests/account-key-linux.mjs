import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {fileURLToPath,pathToFileURL} from 'node:url';

const source=process.env.ACCOUNT_KEY_SOURCE==='1';
if(process.env.ACCOUNT_KEY_SOURCE!==undefined&&!source)throw Error('Unsupported source-mode test flag.');
const directory=source?fileURLToPath(new URL('../account/server/src',import.meta.url))
  :process.env.ACCOUNT_KEY_DIST??fileURLToPath(new URL('../account/server/dist',import.meta.url));
const moduleUrl=pathToFileURL(path.join(directory,source?'client-key-state.ts':'client-key-state.js')).href;
const loader=source?['--import',import.meta.resolve('tsx')]:[];
const {scheduleClientKeyRotation,getClientKeyStatus,getClientPublicJwks,selectClientSigningKey,applyClientKeyOperationLocked}=await import(moduleUrl);
const linux={skip:process.platform!=='linux'};
function fixture(){
  const dir=fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(),'account-key-linux-')));fs.chmodSync(dir,0o700);
  const raw=crypto.generateKeyPairSync('ed25519').privateKey.export({format:'jwk'});
  const kid=crypto.createHash('sha256').update(JSON.stringify({crv:raw.crv,kty:raw.kty,x:raw.x})).digest('base64url');
  const file=path.join(dir,'state.json');fs.writeFileSync(file,JSON.stringify({...raw,kid}),{mode:0o600});
  return{dir,file,kid,close:()=>fs.rmSync(dir,{recursive:true,force:true})};
}
function completed(child){return new Promise((resolve,reject)=>{child.once('error',reject);child.once('close',(code,signal)=>resolve({code,signal}));});}
test('Linux flock serializes concurrent schedules into one public pending operation',linux,async()=>{
  const f=fixture();try{
    const results=await Promise.all(Array.from({length:4},()=>scheduleClientKeyRotation(f.file)));
    assert.equal(new Set(results.map(r=>r.rotation.id)).size,1);
    assert.equal(new Set(results.map(r=>r.rotation.kid)).size,1);
    assert.ok(results.every(r=>r.kid===f.kid&&r.state==='pending'));
    assert.equal(JSON.parse(fs.readFileSync(f.file,'utf8')).generation,'2');
    assert.equal((await getClientPublicJwks(f.file)).keys.length,2);
  }finally{f.close();}
});
test('the kernel releases the same persistent lock inode when its holder is killed',linux,async()=>{
  const f=fixture();let holder;
  try{
    await scheduleClientKeyRotation(f.file);const lock=f.file+'.rotation.lock',before=fs.statSync(lock);
    holder=spawn('/usr/bin/flock',['--exclusive','--no-fork',lock,process.execPath,'-e',"process.stdout.write('locked\\n');setInterval(()=>{},1000)"],{stdio:['ignore','pipe','ignore']});
    const done=completed(holder);await new Promise((resolve,reject)=>{holder.once('error',reject);holder.stdout.once('data',resolve);});
    const probe=spawn('/usr/bin/flock',['--exclusive','--nonblock',lock,'/usr/bin/true'],{stdio:'ignore'});
    assert.equal((await completed(probe)).code,1);
    holder.kill('SIGKILL');await done;holder=undefined;
    const retry=spawn('/usr/bin/flock',['--exclusive','--nonblock',lock,'/usr/bin/true'],{stdio:'ignore'});
    assert.equal((await completed(retry)).code,0);
    assert.equal(fs.statSync(lock).ino,before.ino);
  }finally{holder?.kill('SIGKILL');f.close();}
});
test('SIGKILL after first durable publication recovers the same key with a full propagation delay',linux,async()=>{
  const f=fixture();try{
    const lock=f.file+'.rotation.lock';fs.writeFileSync(lock,'',{mode:0o600});
    const script="const m=await import(process.argv[1]);m.applyClientKeyOperationLocked(process.argv[2],'schedule',Date.now,phase=>{if(phase==='stage')process.kill(process.pid,'SIGKILL')});";
    const child=spawn('/usr/bin/flock',['--exclusive','--no-fork',lock,process.execPath,...loader,'--input-type=module','-e',script,moduleUrl,f.file],{stdio:'ignore'});
    assert.equal((await completed(child)).signal,'SIGKILL');
    const stored=JSON.parse(fs.readFileSync(f.file,'utf8'));
    assert.equal(stored.pending.published_at,null);assert.equal(stored.current.kid,f.kid);
    const before=Date.now(),recovered=await getClientKeyStatus(f.file);
    assert.equal(recovered.state,'pending');assert.equal(recovered.rotation.id,stored.pending.id);
    assert.equal(recovered.rotation.kid,stored.pending.key.kid);assert.equal(recovered.kid,f.kid);
    assert.ok(Date.parse(recovered.rotation.activate_after)>=before+300_000);
    assert.equal(fs.readdirSync(f.dir).filter(n=>n.endsWith('.tmp')).length,0);
  }finally{f.close();}
});

test('eligible signing requests coalesce activation and return only a durably published key/kid pair',linux,async()=>{
  const f=fixture();try{
    const staged=applyClientKeyOperationLocked(f.file,'schedule',()=>Date.now()-400_000);
    const selections=await Promise.all(Array.from({length:32},()=>selectClientSigningKey(f.file)));
    for(const selection of selections){assert.equal(selection.kid,selection.jwk.kid);assert.ok([f.kid,staged.rotation.kid].includes(selection.kid));}
    const active=await getClientKeyStatus(f.file);assert.equal(active.kid,staged.rotation.kid);
    assert.equal(JSON.parse(fs.readFileSync(f.file,'utf8')).generation,'3');
  }finally{f.close();}
});

test('a blocked activation cannot block signing; status reports the failure and later reconciles',linux,async()=>{
  const f=fixture();let holder;
  try{
    const staged=applyClientKeyOperationLocked(f.file,'schedule',()=>Date.now()-400_000);
    const lock=f.file+'.rotation.lock';fs.writeFileSync(lock,'',{mode:0o600});
    holder=spawn('/usr/bin/flock',['--exclusive','--no-fork',lock,process.execPath,'-e',"process.stdout.write('locked\\n');setInterval(()=>{},1000)"],{stdio:['ignore','pipe','ignore']});
    const done=completed(holder);await new Promise((resolve,reject)=>{holder.once('error',reject);holder.stdout.once('data',resolve);});
    const start=performance.now(),selected=await selectClientSigningKey(f.file);
    assert.equal(selected.kid,f.kid);assert.ok(performance.now()-start<1000);
    await assert.rejects(getClientKeyStatus(f.file));
    holder.kill('SIGKILL');await done;holder=undefined;
    assert.equal((await getClientKeyStatus(f.file)).kid,staged.rotation.kid);
  }finally{holder?.kill('SIGKILL');f.close();}
});


test('descriptor exhaustion cannot crash the signing process or retain a failed worker forever',linux,async()=>{
  const f=fixture();
  const script=String.raw`
    import fs from 'node:fs';import assert from 'node:assert/strict';
    const m=await import(process.argv[1]),file=process.argv[2],held=[];
    try{
      const pending=m.applyClientKeyOperationLocked(file,'schedule',()=>Date.now()-400000);
      while(true){try{held.push(fs.openSync('/dev/null','r'));}catch(e){if(e.code!=='EMFILE')throw e;break;}}
      fs.closeSync(held.pop());
      const selected=await m.selectClientSigningKey(file);assert.equal(selected.kid,pending.kid);
      for(const fd of held.splice(0))fs.closeSync(fd);
      await new Promise(resolve=>setTimeout(resolve,100));
      const status=await m.getClientKeyStatus(file);assert.equal(status.kid,pending.rotation.kid);
      process.stdout.write('recovered\n');
    }finally{for(const fd of held)fs.closeSync(fd);}
  `;
  try{
    // Fixed shell fragment only sets this child's descriptor bound; all program
    // arguments are separate argv entries, never interpolated into shell text.
    const child=spawn('/bin/sh',['-c','ulimit -n 64; exec "$@"','account-key-fd-fixture',process.execPath,...loader,'--input-type=module','-e',script,moduleUrl,f.file],{stdio:['ignore','pipe','pipe']});
    let output='',errors='';child.stdout.on('data',chunk=>{output+=chunk;});child.stderr.on('data',chunk=>{errors+=chunk;});
    const result=await completed(child);assert.equal(result.code,0,errors);assert.equal(output,'recovered\n');
  }finally{f.close();}
});
