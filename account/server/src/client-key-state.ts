import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {fileURLToPath} from 'node:url';
import {spawn} from 'node:child_process';

export const CLIENT_KEY_PROPAGATION_MS=300_000;
export const CLIENT_KEY_RETENTION_MS=86_400_000;
const MAX_BYTES=262_144,MAX_RETIRED=512;
type PublicKey={kty:'OKP';crv:'Ed25519';x:string;kid:string;alg:'EdDSA';use:'sig'};
type PrivateKey=PublicKey&{d:string};
interface Pending {id:string;key:PrivateKey;created_at:string;published_at:string|null;activate_after:string|null}
interface Retired {key:PublicKey;retired_at:string}
interface State {version:2;generation:string;keys:PublicKey[];current:PrivateKey;rotated_at:string|null;pending:Pending|null;retired:Retired[]}
export interface ClientKeyStatus {
  kid:string;rotated_at:string|null;state:'active'|'pending';
  rotation:null|{id:string;kid:string;published_at:string|null;activate_after:string|null};
}
export class ClientKeyStateError extends Error {
  constructor(readonly code:'client_key_state_invalid'|'client_key_storage_unavailable'|'client_key_rotation_unavailable') {super(code);}
}
const invalid=():never=>{throw new ClientKeyStateError('client_key_state_invalid');};
const uuid=(s:unknown):s is string=>typeof s==='string'&&/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(s);
function date(value:unknown):string {
  if(typeof value!=='string'||!Number.isFinite(Date.parse(value))||new Date(value).toISOString()!==value)return invalid();
  return value;
}
function publicKey(value:unknown):PublicKey {
  if(!value||typeof value!=='object'||Array.isArray(value))return invalid();
  const k=value as Record<string,unknown>;
  if(k.kty!=='OKP'||k.crv!=='Ed25519'||typeof k.x!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(k.x)
    ||typeof k.kid!=='string'||!k.kid||k.kid.length>200||/[\x00-\x20\x7f]/.test(k.kid)
    ||k.alg!==undefined&&k.alg!=='EdDSA'||k.use!==undefined&&k.use!=='sig')return invalid();
  return{kty:'OKP',crv:'Ed25519',x:k.x,kid:k.kid,alg:'EdDSA',use:'sig'};
}
function privateKey(value:unknown):PrivateKey {
  const pub=publicKey(value),d=(value as Record<string,unknown>).d;
  if(typeof d!=='string'||!/^[A-Za-z0-9_-]{43}$/.test(d))return invalid();
  try{
    const key=crypto.createPrivateKey({key:{...pub,d},format:'jwk'});
    const derived=crypto.createPublicKey(key);
    if(derived.export({format:'jwk'}).x!==pub.x)return invalid();
    const probe=Buffer.from('account-client-key-check');
    if(!crypto.verify(null,probe,derived,crypto.sign(null,probe,key)))return invalid();
  }catch{return invalid();}
  return{...pub,d};
}
function generatedKey():PrivateKey {
  const pair=crypto.generateKeyPairSync('ed25519');
  const raw=pair.privateKey.export({format:'jwk'});
  const kid=crypto.createHash('sha256').update(JSON.stringify({crv:raw.crv,kty:raw.kty,x:raw.x})).digest('base64url');
  return privateKey({...raw,kid,alg:'EdDSA',use:'sig'});
}
function projection(s:State,at:number):PublicKey[] {
  return[publicKey(s.current),...(s.pending?[publicKey(s.pending.key)]:[]),
    ...s.retired.filter(r=>Date.parse(r.retired_at)+CLIENT_KEY_RETENTION_MS>at).map(r=>publicKey(r.key))];
}
function encode(s:State):string {
  // keys[0] remains the current signer for existing backup/inspection tooling.
  // Actual legacy signing code must not run concurrently with this state writer.
  return JSON.stringify({...s,keys:[s.current,...(s.pending?[publicKey(s.pending.key)]:[]),...s.retired.map(r=>r.key)]})+'\n';
}
function decode(raw:string,at:number):State {
  let value:Record<string,unknown>;try{value=JSON.parse(raw);}catch{return invalid();}
  if(!value||typeof value!=='object'||Array.isArray(value))return invalid();
  if(value.version===undefined){
    const keys=Array.isArray(value.keys)?value.keys:[value];
    if(!keys.length||keys.length>MAX_RETIRED)return invalid();
    const current=privateKey(keys[0]);
    const retired=keys.slice(1).map(k=>({key:publicKey(k),retired_at:new Date(at).toISOString()}));
    if(new Set([current.kid,...retired.map(r=>r.key.kid)]).size!==keys.length)return invalid();
    const state:State={version:2,generation:'0',current,keys:keys.map(publicKey),rotated_at:value.rotated_at===undefined?null:date(value.rotated_at),pending:null,retired};
    // Leave space for one pending key and its publication metadata.
    if(Buffer.byteLength(encode(state))+2048>MAX_BYTES)return invalid();
    return state;
  }
  if(value.version!==2||typeof value.generation!=='string'||!/^(0|[1-9][0-9]{0,18})$/.test(value.generation)||BigInt(value.generation)>9223372036854775807n
    ||!Array.isArray(value.retired)||value.retired.length>MAX_RETIRED||!Array.isArray(value.keys))return invalid();
  const current=privateKey(value.current),retired=value.retired.map(item=>{
    if(!item||typeof item!=='object')return invalid();
    return{key:publicKey(item.key),retired_at:date(item.retired_at)};
  });
  let pending:Pending|null=null;
  if(value.pending!==null){
    const p=value.pending as Pending;if(!p||!uuid(p.id))return invalid();
    pending={id:p.id,key:privateKey(p.key),created_at:date(p.created_at),published_at:p.published_at===null?null:date(p.published_at),activate_after:p.activate_after===null?null:date(p.activate_after)};
    if((pending.published_at===null)!==(pending.activate_after===null))return invalid();
    if(pending.published_at!==null&&(Date.parse(pending.published_at)<Date.parse(pending.created_at)
      ||Date.parse(pending.activate_after!)!==Date.parse(pending.published_at)+CLIENT_KEY_PROPAGATION_MS))return invalid();
  }
  const s:State={version:2,generation:value.generation,current,keys:[],rotated_at:value.rotated_at===null?null:date(value.rotated_at),pending,retired};
  const expected=[current,...(pending?[publicKey(pending.key)]:[]),...retired.map(r=>r.key)];
  if(JSON.stringify(value.keys)!==JSON.stringify(expected)||new Set(expected.map(k=>k.kid)).size!==expected.length)return invalid();
  s.keys=expected.map(publicKey);return s;
}
function directory(file:string,write=false):string {
  if(!path.isAbsolute(file)||path.normalize(file)!==file)throw new ClientKeyStateError('client_key_storage_unavailable');
  const parent=path.dirname(file),st=fs.lstatSync(parent),uid=process.getuid?.();
  if(!st.isDirectory()||st.isSymbolicLink()||st.mode&0o022||fs.realpathSync(parent)!==parent
    ||uid!==undefined&&st.uid!==uid&&st.uid!==0)throw new ClientKeyStateError('client_key_storage_unavailable');
  if(write)fs.accessSync(parent,fs.constants.W_OK);
  return parent;
}
function read(file:string,at=Date.now()):{state:State;witness:fs.Stats} {
  directory(file);const fd=fs.openSync(file,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  try{
    const st=fs.fstatSync(fd),uid=process.getuid?.();
    if(!st.isFile()||st.nlink!==1||(st.mode&0o777)!==0o600||uid!==undefined&&st.uid!==uid||st.size>MAX_BYTES||st.size===0)return invalid();
    const bytes=Buffer.alloc(st.size+1);let used=0;
    try{
      while(used<bytes.length){const count=fs.readSync(fd,bytes,used,bytes.length-used,null);if(!count)break;used+=count;}
      const after=fs.fstatSync(fd);
      if(after.size!==st.size||after.mtimeMs!==st.mtimeMs||used!==st.size)return invalid();
      let raw:string;try{raw=new TextDecoder('utf-8',{fatal:true}).decode(bytes.subarray(0,used));}catch{return invalid();}
      return{state:decode(raw,at),witness:st};
    }finally{bytes.fill(0);}
  }finally{fs.closeSync(fd);}
}
function sameFile(a:fs.Stats,b:fs.Stats):boolean{return a.dev===b.dev&&a.ino===b.ino&&a.size===b.size&&a.mtimeMs===b.mtimeMs;}
function tempPrefix(file:string):string{return '.account-key-'+crypto.createHash('sha256').update(file).digest('hex').slice(0,24)+'-';}
function cleanOrphans(file:string):void {
  const parent=directory(file,true),prefix=tempPrefix(file);let changed=false;
  // Every writer for this exact state file holds its persistent lock. A different
  // state file in the same directory has a different prefix and lock.
  for(const name of fs.readdirSync(parent)){
    if(!name.startsWith(prefix)||!name.endsWith('.tmp')||!uuid(name.slice(prefix.length,-4)))continue;
    const candidate=path.join(parent,name),st=fs.lstatSync(candidate);
    if(!st.isFile()||st.nlink!==1||(st.mode&0o777)!==0o600||process.getuid&&st.uid!==process.getuid()||st.size>MAX_BYTES)continue;
    fs.unlinkSync(candidate);changed=true;
  }
  if(changed){const fd=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);try{fs.fsyncSync(fd);}finally{fs.closeSync(fd);}}
}
function publish(file:string,state:State,witness:fs.Stats):void {
  const parent=directory(file,true),bytes=encode(state);if(Buffer.byteLength(bytes)>MAX_BYTES)return invalid();
  const temporary=path.join(parent,tempPrefix(file)+crypto.randomUUID()+'.tmp');
  const fd=fs.openSync(temporary,fs.constants.O_WRONLY|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);
  const owned=fs.fstatSync(fd);let closed=false,published=false;
  try{
    fs.fchmodSync(fd,0o600);
    fs.writeFileSync(fd,bytes);fs.fsyncSync(fd);fs.closeSync(fd);closed=true;
    if(!sameFile(fs.lstatSync(file),witness))throw new ClientKeyStateError('client_key_rotation_unavailable');
    fs.renameSync(temporary,file);published=true;
    const dir=fs.openSync(parent,fs.constants.O_RDONLY|fs.constants.O_DIRECTORY);
    try{fs.fsyncSync(dir);}finally{fs.closeSync(dir);}
  }finally{
    if(!closed)fs.closeSync(fd);
    if(!published){try{const st=fs.lstatSync(temporary);if(st.dev===owned.dev&&st.ino===owned.ino)fs.unlinkSync(temporary);}catch{/* Preserve unattributable or uncertain state. */}}
  }
}
function status(s:State):ClientKeyStatus {
  return{kid:s.current.kid,rotated_at:s.rotated_at,state:s.pending?'pending':'active',rotation:s.pending?{
    id:s.pending.id,kid:s.pending.key.kid,published_at:s.pending.published_at,activate_after:s.pending.activate_after}:null};
}
function singleFileMount(file:string):boolean {
  if(process.platform!=='linux')return false;
  const decodeMount=(s:string)=>s.replace(/\\([0-7]{3})/g,(_match,n:string)=>String.fromCharCode(parseInt(n,8)));
  return fs.readFileSync('/proc/self/mountinfo','utf8').split('\n').some(line=>decodeMount(line.split(' ')[4]??'')===file);
}
/** Internal writer entry point. Production callers must hold the persistent OS flock. */
export function applyClientKeyOperationLocked(file:string,operation:'schedule'|'reconcile',now=Date.now,afterPublish?:(phase:'stage'|'arm'|'activate')=>void):ClientKeyStatus {
  directory(file,true);if(singleFileMount(file))throw new ClientKeyStateError('client_key_storage_unavailable');
  let record=read(file,now()),s=record.state;
  cleanOrphans(file);
  const save=(phase:'stage'|'arm'|'activate')=>{
    if(BigInt(s.generation)>=9223372036854775807n)return invalid();
    s.generation=(BigInt(s.generation)+1n).toString();
    publish(file,s,record.witness);afterPublish?.(phase);record=read(file,now());s=record.state;
  };
  if(operation==='schedule'&&!s.pending){
    const at=now();s.retired=s.retired.filter(r=>Date.parse(r.retired_at)+CLIENT_KEY_RETENTION_MS>at);
    if(s.retired.length>=MAX_RETIRED)throw new ClientKeyStateError('client_key_rotation_unavailable');
    s.pending={id:crypto.randomUUID(),key:generatedKey(),created_at:new Date(at).toISOString(),published_at:null,activate_after:null};save('stage');
  }
  if(s.pending&&!s.pending.published_at){
    // This marker is written only after the first state is durably public.
    const at=Math.max(now(),Date.parse(s.pending.created_at));s.pending.published_at=new Date(at).toISOString();
    s.pending.activate_after=new Date(at+CLIENT_KEY_PROPAGATION_MS).toISOString();save('arm');
  }
  if(s.pending&&s.pending.activate_after&&now()>=Date.parse(s.pending.activate_after)){
    const at=now();s.retired=s.retired.filter(r=>Date.parse(r.retired_at)+CLIENT_KEY_RETENTION_MS>at);
    s.retired.push({key:publicKey(s.current),retired_at:new Date(at).toISOString()});
    s.current=s.pending.key;s.pending=null;s.rotated_at=new Date(at).toISOString();save('activate');
  }
  return status(s);
}
function lockFile(file:string):string {
  const lock=file+'.rotation.lock';directory(lock,true);let fd:number,created=false;
  try{fd=fs.openSync(lock,fs.constants.O_RDWR|fs.constants.O_CREAT|fs.constants.O_EXCL|fs.constants.O_NOFOLLOW,0o600);created=true;}
  catch(error){if((error as NodeJS.ErrnoException).code!=='EEXIST')throw error;fd=fs.openSync(lock,fs.constants.O_RDWR|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);}
  try{if(created)fs.fchmodSync(fd,0o600);const st=fs.fstatSync(fd);if(!st.isFile()||st.nlink!==1||(st.mode&0o777)!==0o600||st.size!==0||process.getuid&&st.uid!==process.getuid())throw new ClientKeyStateError('client_key_storage_unavailable');}
  finally{fs.closeSync(fd);}
  return lock;
}
interface WorkerJob {operation:'schedule'|'reconcile';result:Promise<void>}
const workers=new Map<string,WorkerJob>(),signingCooldown=new Map<string,number>();
async function mutate(file:string,operation:'schedule'|'reconcile'):Promise<void> {
  const running=workers.get(file);
  if(running){
    const hadPending=operation==='schedule'?!!read(file).state.pending:true;
    await running.result;
    if(operation==='reconcile'||running.operation==='schedule'||hadPending)return;
    return mutate(file,operation);
  }
  if(process.platform!=='linux')throw new ClientKeyStateError('client_key_storage_unavailable');
  const lock=lockFile(file);fs.accessSync('/usr/bin/flock',fs.constants.X_OK);
  // Source-mode development uses the repository's locked tsx loader. Resolve
  // it from this module rather than cwd and never inherit arbitrary execArgv.
  // Compiled production never resolves or requires this development dependency.
  const source=fileURLToPath(import.meta.url).endsWith('.ts');
  const worker=fileURLToPath(new URL(source?'./client-key-worker.ts':'./client-key-worker.js',import.meta.url));
  const loader=source?['--import',import.meta.resolve('tsx')]:[];
  let resolve!:()=>void,reject!:(error:Error)=>void;
  const result=new Promise<void>((yes,no)=>{resolve=yes;reject=no;}),job:WorkerJob={operation,result};
  workers.set(file,job);let settled=false,failed=false,bytes=0,output='';
  const finish=(ok:boolean)=>{if(settled)return;settled=true;if(ok)resolve();else reject(new ClientKeyStateError('client_key_rotation_unavailable'));};
  let child:ReturnType<typeof spawn>;
  try{child=spawn('/usr/bin/flock',['--exclusive','--wait','5','--no-fork',lock,process.execPath,...loader,worker,operation,file],{stdio:['ignore','pipe','pipe'],shell:false});}
  catch{workers.delete(file);finish(false);return result;}
  const stop=()=>{failed=true;child.kill('SIGKILL');finish(false);};
  const timer=setTimeout(stop,12_000);timer.unref();
  // EMFILE/ENFILE may return a ChildProcess with null streams, then emit
  // error/close on the next tick. Install lifecycle handlers before touching IO.
  child.on('error',()=>{failed=true;finish(false);});
  child.once('close',code=>{
    clearTimeout(timer);if(workers.get(file)===job)workers.delete(file);
    let ok=false;try{const value=JSON.parse(output);ok=value?.ok===true&&Object.keys(value).length===1;}catch{/* No raw child output is exposed. */}
    finish(!failed&&code===0&&ok);
  });
  if(!child.stdout||!child.stderr){failed=true;finish(false);return result;}
  child.stdout.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>16384)stop();else if(!failed)output+=chunk.toString('utf8');});
  child.stderr.on('data',(chunk:Buffer)=>{bytes+=chunk.length;if(bytes>16384)stop();});
  // A timeout bounds the caller, but the entry remains until actual process exit.
  // This prevents new workers from piling up behind an unsettled writer.
  return result;
}
async function reconcile(file:string,forSigning=false):Promise<State> {
  try{
    let s=read(file).state;
    const due=!!s.pending&&(!s.pending.activate_after||Date.now()>=Date.parse(s.pending.activate_after));
    if(due||!forSigning&&process.platform==='linux'){
      if(!forSigning){await mutate(file,'reconcile');signingCooldown.delete(file);}
      else if((signingCooldown.get(file)??0)<=performance.now())void mutate(file,'reconcile')
        .then(()=>signingCooldown.delete(file),()=>signingCooldown.set(file,performance.now()+10_000));
      // Never fall back to an in-memory or historical key. This is the currently
      // durable signer, which remains public even if activation cannot be written.
      // Signing does not wait behind a maintenance lock; status still reports errors.
      s=read(file).state;if(!s.pending)signingCooldown.delete(file);
    }
    return s;
  }catch(error){if(error instanceof ClientKeyStateError)throw error;throw new ClientKeyStateError('client_key_storage_unavailable');}
}
export async function selectClientSigningKey(file:string):Promise<{kid:string;jwk:PrivateKey}> {
  const s=await reconcile(file,true);return{kid:s.current.kid,jwk:{...s.current}};
}
export async function getClientPublicJwks(file:string,now=Date.now):Promise<{keys:PublicKey[]}> {
  try{const at=now(),s=read(file,at).state;return{keys:projection(s,at)};}
  catch(error){if(error instanceof ClientKeyStateError)throw error;throw new ClientKeyStateError('client_key_storage_unavailable');}
}
export async function getClientKeyStatus(file:string):Promise<ClientKeyStatus>{return status(await reconcile(file));}
export async function scheduleClientKeyRotation(file:string):Promise<ClientKeyStatus>{
  try{await mutate(file,'schedule');return status(read(file).state);}
  catch(error){if(error instanceof ClientKeyStateError)throw error;throw new ClientKeyStateError('client_key_storage_unavailable');}
}
