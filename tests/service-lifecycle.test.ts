import assert from 'node:assert/strict';
import test from 'node:test';
import {createServer,type Server} from 'node:http';
import {spawn} from 'node:child_process';
import {connect} from 'node:net';
import {readFile} from 'node:fs/promises';
import {fileURLToPath} from 'node:url';
import {ActiveTasks,ServiceLifecycle,SHUTDOWN_BUDGET_MS,safeLifecycleError,type LifecycleOptions} from '../src/lifecycle.js';
import {ServiceLifecycle as AccountLifecycle} from '../account/server/src/lifecycle.js';
const deferred=()=>{let resolve!:()=>void;const promise=new Promise<void>(yes=>{resolve=yes;});return{promise,resolve};};
const turn=()=>new Promise<void>(resolve=>setImmediate(resolve));
const address=(server:Server)=>'http://127.0.0.1:'+(server.address()as {port:number}).port;
const implementations=[['SSO',(options:LifecycleOptions)=>new ServiceLifecycle(options)],['Account',(options:LifecycleOptions)=>new AccountLifecycle(options)]] as const;

for(const [name,create] of implementations){
 test(name+': accepted HTTP and started jobs settle before clients close; new work stops',async()=>{
  const accepted=deferred(),reply=deferred(),job=deferred(),actualChildClose=deferred(),order:string[]=[],exits:number[]=[];
  const lifecycle=create({budgetMs:2000,quiesce:()=>order.push('quiesce'),drain:()=>actualChildClose.promise,close:async()=>{order.push('clients');},force:()=>order.push('force'),exit:code=>exits.push(code)});
  await lifecycle.boot(()=>{lifecycle.every(()=>job.promise,60_000);});
  const server=lifecycle.listen(()=>createServer(async(_req,res)=>{accepted.resolve();await reply.promise;res.end('accepted work committed');}).listen(0,'127.0.0.1'))!;
  await new Promise<void>((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});
  const url=address(server),response=fetch(url);await accepted.promise;
  const first=lifecycle.stop(),second=lifecycle.stop();assert.equal(first,second);assert.equal(lifecycle.stopping,true);assert.deepEqual(order,['quiesce']);
  let newer=0;lifecycle.every(async()=>{newer++;},1);assert.equal(lifecycle.listen(()=>{throw Error('must not open another listener');}),null);
  await assert.rejects(fetch(url,{signal:AbortSignal.timeout(500)}));
  reply.resolve();assert.equal(await(await response).text(),'accepted work committed');await turn();assert.deepEqual(exits,[]);assert.ok(!order.includes('clients'));
  // A caller can fail before a key worker's process closes; cleanup must still wait.
  job.resolve();await turn();assert.ok(!order.includes('clients'));
  actualChildClose.resolve();await first;
  assert.deepEqual(order,['quiesce','clients']);assert.deepEqual(exits,[0]);assert.equal(newer,0);
 });
 test(name+': stopping during awaited startup never starts HTTP or new jobs',async()=>{
  const bootGate=deferred(),exits:number[]=[];let starts=0,closed=0;
  const lifecycle=create({quiesce:()=>{},drain:async()=>{},close:async()=>{closed++;},force:()=>{},exit:code=>exits.push(code),budgetMs:1000});
  const boot=lifecycle.boot(async()=>{await bootGate.promise;lifecycle.listen(()=>{starts++;return createServer();});lifecycle.every(async()=>{starts++;},1);});
  await turn();const stopping=lifecycle.stop();assert.deepEqual(exits,[]);bootGate.resolve();await boot;await stopping;
  assert.equal(starts,0);assert.equal(closed,1);assert.deepEqual(exits,[0]);
 });
 test(name+': startup rejection after shutdown begins preserves failure status and closes clients once',async()=>{
  const gate=deferred(),exits:number[]=[];let closed=0;
  const lifecycle=create({quiesce:()=>{},drain:async()=>{},close:async()=>{closed++;},force:()=>{},exit:code=>exits.push(code),budgetMs:1000});
  const boot=lifecycle.boot(async()=>{await gate.promise;throw Object.assign(Error('sensitive synthetic configuration'),{code:'ECONNREFUSED'});});
  const caught=boot.catch(error=>{assert.equal(safeLifecycleError(error),'Error:ECONNREFUSED');void lifecycle.stop(1);});
  await turn();const stopping=lifecycle.stop();gate.resolve();await caught;await stopping;
  assert.deepEqual(exits,[1]);assert.equal(closed,1);
 });
 test(name+': listener failure reports only safe diagnostics and exits unsuccessfully',async()=>{
  const exits:number[]=[],reports:string[]=[];
  const lifecycle=create({quiesce:()=>{},drain:async()=>{},close:async()=>{},force:()=>{},exit:code=>exits.push(code),report:code=>reports.push(code)});
  const server=lifecycle.listen(()=>createServer())!;
  server.emit('error',Object.assign(Error('sensitive binding address'),{code:'EADDRINUSE'}));await lifecycle.stop();
  assert.deepEqual(reports,['http_server_failed Error:EADDRINUSE']);assert.deepEqual(exits,[1]);
 });
 test(name+': bounded deadline closes stuck HTTP and forces failure without closing clients under live work',async()=>{
  const entered=deferred(),reply=deferred(),exits:number[]=[],order:string[]=[];
  const lifecycle=create({quiesce:()=>{},drain:async()=>{},close:async()=>{order.push('clients');},force:()=>{order.push('force');},exit:code=>exits.push(code),budgetMs:60});
  const server=lifecycle.listen(()=>createServer(async(_req,res)=>{entered.resolve();await reply.promise;res.end();}).listen(0,'127.0.0.1'))!;
  await new Promise<void>((resolve,reject)=>{server.once('listening',resolve);server.once('error',reject);});const request=fetch(address(server));const rejected=assert.rejects(request);await entered.promise;
  await lifecycle.stop();await rejected;assert.deepEqual(exits,[1]);assert.deepEqual(order,['force']);reply.resolve();await turn();assert.ok(!order.includes('clients'));
 });
 test(name+': client cleanup failure still forces residual resources closed and exits unsuccessfully',async()=>{
  const exits:number[]=[],order:string[]=[];
  const lifecycle=create({quiesce:()=>{},drain:async()=>{},close:async()=>{throw Error('synthetic cleanup failure');},force:()=>order.push('force'),exit:code=>exits.push(code),budgetMs:500});
  await lifecycle.stop();assert.deepEqual(exits,[1]);assert.deepEqual(order,['force']);
 });
}

test('actual task settlement is independent from an earlier rejected caller promise',async()=>{
 const tasks=new ActiveTasks(),closed=deferred();let settled=false;
 const caller=Promise.reject(Error('bounded caller timeout'));await assert.rejects(caller);
 tasks.track(closed.promise);const wait=tasks.settle().then(()=>{settled=true;});await turn();assert.equal(settled,false);closed.resolve();await wait;assert.equal(settled,true);
});

test('both isolated package builds use the same lifecycle implementation and leave 15s Docker margin',async()=>{
 assert.equal(SHUTDOWN_BUDGET_MS,45_000);assert.equal(60_000-SHUTDOWN_BUDGET_MS,15_000);
 assert.equal(await readFile(new URL('../src/lifecycle.ts',import.meta.url),'utf8'),await readFile(new URL('../account/server/src/lifecycle.ts',import.meta.url),'utf8'));
});

for(const signal of ['SIGTERM','SIGINT'] as const)test('real '+signal+' drains accepted HTTP, then jobs, and exits once with zero',async()=>{
 const module=fileURLToPath(new URL('../src/lifecycle.ts',import.meta.url)),loader=import.meta.resolve('tsx');
 const source=`import {createServer} from 'node:http';import {pathToFileURL} from 'node:url';const {ServiceLifecycle,installShutdownSignals}=await import(pathToFileURL(process.argv[1]));let job;const pending=new Promise(r=>job=r);const lifecycle=new ServiceLifecycle({budgetMs:2000,quiesce:()=>{process.stdout.write('STOPPING\\n');setTimeout(job,120);},drain:()=>pending,close:async()=>{process.stdout.write('CLOSED\\n');},force:()=>{},exit:code=>process.exit(code)});installShutdownSignals(lifecycle);lifecycle.listen(()=>createServer((_req,res)=>{process.stdout.write('ACCEPTED\\n');setTimeout(()=>res.end('committed'),80);}).listen(0,'127.0.0.1',function(){process.stdout.write('PORT '+this.address().port+'\\n');}));`;
 const child=spawn(process.execPath,['--import',loader,'--input-type=module','-e',source,module],{stdio:['ignore','pipe','pipe']});
 let output='',errors='';child.stdout.on('data',chunk=>{output+=chunk.toString();});child.stderr.on('data',chunk=>{errors+=chunk.toString();});
 const exited=new Promise<number|null>(resolve=>child.once('exit',resolve));
 const until=async(check:()=>boolean)=>{for(let i=0;i<2000;i++){if(check())return;if(child.exitCode!==null)throw Error('Synthetic service exited early.');await new Promise(resolve=>setTimeout(resolve,5));}throw Error('Synthetic service did not reach its bounded checkpoint.');};
 try{
  await until(()=>/PORT (\d+)/.test(output));const port=/PORT (\d+)/.exec(output)![1],response=fetch('http://127.0.0.1:'+port);await until(()=>output.includes('ACCEPTED'));
  child.kill(signal);assert.equal(await(await response).text(),'committed');assert.equal(await exited,0);assert.equal(output.split('STOPPING').length-1,1);assert.equal(output.split('CLOSED').length-1,1);assert.equal(errors,'');
 }finally{if(child.exitCode===null)child.kill('SIGKILL');await exited;}
});

test('diagnostics allow only fixed error names/codes, never arbitrary messages or fields',()=>{
 assert.equal(safeLifecycleError(Object.assign(Error('secret'),{code:'token=secret'})),'Error');
 assert.equal(safeLifecycleError({name:'secret',code:'secret'}),'Error');
 assert.equal(safeLifecycleError(null),'unknown');
 assert.equal(safeLifecycleError({name:'TypeError',code:'ECONNREFUSED'}),'TypeError:ECONNREFUSED');
});

test('SIGTERM refuses a later request on the same active keepalive connection while accepted HTTP drains',async()=>{
 const module=fileURLToPath(new URL('../src/lifecycle.ts',import.meta.url)),loader=import.meta.resolve('tsx');
 const source=String.raw`import {createServer} from 'node:http';import {pathToFileURL} from 'node:url';const {ServiceLifecycle,installShutdownSignals}=await import(pathToFileURL(process.argv[1]));let accepted=0;const lifecycle=new ServiceLifecycle({budgetMs:2000,quiesce:()=>process.stdout.write('STOPPING\n'),drain:async()=>{},close:async()=>{if(accepted!==1)throw Error('late work admitted');},force:()=>{},exit:code=>process.exit(code)});installShutdownSignals(lifecycle);lifecycle.listen(()=>createServer((req,res)=>{if(lifecycle.stopping){res.writeHead(503,{'Connection':'close','Cache-Control':'no-store'});res.end('service_stopping');return;}accepted++;process.stdout.write('ACCEPTED\n');setTimeout(()=>res.end('committed'),200);}).listen(0,'127.0.0.1',function(){process.stdout.write('PORT '+this.address().port+'\n');}));`;
 const child=spawn(process.execPath,['--import',loader,'--input-type=module','-e',source,module],{stdio:['ignore','pipe','pipe']});
 let output='',errors='';child.stdout.on('data',chunk=>{output+=chunk;});child.stderr.on('data',chunk=>{errors+=chunk;});
 const exited=new Promise<number|null>(resolve=>child.once('exit',resolve));
 const until=async(check:()=>boolean)=>{for(let i=0;i<1000;i++){if(check())return;if(child.exitCode!==null)throw Error('Synthetic service exited early.');await new Promise(resolve=>setTimeout(resolve,5));}throw Error('Synthetic checkpoint timeout.');};
 let socket:ReturnType<typeof connect>|undefined;
 try{
  await until(()=>/PORT (\d+)/.test(output));socket=connect(Number(/PORT (\d+)/.exec(output)![1]),'127.0.0.1');
  let wire='';socket.on('data',chunk=>{wire+=chunk;});const ended=new Promise<void>((resolve,reject)=>{socket!.once('close',()=>resolve());socket!.once('error',reject);});
  socket.write('GET /accepted HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n');await until(()=>output.includes('ACCEPTED'));
  child.kill('SIGTERM');await until(()=>output.includes('STOPPING'));
  socket.write('GET /late HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n');
  await ended;assert.match(wire,/HTTP\/1.1 200/);assert.match(wire,/committed/);assert.match(wire,/HTTP\/1.1 503/);assert.match(wire,/Connection: close/i);assert.match(wire,/service_stopping/);
  assert.equal(await exited,0);assert.equal(output.split('ACCEPTED').length-1,1);assert.equal(errors,'');
 }finally{socket?.destroy();if(child.exitCode===null)child.kill('SIGKILL');await exited;}
});
