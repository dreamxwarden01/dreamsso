import type {Server} from 'node:http';

export const SHUTDOWN_BUDGET_MS=45_000; // Deployment stop grace must exceed this (planned: 60s).

// Only fixed diagnostic vocabulary is logged: messages and arbitrary codes can
// contain configuration values, URLs or credentials.
const errorCodes=new Set(['EADDRINUSE','EACCES','EPERM','ECONNREFUSED','ECONNRESET','ETIMEDOUT','ENOTFOUND','EAI_AGAIN','ENOENT','ENFILE','EMFILE','ERR_SERVER_NOT_RUNNING']);
const errorNames=new Set(['Error','TypeError','RangeError','SyntaxError','AbortError','AggregateError']);
export function safeLifecycleError(error:unknown):string{
 if(!error||typeof error!=='object')return 'unknown';
 const {name,code}=error as {name?:unknown;code?:unknown};
 return [typeof name==='string'&&errorNames.has(name)?name:'Error',typeof code==='string'&&errorCodes.has(code)?code:''].filter(Boolean).join(':');
}

/** Tracks actual settlement, including tasks whose callers have already timed out. */
export class ActiveTasks {
 private readonly active=new Set<Promise<unknown>>();
 track<T>(work:Promise<T>):Promise<T>{
  this.active.add(work);void work.then(()=>this.active.delete(work),()=>this.active.delete(work));return work;
 }
 async settle():Promise<void>{while(this.active.size)await Promise.allSettled([...this.active]);}
}

export interface LifecycleOptions {
 quiesce:()=>void;
 drain:()=>Promise<void>;
 close:()=>Promise<void>;
 force:()=>void;
 exit:(code:number)=>void;
 report?:(code:string)=>void;
 budgetMs?:number;
}
/** Owns one HTTP listener and one bounded, idempotent shutdown, including boot. */
export class ServiceLifecycle {
 stopping=false;
 private server:Server|null=null;
 private startup:Promise<void>|null=null;
 private shutdown:Promise<void>|null=null;
 private code=0;
 readonly tasks=new ActiveTasks();
 private readonly timers=new Set<NodeJS.Timeout>();
 constructor(private readonly options:LifecycleOptions){}
 boot(start:()=>Promise<void>|void):Promise<void>{
  if(this.startup)return this.startup;
  this.startup=Promise.resolve().then(async()=>{if(!this.stopping)await start();}).catch(error=>{this.code=1;throw error;});return this.startup;
 }
 listen(start:()=>Server):Server|null{
  if(this.stopping)return null;if(this.server)throw Error('HTTP listener already exists.');
  this.server=start();this.server.once('error',error=>{this.options.report?.('http_server_failed '+safeLifecycleError(error));void this.stop(1);});
  // A connection that was active at close() can become idle only after its
  // accepted response finishes; reap it then rather than waiting keepAliveTimeout.
  this.server.on('request',(_req,res)=>{res.once('finish',()=>{if(this.stopping)this.server?.closeIdleConnections();});});
  return this.server;
 }
 every(work:()=>Promise<unknown>,interval:number):void{
  if(this.stopping)return;
  const run=()=>{if(!this.stopping)void this.tasks.track(Promise.resolve().then(work)).catch(()=>this.options.report?.('background_failed'));};
  run();const timer=setInterval(run,interval);timer.unref();this.timers.add(timer);
 }
 stop(code=0):Promise<void>{
  this.code=Math.max(this.code,code);
  if(this.shutdown)return this.shutdown;
  this.stopping=true;
  // Assign the promise before invoking hooks: repeated signals or a synchronous
  // close callback cannot begin another shutdown sequence.
  this.shutdown=Promise.resolve().then(()=>this.finish());
  for(const timer of this.timers)clearInterval(timer);this.timers.clear();
  try{this.options.quiesce();}catch{this.code=1;this.options.report?.('quiesce_failed');}
  return this.shutdown;
 }
 private async finish():Promise<void>{
  let ended=false,done!:()=>void;
  const complete=new Promise<void>(resolve=>{done=resolve;});
  const exit=(code:number)=>{if(ended)return;ended=true;this.options.exit(code);done();};
  const deadline=setTimeout(()=>{
   this.options.report?.('shutdown_deadline');
   this.server?.closeAllConnections();
   try{this.options.force();}catch{/* Exit is still required after failed force cleanup. */}
   exit(1);
  },this.options.budgetMs??SHUTDOWN_BUDGET_MS);
  const closeHttp=this.server?new Promise<void>(resolve=>{
   this.server!.close(error=>{if(error&&(error as NodeJS.ErrnoException).code!=='ERR_SERVER_NOT_RUNNING')this.code=1;resolve();});
   this.server!.closeIdleConnections();
  }):Promise.resolve();
  void(async()=>{
   try{
    await Promise.allSettled([closeHttp,this.startup??Promise.resolve()]);
    if(ended)return;
    await Promise.all([this.tasks.settle(),this.options.drain()]);
    if(ended)return;
    await this.options.close();
   }catch{this.code=1;this.options.report?.('shutdown_cleanup_failed');try{this.options.force();}catch{/* Preserve the failure exit even if cleanup fails. */}}
   if(ended)return;clearTimeout(deadline);exit(this.code);
  })();
  await complete;
 }
}

export function installShutdownSignals(lifecycle:ServiceLifecycle):()=>void{
 const stop=()=>{void lifecycle.stop();};
 process.on('SIGTERM',stop);process.on('SIGINT',stop);
 return()=>{process.off('SIGTERM',stop);process.off('SIGINT',stop);};
}
