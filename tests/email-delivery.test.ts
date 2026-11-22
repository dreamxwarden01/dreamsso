import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

function mailer(fetch: typeof globalThis.fetch) {
 const source=readFileSync(new URL('../src/email.ts',import.meta.url),'utf8');
 const output=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 const exports:any={};
 vm.runInNewContext(output,{exports,require:(name:string)=>{
  if(name!=='./settings.js')throw Error('Unexpected import');
  return{getSetting:async(key:string)=>({mail_from:'no-reply@example.invalid',site_name:'Example',cf_account_id:'synthetic',cf_api_base:'https://api.example.invalid'} as any)[key],getSecretSetting:async()=> 'synthetic-private-test-value'};
 },fetch,AbortSignal,encodeURIComponent,console:{warn(){}}});
 return exports.sendEmail as (args:any)=>Promise<any>;
}
const args={to:'recipient@example.invalid',subject:'Test',html:'<p>Test</p>',text:'Test'};
test('only a positive provider acknowledgment means accepted',async()=>{
 assert.equal((await mailer(async()=>Response.json({success:true})) (args)).ok,true);
 assert.equal((await mailer(async()=>Response.json({success:false},{status:400}))(args)).reason,'rejected');
});
test('ambiguous HTTP and unreadable bodies never claim definite failure',async()=>{
 for(const status of [408,429,500,502,503])assert.equal((await mailer(async()=>Response.json({success:false},{status}))(args)).reason,'unknown');
 assert.equal((await mailer(async()=>new Response('not json'))(args)).reason,'unknown');
 assert.equal((await mailer(async()=>({json:async()=>{throw new DOMException('timed out','TimeoutError');},status:200,ok:true}) as Response)(args)).reason,'unknown');
 assert.equal((await mailer(async()=>{throw Error('synthetic connection failure');})(args)).reason,'unreachable');
});
test('configuration authorization failures and definite recipient bounce remain distinguishable',async()=>{
 for(const status of [401,403])assert.equal((await mailer(async()=>new Response('not json',{status}))(args)).reason,'email_not_configured');
 assert.equal((await mailer(async()=>Response.json({success:true,result:{permanent_bounces:['recipient@example.invalid']}}))(args)).reason,'bounced');
 assert.equal((await mailer(async()=>Response.json({success:false},{status:422}))(args)).reason,'rejected');
});
