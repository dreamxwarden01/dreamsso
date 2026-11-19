import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import * as model from '../account/client/src/pages/org/invitations/invitationModel.js';
import {settleOperation} from '../account/client/src/pages/org/invitations/invitationOperations.js';
function sourceModule(file:string,require:any,globals:any={}) {
 const exports:any={};const code=ts.transpileModule(readFileSync(new URL('../'+file,import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.CommonJS,target:ts.ScriptTarget.ES2022}}).outputText;
 vm.runInNewContext(code,{exports,require,AbortSignal,Error,...globals});return exports;
}
function fixture(fetch:any){
 const api=sourceModule('account/client/src/api.js',()=>{throw Error('Unexpected import');},{fetch});
 const invites=sourceModule('account/client/src/pages/org/invitations/invitationApi.js',(name:string)=>name==='../../../api.js'?api:model);
 return invites;
}
async function preservesRequest(work:()=>Promise<unknown>,code:string){
 let error:any;try{await work();assert.fail('expected failure');}catch(e){error=e;}
 assert.equal(error.code,code);assert.equal(model.uncertainMutation(error),true);
 const map=new Map([['test-operation','retained']]),old=(globalThis as any).sessionStorage;
 (globalThis as any).sessionStorage={removeItem:(key:string)=>map.delete(key)};
 try{settleOperation({key:'test-operation'},error);assert.equal(map.get('test-operation'),'retained');}
 finally{(globalThis as any).sessionStorage=old;}
 assert.match(model.invitationError(error),/saved|confirmed|unexpected|current invitations/i);
}
test('actual mutation adapter preserves retry identity after timeout and network errors',async()=>{
 await preservesRequest(()=>fixture(async()=>{throw new DOMException('deadline','TimeoutError');}).createInvitation({}),'request_timeout');
 await preservesRequest(()=>fixture(async()=>{throw new TypeError('network failure');}).createInvitation({}),'network_error');
});
test('null successful mutation body is an uncertain invalid response, never a fresh retry',async()=>{
 await preservesRequest(()=>fixture(async()=>Response.json(null)).createInvitation({}),'invalid_response');
});
