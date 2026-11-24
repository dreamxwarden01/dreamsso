import test from 'node:test';
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {runInNewContext} from 'node:vm';
import crypto from 'node:crypto';
import express from 'express';
import ts from 'typescript';
import {identityConflict} from '../src/identityConflicts.js';

test('exact SQL23505 identity indexes map to the corresponding field',()=>{
  for(const [constraint,field] of [['uq_identities_email','email'],['uq_identities_username','username']] as const){
    const error=Object.assign(new Error('synthetic uniqueness error'),{code:'23505',constraint});
    assert.equal(identityConflict(error),field);
  }
});

test('unknown unique constraints never become username/email errors by substring, detail or message',()=>{
  for(const constraint of [undefined,null,'','identities_pkey','uq_accounts_email','uq_identities_email_history',
    'prefix_uq_identities_username','public.uq_identities_email','UQ_IDENTITIES_EMAIL']){
    assert.equal(identityConflict({code:'23505',constraint,message:'duplicate uq_identities_email username',detail:'Key (email) already exists'}),null);
  }
});

test('other SQL errors and malformed input cannot masquerade as an identity conflict',()=>{
  for(const value of [null,undefined,'23505',23505,{},new Error('23505'),{constraint:'uq_identities_email'},
    {code:23505,constraint:'uq_identities_email'},{code:'23503',constraint:'uq_identities_email'},
    {code:'23514',constraint:'uq_identities_username'},{code:'23505',constraint:[]}]){
    assert.equal(identityConflict(value),null);
  }
});

async function isolated(file:string,imports:Record<string,unknown>){
  const source=await readFile(new URL('../src/'+file,import.meta.url),'utf8');
  const output=ts.transpileModule(source,{compilerOptions:{target:ts.ScriptTarget.ES2022,module:ts.ModuleKind.CommonJS,esModuleInterop:true}}).outputText;
  const exports:Record<string,any>={};
  runInNewContext(output,{exports,require:(name:string)=>{
    assert.ok(Object.hasOwn(imports,name),'Unexpected isolated dependency '+name);return imports[name];
  },console:{error(){},warn(){}}},{filename:file});
  return exports;
}
const duplicate=(constraint:string)=>Object.assign(new Error('synthetic database details'),{code:'23505',constraint});

test('actual admin create catch preserves field/status copy and rethrows unknown23505 unchanged',async()=>{
  const runtime=await isolated('rbac/roleAdministration.ts',{
    '../identityConflicts.js':{identityConflict},'./catalog.js':{PERM_KEYS:[]},
    './index.js':{resolveAuthz:async()=>({role:'fixture-admin',level:10,granted:new Set(['org.users.create'])})},
    './appRoles.js':{appRoleLevel(){assert.fail('unrelated app-role operation');},effectiveAppRole(){assert.fail('unrelated app-role operation');}},
    './roleChanges.js':{publishRoleChanges(){assert.fail('conflicted creation must not publish');}},
  });
  let injected:unknown,attempts=0,afterIdentity=0;
  const db={async query(sql:string){
    if(sql.startsWith('SELECT status,deleted_at'))return{rows:[{status:'active',deleted_at:null,display_name:'Fixture actor',username:'fixture'}]};
    if(sql.startsWith('SELECT slug,level FROM org_roles'))return{rows:[{slug:'fixture-member',level:100}]};
    if(sql.startsWith('INSERT INTO identities')){attempts++;throw injected;}
    if(sql.startsWith('INSERT ')){afterIdentity++;assert.fail('no membership/audit write after identity conflict');}
    return{rows:[]};
  }};
  const actor='11111111-1111-4111-8111-111111111111',input={sub:'22222222-2222-4222-8222-222222222222',username:'fixture',displayName:'Fixture',email:'fixture@example.invalid',passwordHash:'synthetic-only',roleSlug:'fixture-member'};
  for(const [constraint,field,copy] of [['uq_identities_email','email','Already in use'],['uq_identities_username','username','Already taken']] as const){
    injected=duplicate(constraint);
    await assert.rejects(runtime.createOrgUser(db,actor,input),(error:any)=>error instanceof runtime.RoleAccessError
      &&error.status===409&&JSON.stringify(error.body.errors)===JSON.stringify({[field]:copy}));
  }
  for(const constraint of ['identities_pkey','uq_other_email','uq_identities_username_history']){
    injected=duplicate(constraint);await assert.rejects(runtime.createOrgUser(db,actor,input),error=>error===injected);
  }
  assert.equal(attempts,5);assert.equal(afterIdentity,0);
});

test('actual setup finish catch reports exact field conflicts and never labels unknown23505 as username',async()=>{
  let injected:unknown;
  const runtime=await isolated('routes/setup.ts',{
    express,'node:crypto':crypto,'../identityConflicts.js':{identityConflict},
    '../setup/state.js':{isSetupComplete:()=>false,isSetupConfigured:()=>true},
    '../setup/token.js':{verifySetupToken:()=>true},'../views.js':{renderUnavailablePage:()=>''},
    '../setup/config.js':{},'../setup/wizard.js':{renderWizard:()=>''},
    '../setup/finish.js':{validateFinish:()=>({}),runFinishTransaction:async()=>{throw injected;}},
    '../oidc/sessions.js':{createSession(){assert.fail('conflicted setup must not create a session');},clientGeo:()=>({})},
  });
  const layer=runtime.setupRouter.stack.find((entry:any)=>entry.route?.path==='/setup/finish'&&entry.route.methods.post);
  assert.ok(layer);const handler=layer.route.stack.at(-1).handle;
  const response=()=>({statusCode:200,body:undefined as any,status(status:number){this.statusCode=status;return this;},json(body:any){this.body=JSON.parse(JSON.stringify(body));return this;}});
  for(const [constraint,field,copy] of [['uq_identities_email','email','That email address is already in use.'],['uq_identities_username','username','That username is already taken.']] as const){
    injected=duplicate(constraint);const res=response();await handler({body:{},headers:{}},res);
    assert.equal(res.statusCode,422);assert.deepEqual(res.body,{errors:{[field]:copy}});
  }
  for(const constraint of ['identities_pkey','uq_other_email','uq_identities_email_history']){
    injected=duplicate(constraint);const res=response();
    await handler({body:{},headers:{}},res);
    assert.equal(res.statusCode,500);assert.deepEqual(res.body,{error:'setup_failed'});
    assert.equal(JSON.stringify(res.body).includes('synthetic database details'),false);
  }
});
