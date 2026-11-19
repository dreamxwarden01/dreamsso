import assert from 'node:assert/strict';
import test from 'node:test';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
const file=readFileSync(new URL('../src/routes/register.ts',import.meta.url),'utf8');
const ast=ts.createSourceFile('register.ts',file,ts.ScriptTarget.Latest,true);
const declaration=ast.statements.find(node=>ts.isFunctionDeclaration(node)&&node.name?.text==='publicInvitation');
assert.ok(declaration);
const code=ts.transpileModule(declaration.getText(ast)+'\nglobalThis.project=publicInvitation;',{compilerOptions:{target:ts.ScriptTarget.ES2022}}).outputText;
const context:any={Date};vm.runInNewContext(code,context);
test('public preview exposes the recipient contract but not administrator notes or private material',()=>{
 const row={code:'ABCD1234EFGH',note:'Private administration note',created_by:'private-actor-id',payload_enc:'private-mail-proof',proof_hash:'private-hash',
  expires_at:new Date(Date.now()+3600000).toISOString(),created_at:new Date().toISOString(),bound_email:'recipient@example.invalid',
  bound_at:new Date().toISOString(),invited_role_slug:'member',invited_role_label:'Member',mail_state:'sent',mail_last_at:null,mail_error_code:null};
 const result=context.project(row),json=JSON.stringify(result);
 assert.equal(result.label,'Invitation');assert.equal(result.bound_email,row.bound_email);assert.equal(result.status,'unused');
 for(const forbidden of ['Private administration note','private-actor-id','private-mail-proof','private-hash'])assert.ok(!json.includes(forbidden));
});
test('terminal states are explicit and completed invitations stay used',()=>{
 const base={expires_at:new Date(Date.now()-1000).toISOString()};
 for(const [patch,status] of [[{},'expired'],[{invalidated_at:'2026-01-01'},'unavailable'],[{voided_at:'2026-01-01'},'revoked'],[{used_at:'2026-01-01',used_by:null},'used']] as const)
  assert.equal(context.project({...base,...patch}).status,status);
});
