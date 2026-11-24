import crypto from 'node:crypto';
import type pg from 'pg';
import { pool } from './db.js';
import { sealSecret, openSecret } from './secretbox.js';
import { lockRoleWrites } from './rbac/roleChanges.js';
import { resolveAuthz } from './rbac/index.js';
import { identityConflict } from './identityConflicts.js';
import { maskEmail } from './emailOtp.js';
import { reserveRegistrationSend } from './registration.js';

export const emailChangeValidityMinutes = 30;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const REVISION = /^(0|[1-9][0-9]{0,18})$/;
const TOKEN = /^ec1\.[A-Za-z0-9_-]{43}$/;
const hashToken = (token: string) => crypto.createHash('sha256').update(token).digest();
export class EmailChangeError extends Error {
  constructor(readonly status: number, readonly code: string, readonly details: Record<string,unknown> = {}) { super(code); }
}
function fail(status: number, code: string): never { throw new EmailChangeError(status,code); }
interface Identity { sub: string; email: string | null; email_verified: boolean; username: string; display_name: string; email_change_revision: string }
interface Operation {
  user_sub: string; request_id: string; revision: string; kind: 'change' | 'confirm'; new_email: string;
  token_hash: Buffer; token_enc: Buffer | null; created_at: Date; expires_at: Date; last_sent_at: Date;
  completed_at: Date | null; pending_valid: boolean; receipt_valid: boolean;
}
export interface EmailChange {
  sub: string; requestId: string; revision: string; kind: 'change' | 'confirm'; newEmail: string;
  createdAt: number; lastSent: number; expiresAt: string;
}
export interface EmailChangeInput { requestId: string; expectedRevision: string }
export function emailChangeInput(requestId:string,expectedRevision:string):EmailChangeInput {
  if(!UUID.test(requestId)||!REVISION.test(expectedRevision))fail(409,'email_change_changed');
  return {requestId:requestId.toLowerCase(),expectedRevision};
}
const operationColumns = `user_sub,request_id,revision::text AS revision,kind,new_email,token_hash,token_enc,created_at,expires_at,last_sent_at,completed_at, expires_at>clock_timestamp() AS pending_valid,
  completed_at>clock_timestamp()-interval '10 minutes' AS receipt_valid`;
const project = (row: Operation): EmailChange => ({ sub:row.user_sub, requestId:row.request_id, revision:row.revision,
  kind:row.kind,newEmail:row.new_email,createdAt:Math.floor(row.created_at.getTime()/1000),
  lastSent:Math.floor(row.last_sent_at.getTime()/1000),expiresAt:row.expires_at.toISOString() });
async function identity(db: pg.PoolClient, sub: string): Promise<Identity> {
  const row=(await db.query<Identity>(`SELECT sub,email,email_verified,username,display_name,email_change_revision::text
    FROM identities WHERE sub=$1 AND deleted_at IS NULL AND status='active' FOR UPDATE`,[sub])).rows[0];
  return row ?? fail(404,'account_unavailable');
}
async function transaction<T>(sub:string, work:(db:pg.PoolClient,id:Identity)=>Promise<T>,database:pg.Pool=pool):Promise<T>{
  const db=await database.connect();
  try{
    await db.query('BEGIN'); await lockRoleWrites(db);
    const result=await work(db,await identity(db,sub)); await db.query('COMMIT');return result;
  }catch(error){await db.query('ROLLBACK').catch(()=>{});throw error;}finally{db.release();}
}
async function current(db:pg.PoolClient,sub:string):Promise<Operation|null>{
  return (await db.query<Operation>(`SELECT ${operationColumns} FROM email_change_operations WHERE user_sub=$1 FOR UPDATE`,[sub])).rows[0]??null;
}
async function available(db:pg.PoolClient,email:string,sub:string){
  if((await db.query('SELECT 1 FROM identities WHERE email=$1 AND sub<>$2 AND deleted_at IS NULL',[email,sub])).rowCount)fail(409,'email_taken');
}
async function reserveSend(email:string):Promise<number>{
  let timer: ReturnType<typeof setTimeout>;
  try{
    // Redis admission is bounded while identity/authority locks are held. A
    // timeout may still charge a slot later, but cannot authorize a mail send.
    const slot=await Promise.race([reserveRegistrationSend(email),new Promise<never>((_resolve,reject)=>{
      timer=setTimeout(()=>reject(new EmailChangeError(503,'email_change_unavailable')),3000);
    })]);
    if(!slot.ok)throw new EmailChangeError(429,'rate_limited',{retry_after:slot.retryAfter,can_retry:slot.canRetry});
    return slot.nextBackoff;
  }finally{clearTimeout(timer!);}
}
async function authorize(db:pg.PoolClient,id:Identity,kind:'change'|'confirm'){
  if(kind==='change'&&!(await resolveAuthz(id.sub,db)).granted.has(id.email===null?'profile.email.add':'profile.email.change'))fail(403,'permission_denied');
}
function tokenFor(row:Operation):string{
  if(!row.token_enc)return fail(404,'no_pending');
  const token=openSecret(row.token_enc);
  if(!TOKEN.test(token)||!hashToken(token).equals(row.token_hash))throw Error('invalid_email_operation');
  return token;
}

export async function getEmailChangeState(sub:string,database:pg.Pool=pool){
  // One statement keeps the displayed revision and pending operation coherent.
  const row=(await database.query(`SELECT i.email,i.email_verified,i.username,i.email_change_revision::text AS revision,
    o.request_id,o.kind,o.new_email,o.last_sent_at,o.expires_at
    FROM identities i LEFT JOIN email_change_operations o ON o.user_sub=i.sub AND o.revision=i.email_change_revision
      AND o.completed_at IS NULL AND o.expires_at>clock_timestamp()
    WHERE i.sub=$1 AND i.deleted_at IS NULL AND i.status='active'`,[sub])).rows[0];
  if(!row)return null;
  return {email:row.email,email_verified:row.email_verified,username:row.username,revision:row.revision,
    pending:row.request_id?{request_id:row.request_id,kind:row.kind,new_email:row.new_email,
      last_sent:Math.floor(new Date(row.last_sent_at).getTime()/1000),expires_at:new Date(row.expires_at).toISOString()}:null};
}

export async function issueEmailChange(sub:string,kind:'change'|'confirm',newEmail:string,input:EmailChangeInput,database:pg.Pool=pool){
  input=emailChangeInput(input.requestId,input.expectedRevision);
  const email=newEmail.trim().toLowerCase();
  return transaction(sub,async(db,id)=>{
    await authorize(db,id,kind);
    const old=await current(db,sub);
    if(old?.request_id===input.requestId){
      if(old.revision!==id.email_change_revision||old.kind!==kind||old.new_email.toLowerCase()!==email||BigInt(input.expectedRevision)+1n!==BigInt(old.revision))fail(409,'email_change_changed');
      if(old.completed_at||!old.pending_valid)fail(404,'no_pending');
      if(kind==='change')await available(db,email,sub);
      const token=tokenFor(old);const backoff=await reserveSend(email);
      const updated=(await db.query<Operation>(`UPDATE email_change_operations SET last_sent_at=clock_timestamp() WHERE user_sub=$1 AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING ${operationColumns}`,[sub])).rows[0];
      if(!updated)fail(404,'no_pending');
      return {...project(updated),token,reused:true,resendBackoff:backoff};
    }
    if(id.email_change_revision!==input.expectedRevision)fail(409,'email_change_changed');
    if(kind==='confirm'){
      if(!id.email||id.email.toLowerCase()!==email)fail(409,'email_change_changed');
      if(id.email_verified)fail(409,'already_verified');
    }else{
      if(id.email?.toLowerCase()===email)fail(422,'same_email');
      await available(db,email,sub);
    }
    const backoff=await reserveSend(email);
    const token='ec1.'+crypto.randomBytes(32).toString('base64url');
    const revision=(await db.query<{revision:string}>('UPDATE identities SET email_change_revision=email_change_revision+1 WHERE sub=$1 RETURNING email_change_revision::text AS revision',[sub])).rows[0].revision;
    await db.query('DELETE FROM email_change_operations WHERE user_sub=$1',[sub]);
    const row=(await db.query<Operation>(`INSERT INTO email_change_operations(user_sub,request_id,revision,kind,new_email,token_hash,token_enc,created_at,expires_at,last_sent_at)
      VALUES($1,$2,$3,$4,$5,$6,$7,statement_timestamp(),statement_timestamp()+interval '30 minutes',statement_timestamp()) RETURNING ${operationColumns}`,
      [sub,input.requestId,revision,kind,email,hashToken(token),sealSecret(token)])).rows[0];
    return {...project(row),token,reused:false,resendBackoff:backoff};
  },database);
}

export async function resendEmailChange(sub:string,requestId:string,database:pg.Pool=pool){
  if(!UUID.test(requestId))fail(409,'email_change_changed');
  requestId=requestId.toLowerCase();
  return transaction(sub,async(db,id)=>{
    const row=await current(db,sub);if(!row||row.completed_at||!row.pending_valid)fail(404,'no_pending');
    if(row.request_id!==requestId||row.revision!==id.email_change_revision)fail(409,'email_change_changed');
    await authorize(db,id,row.kind);if(row.kind==='change')await available(db,row.new_email,sub);
    if(row.kind==='confirm'&&(!id.email||id.email.toLowerCase()!==row.new_email.toLowerCase()||id.email_verified))fail(409,'email_change_changed');
    const token=tokenFor(row);const backoff=await reserveSend(row.new_email);
    const updated=(await db.query<Operation>(`UPDATE email_change_operations SET last_sent_at=clock_timestamp() WHERE user_sub=$1 AND completed_at IS NULL AND expires_at>clock_timestamp() RETURNING ${operationColumns}`,[sub])).rows[0];
    if(!updated)fail(404,'no_pending');
    return {...project(updated),token,reused:true,resendBackoff:backoff};
  },database);
}

export async function cancelEmailChange(sub:string,requestId:string,database:pg.Pool=pool):Promise<void>{
  if(!UUID.test(requestId))fail(409,'email_change_changed');
  requestId=requestId.toLowerCase();
  await transaction(sub,async(db,id)=>{
    const row=await current(db,sub);if(!row||row.completed_at||!row.pending_valid)fail(404,'no_pending');
    if(row.request_id!==requestId||row.revision!==id.email_change_revision)fail(409,'email_change_changed');
    await db.query('DELETE FROM email_change_operations WHERE user_sub=$1',[sub]);
    await db.query('UPDATE identities SET email_change_revision=email_change_revision+1 WHERE sub=$1',[sub]);
  },database);
}

export async function completeEmailChange(token:string,database:pg.Pool=pool){
  if(!TOKEN.test(token))fail(422,'invalid_token');
  const hash=hashToken(token);
  const hint=(await database.query<{user_sub:string}>('SELECT user_sub FROM email_change_operations WHERE token_hash=$1',[hash])).rows[0];
  if(!hint)fail(422,'invalid_token');
  try{return await transaction(hint.user_sub,async(db,id)=>{
    const row=await current(db,id.sub);
    if(!row||!row.token_hash.equals(hash)||row.revision!==id.email_change_revision)fail(422,'invalid_token');
    if(row.completed_at){if(!row.receipt_valid)fail(422,'invalid_token');return {kind:row.kind,replayed:true,oldEmail:null,identity:id,newEmail:row.new_email};}
    if(!row.pending_valid)fail(422,'invalid_token');
    await authorize(db,id,row.kind);
    if(row.kind==='change')await available(db,row.new_email,id.sub);
    else if(!id.email||id.email.toLowerCase()!==row.new_email.toLowerCase())fail(422,'invalid_token');
    const changed=await db.query<{revision:string}>(`UPDATE identities SET email=$2,email_verified=true WHERE sub=$1 AND deleted_at IS NULL AND status='active'
      RETURNING email_change_revision::text AS revision`,[id.sub,row.new_email]);
    if(changed.rowCount!==1)fail(422,'invalid_token');
    if(BigInt(changed.rows[0].revision)!==BigInt(id.email_change_revision)+1n)throw new EmailChangeError(503,'email_change_unavailable');
    if(!(await db.query('SELECT 1 WHERE $1::timestamptz>clock_timestamp()',[row.expires_at])).rowCount)fail(422,'invalid_token');
    // The identity trigger removes the pending row and advances the revision.
    // Publish the read-only replay receipt in this same transaction.
    await db.query(`INSERT INTO email_change_operations(user_sub,request_id,revision,kind,new_email,token_hash,token_enc,created_at,expires_at,last_sent_at,completed_at)
      VALUES($1,$2,$3,$4,$5,$6,NULL,$7,$8,$9,clock_timestamp())`,
      [id.sub,row.request_id,changed.rows[0].revision,row.kind,row.new_email,hash,row.created_at,row.expires_at,row.last_sent_at]);
    await db.query(`INSERT INTO org_audit_log(actor_sub,actor_label,action,detail) VALUES($1,$2,$3,$4::jsonb)`,
      [id.sub,id.display_name||id.username,row.kind==='confirm'?'email.verify':'email.change',JSON.stringify(row.kind==='change'?{to:maskEmail(row.new_email)}:{})]);
    return {kind:row.kind,replayed:false,oldEmail:row.kind==='change'?id.email:null,identity:id,newEmail:row.new_email};
  },database);}catch(error){
    if(identityConflict(error)==='email')fail(409,'email_taken');
    if(error instanceof EmailChangeError&&error.code==='account_unavailable')fail(422,'invalid_token');
    throw error;
  }
}

export async function sweepEmailChanges(database:pg.Pool=pool){
  await database.query(`DELETE FROM email_change_operations WHERE
    (completed_at IS NULL AND expires_at<=clock_timestamp()) OR completed_at<=clock_timestamp()-interval '10 minutes'`);
}

// Required infrastructure for current-operation fencing, checked before serving.
export async function assertEmailChangeSchema(database:pg.Pool=pool):Promise<void>{
  const {rows:[state]}=await database.query(`SELECT current_setting('session_replication_role') AS replication,
    EXISTS(SELECT 1 FROM pg_trigger WHERE tgrelid='identities'::regclass AND tgname='trg_identity_email_operation'
      AND NOT tgisinternal AND tgenabled IN ('O','A') AND tgtype=19
      AND tgfoid='invalidate_email_change_operation()'::regprocedure) AS enabled,
    has_table_privilege(current_user,'email_change_operations','DELETE') AS can_delete`);
  if(state?.replication!=='origin'||state.enabled!==true||state.can_delete!==true)throw Error('email_operation_trigger_unavailable');
}
