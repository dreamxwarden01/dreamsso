import crypto from 'node:crypto';
import type pg from 'pg';
import { pool } from './db.js';
import { sealSecret, openSecret } from './secretbox.js';
import { reserveRegistrationSend } from './registration.js';
import { getSetting } from './settings.js';
import { sendEmail, type SendResult } from './email.js';
import { renderRegistrationEmail } from './emailTemplates.js';
import { config } from './config.js';
import { lockRoleWrites } from './rbac/roleChanges.js';
import { lockInvitation, validateLockedInvitation, InvitationError } from './invitations.js';

export const invitationProofHash = (token: string): Buffer => crypto.createHash('sha256').update(token).digest();
export interface MailInvitation { id: string; code: string; bound_email: string | null; expires_at: Date | string }
export interface QueueResult { queued: boolean; retry_after?: number; error?: string }

/** Caller owns role lock and invite row lock; binding and private intent commit together. */
export async function queueInvitationMail(db: pg.PoolClient, invite: MailInvitation,
  request: { actorSub: string | null; requestId: string; requireQueued?: boolean }): Promise<QueueResult> {
  if (!invite.bound_email) throw Error('Invitation email must be bound before queueing.');
  const actor = request.actorSub ?? 'public:' + invite.id;
  const prior = (await db.query(`SELECT r.invitation_id,r.email,j.state FROM invitation_mail_requests r
    JOIN invitation_mail_jobs j ON j.id=r.job_id WHERE r.actor_key=$1 AND r.request_id=$2`, [actor,request.requestId])).rows[0];
  if (prior) {
    if (prior.invitation_id!==invite.id || prior.email.toLowerCase()!==invite.bound_email.toLowerCase()) throw new InvitationError(409,'request_conflict');
    return {queued:['queued','sending'].includes(prior.state)};
  }
  const pending = (await db.query("SELECT id,state FROM invitation_mail_jobs WHERE invitation_id=$1 AND state IN('queued','sending') LIMIT 1", [invite.id])).rows[0];
  if (pending) {
    await db.query('INSERT INTO invitation_mail_requests(actor_key,request_id,invitation_id,email,job_id) VALUES($1,$2,$3,$4,$5)', [actor,request.requestId,invite.id,invite.bound_email,pending.id]);
    return {queued:true};
  }
  const cooldown = (await db.query(`SELECT GREATEST(0,ceil(extract(epoch from(mail_next_retry_at-clock_timestamp()))))::int AS seconds
    FROM invitation_codes WHERE id=$1`, [invite.id])).rows[0]?.seconds ?? 0;
  if (cooldown > 0) {
    if(request.requireQueued)throw new InvitationError(429,'rate_limited',{retry_after:cooldown,can_retry:true});
    return {queued:false,retry_after:cooldown,error:'rate_limited'};
  }
  const slot = await reserveRegistrationSend(invite.bound_email);
  if (!slot.ok) {
    if(request.requireQueued)throw new InvitationError(429,'rate_limited',{retry_after:slot.retryAfter,can_retry:slot.canRetry});
    await db.query(`UPDATE invitation_codes SET mail_state='failed',mail_error_code='rate_limited',mail_last_at=clock_timestamp(),
      mail_next_retry_at=clock_timestamp()+make_interval(secs=>$2) WHERE id=$1`, [invite.id,slot.retryAfter]);
    return { queued: false, retry_after: slot.retryAfter, error: 'rate_limited' };
  }
  const token = crypto.randomBytes(48).toString('hex');
  const inserted = await db.query(`INSERT INTO invitation_mail_jobs(invitation_id,request_id,actor_key,email,proof_hash,payload_enc,expires_at)
    VALUES($1,$2,$3,$4,$5,$6,$7) RETURNING id`, [invite.id,request.requestId,actor,invite.bound_email,invitationProofHash(token),sealSecret(token),invite.expires_at]);
  await db.query('INSERT INTO invitation_mail_requests(actor_key,request_id,invitation_id,email,job_id) VALUES($1,$2,$3,$4,$5)', [actor,request.requestId,invite.id,invite.bound_email,inserted.rows[0].id]);
  await db.query(`UPDATE invitation_codes SET mail_state='queued',mail_attempts=mail_attempts+1,mail_last_at=clock_timestamp(),
    mail_error_code=NULL,mail_next_retry_at=clock_timestamp()+make_interval(secs=>$2) WHERE id=$1`, [invite.id,Math.max(60,slot.nextBackoff)]);
  return { queued: true, retry_after: Math.max(60,slot.nextBackoff) };
}

export async function readInvitationProof(db: pg.Pool | pg.PoolClient, email: string, token: string, includeExpired = false) {
  if (!/^[0-9a-f]{96}$/.test(token)) return null;
  const row = (await db.query(`SELECT j.id,j.invitation_id,j.email,j.expires_at,ic.code
    FROM invitation_mail_jobs j JOIN invitation_codes ic ON ic.id=j.invitation_id
    WHERE j.proof_hash=$1 AND j.email=$2 AND ($3 OR j.expires_at>clock_timestamp())`, [invitationProofHash(token),email,includeExpired])).rows[0];
  return row ?? null;
}

/** Ambiguous provider outcomes are never retried automatically. A new explicit resend is required. */
export async function drainInvitationMail(options: { database?: pg.Pool; send?: typeof sendEmail } = {}): Promise<void> {
  const database = options.database ?? pool, deliver = options.send ?? sendEmail;
  const db = await database.connect();let job: any = null;
  try {
    await db.query('BEGIN');await lockRoleWrites(db);
    const abandoned = (await db.query(`UPDATE invitation_mail_jobs SET state='unknown',error_code='delivery_unknown',payload_enc=NULL,
      finished_at=clock_timestamp(),lease_id=NULL,lease_until=NULL WHERE state='sending' AND lease_until<clock_timestamp()
      RETURNING invitation_id,id`)).rows;
    for (const old of abandoned) await db.query(`UPDATE invitation_codes SET mail_state='unknown',mail_error_code='delivery_unknown',mail_last_at=clock_timestamp()
      WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1 AND (created_at,id)>(SELECT created_at,id FROM invitation_mail_jobs WHERE id=$2))`, [old.invitation_id,old.id]);
    job = (await db.query(`SELECT * FROM invitation_mail_jobs WHERE state='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED`)).rows[0];
    if (job) {
      const invite = await lockInvitation(db,job.invitation_id);
      try {
        if (!invite) throw Error('missing');
        await validateLockedInvitation(db,invite,job.email,false);
        const enabled = (await db.query("SELECT value FROM settings WHERE key='enable_registration'")).rows[0]?.value === 'true';
        if (!enabled) throw Error('closed');
      } catch {
        await db.query("UPDATE invitation_mail_jobs SET state='failed',error_code='invitation_unavailable',payload_enc=NULL,finished_at=clock_timestamp() WHERE id=$1", [job.id]);
        await db.query("UPDATE invitation_codes SET mail_state='failed',mail_error_code='invitation_unavailable',mail_last_at=clock_timestamp() WHERE id=$1", [job.invitation_id]);
        job = null;
      }
      if (job) {
        job.lease_id = crypto.randomUUID();
        await db.query("UPDATE invitation_mail_jobs SET state='sending',lease_id=$2,lease_until=clock_timestamp()+interval '45 seconds' WHERE id=$1", [job.id,job.lease_id]);
        await db.query("UPDATE invitation_codes SET mail_state='sending',mail_last_at=clock_timestamp() WHERE id=$1", [job.invitation_id]);
      }
    }
    await db.query('COMMIT');
  } catch (error) { await db.query('ROLLBACK').catch(()=>{});throw error; }
  finally { db.release(); }
  if (!job) return;
  let result: SendResult;
  try {
    const token = openSecret(job.payload_enc);
    const [site,portal] = await Promise.all([getSetting('site_name','DreamSSO'),getSetting('account_portal_url',config.accountPortalUrl)]);
    const link = `${portal}/register/complete?email=${encodeURIComponent(job.email)}&token=${token}`;
    result = await deliver({ to:job.email,...renderRegistrationEmail({siteName:site!,link,expiresAt:new Date(job.expires_at).toISOString()}) });
  } catch { result = {ok:false,reason:'unreachable'}; }
  const state = result.ok ? 'sent' : ['unreachable','unknown'].includes(result.reason) ? 'unknown' : 'failed';
  const code = result.ok ? null : state === 'unknown' ? 'delivery_unknown' : result.reason === 'not_configured' ? 'email_not_configured' : 'send_failed';
  const finish = await database.connect();
  try {
    await finish.query('BEGIN');
    const changed = await finish.query(`UPDATE invitation_mail_jobs SET state=$3,error_code=$4,payload_enc=NULL,finished_at=clock_timestamp(),lease_until=NULL,lease_id=NULL
      WHERE id=$1 AND lease_id=$2 AND state='sending' RETURNING invitation_id`, [job.id,job.lease_id,state,code]);
    if (changed.rowCount) await finish.query(`UPDATE invitation_codes SET mail_state=$2,mail_error_code=$3,mail_last_at=clock_timestamp()
      WHERE id=$1 AND NOT EXISTS(SELECT 1 FROM invitation_mail_jobs WHERE invitation_id=$1 AND (created_at,id)>(SELECT created_at,id FROM invitation_mail_jobs WHERE id=$4))`, [job.invitation_id,state,code,job.id]);
    await finish.query('COMMIT');
  } catch(error) { await finish.query('ROLLBACK').catch(()=>{});throw error; }
  finally { finish.release(); }
}
