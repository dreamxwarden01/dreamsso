import type pg from 'pg';
import { lockRoleWrites } from './rbac/roleChanges.js';
import { lockInvitation, validateLockedInvitation, InvitationError } from './invitations.js';
import { resolveRegistrationRole } from './registrationRole.js';

export interface RegistrationCommit {
  sub: string; username: string; displayName: string; email: string; passwordHash: string;
  proofHash: Buffer; requestHash: Buffer; code: string | null; proofExpiresAt: Date;
  /** Modern proofs are checked inside the transaction; legacy pending links have a fixed Redis deadline. */
  modernProof: boolean;
}

/** One transaction owns authority checks, identity, role, single-use consumption and receipt. */
export async function commitRegistration(db: pg.PoolClient, input: RegistrationCommit): Promise<{sub:string;role:string;replayed:boolean}> {
  await lockRoleWrites(db);
  const prior = (await db.query(`SELECT user_sub,request_hash FROM registration_completions
    WHERE proof_hash=$1 AND retry_until>clock_timestamp()`, [input.proofHash])).rows[0];
  if (prior) {
    if (!Buffer.from(prior.request_hash).equals(input.requestHash)) throw new InvitationError(409,'registration_completed');
    return {sub:prior.user_sub,role:'',replayed:true};
  }
  const enabled = (await db.query("SELECT value FROM settings WHERE key='enable_registration'")).rows[0]?.value==='true';
  if (!enabled) throw new InvitationError(403,'registration_closed');
  if (input.modernProof) {
    const proof = (await db.query(`SELECT j.invitation_id FROM invitation_mail_jobs j
      WHERE j.proof_hash=$1 AND j.email=$2 AND j.expires_at>clock_timestamp()`, [input.proofHash,input.email])).rows[0];
    if (!proof) throw new InvitationError(422,'invalid_token');
  }
  const invite = input.code ? await lockInvitation(db,input.code) : null;
  if (input.code && !invite) throw new InvitationError(409,'invitation_unavailable');
  if (invite) await validateLockedInvitation(db,invite,input.email,true);
  const role = await resolveRegistrationRole(db,invite?.invited_role_slug ?? null);
  // Email uniqueness constraints remain the final arbiter, including concurrent email changes.
  await db.query(`INSERT INTO identities(sub,username,display_name,email,email_verified,password_hash,password_changed_at)
    VALUES($1,$2,$3,$4,true,$5,clock_timestamp())`, [input.sub,input.username,input.displayName,input.email,input.passwordHash]);
  await db.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)', [input.sub,role]);
  // clock_timestamp, not transaction now(): expiry after waiting on a lock must still reject.
  if (!(await db.query('SELECT 1 WHERE $1::timestamptz>clock_timestamp()', [input.proofExpiresAt])).rowCount) {
    throw new InvitationError(422,'invalid_token');
  }
  if (invite) {
    const consumed = await db.query(`UPDATE invitation_codes SET used_by=$2,used_at=clock_timestamp(),clear_at=NULL,used_username_snapshot=$4,used_display_name_snapshot=$5,
      pending_email=NULL,pending_at=NULL WHERE id=$1 AND used_at IS NULL AND voided_at IS NULL AND invalidated_at IS NULL
      AND expires_at>clock_timestamp() AND bound_email=$3 RETURNING id`, [invite.id,input.sub,input.email,input.username,input.displayName]);
    if (!consumed.rowCount) throw new InvitationError(409,'invitation_unavailable');
  }
  await db.query(`INSERT INTO registration_completions(proof_hash,user_sub,request_hash,retry_until)
    VALUES($1,$2,$3,clock_timestamp()+interval '10 minutes')`, [input.proofHash,input.sub,input.requestHash]);
  return {sub:input.sub,role,replayed:false};
}
