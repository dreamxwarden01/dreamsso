import { Router, type Request, type Response } from 'express';
import crypto from 'node:crypto';
import argon2 from 'argon2';
import { uuidv7 } from 'uuidv7';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSetting, hasSetting } from '../settings.js';
import { createSession, clientGeo } from '../oidc/sessions.js';
import { createTxn } from '../oidc/transactions.js';
import { sendEmail } from '../email.js';
import { renderRegistrationEmail } from '../emailTemplates.js';
import { renderErrorPage } from '../views.js';
import { passwordComplexityOk } from './security.js';
import { isPortalAssertion } from './reset.js';
import { mintLoginTicket, redeemLoginTicket } from '../passwordReset.js';
import { audit } from '../audit.js';
import {
  issuePending, validatePending, dropPending,
  reserveRegistrationSend, releaseRegistrationSend,
  registrationLinkValidityMinutes, CODE_RE,
} from '../registration.js';
import { changePendingForAddress } from '../emailChange.js';

import { withRoleTransaction } from '../rbac/roleChanges.js';
import { lockInvitation, validateLockedInvitation, readInvitationPreview, InvitationError } from '../invitations.js';
import { queueInvitationMail, readInvitationProof, invitationProofHash } from '../invitationMail.js';
import { commitRegistration } from '../registrationStore.js';

export const registerRouter = Router();
const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
const portalUrl = async () => (await getSetting('account_portal_url', config.accountPortalUrl))!;
const qstr = (v: unknown): string => typeof v === 'string' ? v : '';
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const registrationEnabled = async () => (await getSetting('enable_registration','false')) === 'true';
const invitationRequired = async () => (await getSetting('require_invitation_code','true')) === 'true';
function fail(res: Response,error: unknown) {
  if(error instanceof InvitationError) return res.status(error.status).json(error.body);
  console.warn('registration_unavailable');return res.status(503).json({error:'registration_unavailable'});
}
function publicInvitation(row:any) {
  const status = row.used_at ? 'used' : row.voided_at ? 'revoked' : row.invalidated_at ? 'unavailable'
    : new Date(row.expires_at).getTime()<=Date.now() ? 'expired' : 'unused';
  return {code:row.code,label:'Invitation',status,role:{id:row.invited_role_slug,name:row.invited_role_label || row.invited_role_slug},
    created_at:row.created_at,expires_at:row.expires_at,bound_email:row.bound_email,bound_at:row.bound_at,
    mail:{state:row.mail_state,at:row.mail_last_at,error_code:row.mail_error_code}};
}
async function currentInvitation(code:string) {
  const row=await readInvitationPreview(pool,code);
  if(!row)throw new InvitationError(404,'invalid_invitation');
  return publicInvitation(row);
}
async function proofFor(email:string,token:string,includeExpired=false) {
  const modern = await readInvitationProof(pool,email,token,includeExpired);
  if(modern) return {code:modern.code,expiresAt:new Date(modern.expires_at),modern:true};
  const old = await validatePending(email,token);
  if(!old) return null;
  return {code:old.code,expiresAt:new Date((old.createdAt+30*60)*1000),modern:false};
}

registerRouter.post('/internal/register/invitation',async(req:Request,res:Response)=>{
  const body=req.body??{};
  if(!(await isPortalAssertion(body,{method:req.method,path:req.path})))return res.status(401).json({error:'invalid_client'});
  if(!(await registrationEnabled()))return res.status(403).json({error:'registration_closed'});
  const code=qstr(body.code).trim().toUpperCase();
  if(!CODE_RE.test(code))return res.status(404).json({error:'invalid_invitation'});
  try{return res.json({invitation:await currentInvitation(code)});}catch(error){return fail(res,error);}
});

registerRouter.post('/internal/register/start',async(req:Request,res:Response)=>{
  const body=req.body??{};
  if(!(await isPortalAssertion(body,{method:req.method,path:req.path})))return res.status(401).json({error:'invalid_client'});
  if(!(await registrationEnabled()))return res.status(403).json({error:'registration_closed'});
  const email=qstr(body.email).trim().toLowerCase(),code=qstr(body.code).trim().toUpperCase();
  if((await invitationRequired()) || code){
    if(!CODE_RE.test(code))return res.status(422).json({errors:{code:'invalid_code'}});
    if(body.request_id!==undefined&&!UUID_RE.test(qstr(body.request_id)))return res.status(422).json({error:'invalid_request_id'});
    try {
      const result=await withRoleTransaction(async db=>{
        const row=await lockInvitation(db,code);if(!row)throw new InvitationError(422,'invalid_invitation');
        await validateLockedInvitation(db,row,email,false);
        if(!EMAIL_RE.test(email)||email.length>254)throw new InvitationError(422,'invalid_email');
        if((await db.query('SELECT 1 FROM identities WHERE email=$1 AND deleted_at IS NULL',[email])).rowCount || await changePendingForAddress(email))
          throw new InvitationError(422,'email_taken');
        await validateLockedInvitation(db,row,email,true);
        const locked=(await lockInvitation(db,code))!;
        const queued=await queueInvitationMail(db,locked,{actorSub:null,requestId:qstr(body.request_id)||crypto.randomUUID(),requireQueued:true});
        return {queued,invitation:publicInvitation((await lockInvitation(db,code))!)};
      });
      const common={email,bound_email:email,expires_at:result.invitation.expires_at,invitation:result.invitation};
      return res.json({...common,queued:result.queued.queued,sent:result.invitation.mail.state==='sent',resend_backoff:result.queued.retry_after??60});
    }catch(error){return fail(res,error);}
  }
  // Open registration retains its short email-verification flow; invitations use the durable queue above.
  if(!EMAIL_RE.test(email)||email.length>254)return res.status(422).json({errors:{email:'invalid_email'}});
  if((await pool.query('SELECT 1 FROM identities WHERE email=$1 AND deleted_at IS NULL',[email])).rowCount||await changePendingForAddress(email))
    return res.status(422).json({errors:{email:'email_taken'}});
  const [from,account,configured]=await Promise.all([getSetting('mail_from'),getSetting('cf_account_id'),hasSetting('cf_api_token')]);
  if(!from||!account||!configured)return res.status(503).json({error:'email_not_configured'});
  const slot=await reserveRegistrationSend(email);
  if(!slot.ok)return res.status(429).json({error:'rate_limited',retry_after:slot.retryAfter,can_retry:slot.canRetry});
  const {token}=await issuePending(email,null);
  const pending=await validatePending(email,token);
  const sent=await sendEmail({to:email,...renderRegistrationEmail({siteName:await siteName(),link:`${await portalUrl()}/register/complete?email=${encodeURIComponent(email)}&token=${token}`,
    expiresAt:new Date(((pending?.createdAt??Math.floor(Date.now()/1000))+registrationLinkValidityMinutes*60)*1000).toISOString()})});
  if(!sent.ok){await releaseRegistrationSend(email);return res.status(503).json({error:'send_failed'});}
  return res.json({sent:true,resend_backoff:slot.nextBackoff});
});

registerRouter.post('/internal/register/validate',async(req:Request,res:Response)=>{
  const body=req.body??{};
  if(!(await isPortalAssertion(body,{method:req.method,path:req.path})))return res.status(401).json({error:'invalid_client'});
  if(!(await registrationEnabled()))return res.status(403).json({error:'registration_closed'});
  const email=qstr(body.email).trim().toLowerCase(),proof=await proofFor(email,qstr(body.token),true);
  if(!proof)return res.status(422).json({error:'invalid_token'});
  try {
    const invitation=proof.code?await currentInvitation(proof.code):null;
    if(invitation&&invitation.status!=='unused')return res.status(409).json({error:'invitation_'+invitation.status,invitation});
    if(invitation?.bound_email&&invitation.bound_email.toLowerCase()!==email)return res.status(403).json({error:'email_mismatch'});
    return res.json({valid:true,email,bound_email:invitation?.bound_email??email,expires_at:proof.expiresAt,invitation});
  }catch(error){return fail(res,error);}
});

registerRouter.post('/internal/register/check-username',async(req:Request,res:Response)=>{
  const body=req.body??{};
  if(!(await isPortalAssertion(body,{method:req.method,path:req.path})))return res.status(401).json({error:'invalid_client'});
  if(!(await registrationEnabled()))return res.status(403).json({error:'registration_closed'});
  const email=qstr(body.email).trim().toLowerCase(),proof=await proofFor(email,qstr(body.token));
  if(!proof)return res.status(422).json({error:'invalid_token'});
  try {
    if(proof.code){const invitation=await currentInvitation(proof.code);if(invitation.status!=='unused')return res.status(409).json({error:'invitation_'+invitation.status});
      if(invitation.bound_email&&invitation.bound_email.toLowerCase()!==email)return res.status(403).json({error:'email_mismatch'});}
    const username=qstr(body.username).trim();
    if(!USERNAME_RE.test(username))return res.status(422).json({errors:{username:'invalid_username'}});
    return res.json({available:!(await pool.query('SELECT 1 FROM identities WHERE username=$1 AND deleted_at IS NULL',[username])).rowCount});
  }catch(error){return fail(res,error);}
});

registerRouter.post('/internal/register/complete',async(req:Request,res:Response)=>{
  const body=req.body??{};
  if(!(await isPortalAssertion(body,{method:req.method,path:req.path})))return res.status(401).json({error:'invalid_client'});
  if(!(await registrationEnabled()))return res.status(403).json({error:'registration_closed'});
  const email=qstr(body.email).trim().toLowerCase(),token=qstr(body.token),username=qstr(body.username).trim(),displayName=qstr(body.display_name).trim(),password=qstr(body.password);
  const errors:Record<string,string>={};
  if(!USERNAME_RE.test(username))errors.username='invalid_username';
  if(!displayName||displayName.length>100)errors.display_name='invalid_display_name';
  if(/\s/.test(password)||!passwordComplexityOk(password))errors.password='weak_password';
  if(Object.keys(errors).length)return res.status(422).json({errors});
  if(!/^[0-9a-f]{96}$/.test(token))return res.status(422).json({error:'invalid_token'});
  const proofHash=invitationProofHash(token);
  // A keyed digest avoids storing an offline password-check oracle in the retry receipt.
  const receiptKey=Buffer.from(crypto.hkdfSync('sha256',Buffer.from(config.keyEncryptionKey,'hex'),Buffer.alloc(0),'dreamsso:registration-receipt:v1',32));
  const requestHash=crypto.createHmac('sha256',receiptKey).update(JSON.stringify([email,username,displayName,password])).digest();
  const previous=(await pool.query('SELECT request_hash FROM registration_completions WHERE proof_hash=$1 AND retry_until>clock_timestamp()',[proofHash])).rows[0];
  if(previous){if(!Buffer.from(previous.request_hash).equals(requestHash))return res.status(409).json({error:'registration_completed'});
    return res.json({already_completed:true,complete_url:`${await portalUrl()}/auth/login`});}
  const proof=await proofFor(email,token);
  if(!proof)return res.status(422).json({error:'invalid_token'});
  const sub=uuidv7(),passwordHash=await argon2.hash(password,{type:argon2.argon2id});
  const db=await pool.connect();let result;
  try {
    await db.query('BEGIN');
    result=await commitRegistration(db,{sub,username,displayName,email,passwordHash,proofHash,requestHash,code:proof.code,proofExpiresAt:proof.expiresAt,modernProof:proof.modern});
    await db.query('COMMIT');
  }catch(error){
    await db.query('ROLLBACK').catch(()=>{});
    if((error as {code?:string}).code==='23505'){
      const duplicates=(await pool.query('SELECT username=$1 AS u,email=$2 AS e FROM identities WHERE deleted_at IS NULL AND (username=$1 OR email=$2)',[username,email])).rows;
      for(const duplicate of duplicates){if(duplicate.u)errors.username='username_taken';if(duplicate.e)errors.email='email_taken';}
      return res.status(422).json(Object.keys(errors).length?{errors}:{error:'registration_conflict'});
    }
    return fail(res,error);
  }finally{db.release();}
  if(result.replayed)return res.json({already_completed:true,complete_url:`${await portalUrl()}/auth/login`});
  // Post-commit Redis/ticket failures must not turn an existing account into an unexplained error.
  await dropPending(email).catch(()=>{});
  audit({actorSub:sub,actorLabel:`${displayName} (${username})`,action:'user.register',detail:{invite:proof.code??undefined,role:result.role}});
  try{
    const ticket=await mintLoginTicket({sub,amr:['email'],acr:'urn:dreamsso:1fa',userLabel:displayName||username});
    return res.json({complete_url:`${config.issuer}/welcome?ticket=${ticket}`});
  }catch{return res.json({already_completed:true,complete_url:`${await portalUrl()}/auth/login`});}
});

// GET /welcome?ticket= — the browser hop that turns a finished registration
// into a signed-in user; the same machinery as /reset/complete with
// registration-appropriate copy on a dead ticket.
registerRouter.get('/welcome', async (req: Request, res: Response) => {
  const ticket = await redeemLoginTicket(qstr(req.query.ticket));
  const site = await siteName();
  const portal = await portalUrl();
  if (!ticket) {
    const nonce = crypto.randomBytes(16).toString('base64');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader(
      'Content-Security-Policy',
      `default-src 'none'; style-src 'nonce-${nonce}'; base-uri 'none'; frame-ancestors 'none'`,
    );
    return res.status(400).send(renderErrorPage(nonce, {
      title: 'Link expired',
      message: 'This sign-in link has expired or was already used. Your account was still created — just sign in normally.',
      code: 'ticket_expired',
      siteName: site,
      action: { href: portal, label: 'Open the account portal' },
    }));
  }
  const { sid } = await createSession(res, {
    userSub: ticket.sub,
    amr: ticket.amr,
    acr: ticket.acr,
    ip: req.ip,
    userAgent: qstr(req.headers['user-agent']),
    ...clientGeo(req),
  });
  const next = `${portal}/auth/login`;
  const txnId = await createTxn({
    clientId: '', redirectUri: next, codeChallenge: '', codeChallengeMethod: '', scope: '',
    clientName: site, localNext: next,
    kmsi: {
      sid, sub: ticket.sub, userLabel: ticket.userLabel,
      amr: ticket.amr, acr: ticket.acr, authTime: Math.floor(Date.now() / 1000),
    },
  });
  res.redirect(`/login?txn=${encodeURIComponent(txnId)}`);
});
