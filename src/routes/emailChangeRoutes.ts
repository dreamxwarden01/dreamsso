import { currentSessionContextError } from '../oidc/currentSession.js';
import { Router, type Response } from 'express';
import { pool } from '../db.js';
import { config } from '../config.js';
import { getSetting, hasSetting } from '../settings.js';
import { requireScope, type AuthedRequest } from '../resourceAuth.js';
import { hasPerm, permissionDenied } from '../rbac/index.js';
import { isStepupFresh } from '../oidc/sessions.js';
import { acceptedStepupMethods, stepupSatisfies } from '../oidc/stepupPolicy.js';
import { maskEmail } from '../emailOtp.js';
import { sendEmail } from '../email.js';
import { renderEmailVerifyEmail, renderEmailChangedEmail } from '../emailTemplates.js';
import { releaseRegistrationSend } from '../registration.js';
import { identityConflict } from '../identityConflicts.js';
import {
  getEmailChangeState, issueEmailChange, resendEmailChange, completeEmailChange, cancelEmailChange, emailChangeInput, EmailChangeError,
} from '../emailChange.js';
import { isPortalAssertion } from './reset.js';
import { audit, actorLabel } from '../audit.js';

// Email verification (change + confirm-current) — VERIFY-THEN-COMMIT: the
// account's email swaps only when the emailed link is clicked; until then the
// old address stays live for OTP/recovery. Starting a CHANGE is gated by the
// user's strongest tier (user rule): fresh step-up when a passkey/TOTP
// exists -> an OTP to the CURRENT address -> the current password when there
// is no email at all (the add case). The public verify hop rides the BFF over
// /internal/* with the portal client assertion, like reset/registration.
export const emailChangeRouter = Router();
const scoped = requireScope('profile');

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const siteName = async () => (await getSetting('site_name', 'DreamSSO'))!;
const portalUrl = async () => (await getSetting('account_portal_url', config.accountPortalUrl))!;

interface IdentityRow {
  sub: string; username: string; display_name: string;
  email: string | null; email_verified: boolean; password_hash: string | null;
}
async function loadIdentity(sub: string): Promise<IdentityRow | null> {
  const { rows: [r] } = await pool.query(
    `SELECT sub, username, display_name, email, email_verified, password_hash
       FROM identities WHERE sub = $1 AND deleted_at IS NULL AND status = 'active'`,
    [sub],
  );
  return (r as IdentityRow) ?? null;
}

// Sensitive self-service changes (email + username) require a fresh FALLBACK-tier
// step-up window: the tiered challenge (passkey/totp if owned, else an OTP to the
// current email, else the password) is proven through /account/stepup/*, which
// stamps the master session — so this just checks the stamp (method ∈ accepted +
// freshness) like the personal-security gates, instead of a bespoke inline proof.
// Sends 403 step_up_required itself and returns false on failure. 10-min cap, same
// as factor management.
const STEPUP_MAX_S = 600;
async function requireFreshStepup(id: IdentityRow, req: AuthedRequest, res: Response): Promise<boolean> {
  const contextError = currentSessionContextError(req.auth, req.headers['x-stepup-sid']);
  if (contextError) { res.status(403).json({ error: contextError });return false; }
  const sid = qstr(req.headers['x-stepup-sid']);
  if (sid) {
    const { rows: [s] } = await pool.query<{ user_sub: string; stepup_at: string | null; stepup_method: string | null }>(
      'SELECT user_sub, EXTRACT(EPOCH FROM stepup_at)::text AS stepup_at, stepup_method FROM sessions WHERE sid = $1',
      [sid],
    );
    if (s && s.user_sub === id.sub) {
      const at = s.stepup_at ? Number(s.stepup_at) : null;
      const withinCap = at != null && Date.now() / 1000 - at < STEPUP_MAX_S;
      const { accepted } = await acceptedStepupMethods(id.sub, 'email-change');
      if (withinCap && stepupSatisfies(accepted, s.stepup_method, await isStepupFresh(at))) return true;
    }
  }
  res.status(403).json({ error: 'step_up_required' });
  return false;
}

// GET /account/email-change — the LIVE address + pending state + which gate
// applies. The portal renders email from here, not from its session claims —
// a verified swap lands SSO-side without touching the BFF session.
emailChangeRouter.get('/account/email-change', scoped, async (req: AuthedRequest, res: Response) => {
  const state=await getEmailChangeState(req.auth!.sub);
  if(!state)return res.status(404).json({error:'not_found'});
  return res.json(state);
});

function changeFailure(res:Response,error:unknown){
  if(error instanceof EmailChangeError)return res.status(error.status).json({error:error.code,...error.details,
    ...(['email_taken','same_email'].includes(error.code)?{errors:{new_email:error.code}}:{})});
  const conflict=identityConflict(error);
  if(conflict)return res.status(409).json({error:conflict+'_taken',errors:{[conflict==='email'?'new_email':'new_username']:conflict+'_taken'}});
  console.warn('email_change_unavailable');return res.status(503).json({error:'email_change_unavailable'});
}
async function mailConfigured(){
  const [from,account,token]=await Promise.all([getSetting('mail_from'),getSetting('cf_account_id'),hasSetting('cf_api_token')]);
  return !!(from&&account&&token);
}
async function sendChangeEmail(res:Response,op:Awaited<ReturnType<typeof issueEmailChange>>){
  const [site,portal]=await Promise.all([siteName(),portalUrl()]);
  const sent=await sendEmail({to:op.newEmail,...renderEmailVerifyEmail({siteName:site,kind:op.kind,
    link:`${portal}/verify-email?token=${op.token}`,minutes:Math.max(1,Math.ceil((Date.parse(op.expiresAt)-Date.now())/60000))})});
  if(!sent.ok){
    if(!['unreachable','unknown'].includes(sent.reason))await releaseRegistrationSend(op.newEmail);
    return res.status(503).json({error:['unreachable','unknown'].includes(sent.reason)?'send_unconfirmed':'send_failed',
      request_id:op.requestId,revision:op.revision,expires_at:op.expiresAt,resend_backoff:op.resendBackoff});
  }
  return res.json({sent:true,new_email:op.newEmail,request_id:op.requestId,revision:op.revision,
    expires_at:op.expiresAt,resend_backoff:op.resendBackoff});
}

// POST /account/email-change/check {new_email} — availability probe run the
// moment the user submits the new value, BEFORE the identity challenge (user
// rule: fail fast, don't waste a challenge). The same checks re-run at start
// and again at verify — this is UX, not enforcement.
emailChangeRouter.post('/account/email-change/check', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  const newEmail = qstr((req.body ?? {}).new_email).trim();
  if (!EMAIL_RE.test(newEmail) || newEmail.length > 254) {
    return res.status(422).json({ errors: { new_email: 'invalid_email' } });
  }
  if ((id.email ?? '').toLowerCase() === newEmail.toLowerCase()) {
    return res.status(422).json({ errors: { new_email: 'same_email' } });
  }
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE email = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newEmail, id.sub],
  );
  if (taken) {
    return res.status(409).json({ errors: { new_email: 'email_taken' } });
  }
  res.status(204).end();
});

// POST /account/username-change/check {new_username} — same early probe.
emailChangeRouter.post('/account/username-change/check', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  if (!(await hasPerm(id.sub, 'profile.username.change'))) {
    return permissionDenied(res, 'profile.username.change');
  }
  const newUsername = qstr((req.body ?? {}).new_username).trim();
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(newUsername)) {
    return res.status(422).json({ errors: { new_username: 'invalid_username' } });
  }
  if (id.username.toLowerCase() === newUsername.toLowerCase()) {
    return res.status(422).json({ errors: { new_username: 'same_username' } });
  }
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE username = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newUsername, id.sub],
  );
  if (taken) return res.status(409).json({ errors: { new_username: 'username_taken' } });
  res.status(204).end();
});

// POST /account/email-change/start {new_email}
// (+ x-stepup-sid injected by the BFF — the fresh fallback step-up is the proof)
emailChangeRouter.post('/account/email-change/start', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  const permKey = id.email == null ? 'profile.email.add' : 'profile.email.change';
  if (!(await hasPerm(id.sub, permKey))) return permissionDenied(res, permKey);

  const body = (req.body ?? {}) as Record<string, unknown>;
  const newEmail = qstr(body.new_email).trim();
  if (!EMAIL_RE.test(newEmail) || newEmail.length > 254) {
    return res.status(422).json({ errors: { new_email: 'invalid_email' } });
  }
  if ((id.email ?? '').toLowerCase() === newEmail.toLowerCase()) {
    return res.status(422).json({ errors: { new_email: 'same_email' } });
  }

  // Availability is a helpful early check. The final SQL write is authoritative.
  const { rows: [taken] } = await pool.query('SELECT 1 FROM identities WHERE email=$1 AND sub<>$2 AND deleted_at IS NULL',[newEmail,id.sub]);
  if(taken)return res.status(409).json({errors:{new_email:'email_taken'}});

  let operationInput;
  try{operationInput=emailChangeInput(qstr(body.request_id),qstr(body.expected_revision));}
  catch(error){return changeFailure(res,error);}

  // Fresh fallback-tier step-up — ALWAYS enforced (no settings toggle).
  const gated = await requireFreshStepup(id, req, res);
  if (!gated) return;

  if(!await mailConfigured())return res.status(503).json({error:'email_not_configured'});
  try{
    const op=await issueEmailChange(id.sub,'change',newEmail,operationInput);
    return await sendChangeEmail(res,op);
  }catch(error){return changeFailure(res,error);}
});

// Retry and cancellation name the displayed operation; a stale tab cannot
// resend or remove a newer operation belonging to this same account.
emailChangeRouter.post('/account/email-change/resend', scoped, async(req:AuthedRequest,res:Response)=>{
  if(!await mailConfigured())return res.status(503).json({error:'email_not_configured'});
  try{return await sendChangeEmail(res,await resendEmailChange(req.auth!.sub,qstr(req.body?.request_id)));}
  catch(error){return changeFailure(res,error);}
});
emailChangeRouter.delete('/account/email-change', scoped, async(req:AuthedRequest,res:Response)=>{
  try{await cancelEmailChange(req.auth!.sub,qstr(req.body?.request_id));return res.status(204).end();}
  catch(error){return changeFailure(res,error);}
});

// Confirmation of the current address uses the same bounded, current-operation
// proof but does not grant a change to another address.
emailChangeRouter.post('/account/email/verify/send', scoped, async(req:AuthedRequest,res:Response)=>{
  const id=await loadIdentity(req.auth!.sub);
  if(!id||!id.email)return res.status(409).json({error:'no_email'});
  if(id.email_verified)return res.status(409).json({error:'already_verified'});
  if(!await mailConfigured())return res.status(503).json({error:'email_not_configured'});
  try{return await sendChangeEmail(res,await issueEmailChange(id.sub,'confirm',id.email,
    {requestId:qstr(req.body?.request_id),expectedRevision:qstr(req.body?.expected_revision)}));}
  catch(error){return changeFailure(res,error);}
});

// POST /account/username-change {new_username, otp_code?, password?} — the
// SAME one-time verification as the email change (user rule), but committing
// immediately: usernames have no inbox to prove. Permission-gated by
// profile.username.change (superadmin-only by default).
emailChangeRouter.post('/account/username-change', scoped, async (req: AuthedRequest, res: Response) => {
  const id = await loadIdentity(req.auth!.sub);
  if (!id) return res.status(404).json({ error: 'not_found' });
  if (!(await hasPerm(id.sub, 'profile.username.change'))) {
    return permissionDenied(res, 'profile.username.change');
  }

  const body = (req.body ?? {}) as Record<string, unknown>;
  const newUsername = qstr(body.new_username).trim();
  if (!/^[A-Za-z0-9_-]{3,20}$/.test(newUsername)) {
    return res.status(422).json({ errors: { new_username: 'invalid_username' } });
  }
  if (id.username.toLowerCase() === newUsername.toLowerCase()) {
    return res.status(422).json({ errors: { new_username: 'same_username' } });
  }
  // Uniqueness BEFORE the gate (single-use OTP proof, same rule as email).
  const { rows: [taken] } = await pool.query(
    'SELECT 1 FROM identities WHERE username = $1 AND sub <> $2 AND deleted_at IS NULL',
    [newUsername, id.sub],
  );
  if (taken) return res.status(409).json({ errors: { new_username: 'username_taken' } });

  const gated = await requireFreshStepup(id, req, res);
  if (!gated) return;

  try {
    const changed=await pool.query("UPDATE identities SET username = $2 WHERE sub = $1 AND deleted_at IS NULL AND status='active'", [id.sub, newUsername]);
    if(!changed.rowCount)return res.status(404).json({error:'not_found'});
  } catch (e) {
    if (identityConflict(e) === 'username') {
      return res.status(409).json({ errors: { new_username: 'username_taken' } });
    }
    throw e;
  }
  audit({
    actorSub: id.sub, actorLabel: await actorLabel(id.sub),
    action: 'username.change', detail: { from: id.username, to: newUsername },
  });
  res.json({ username: newUsername });
});

// POST /internal/email-change/verify {token} — the public capability hop
// (clicker may be signed out; the token authorizes). Commits the swap (or the
// confirm), then notifies the OLD address — after everything, per the design.
emailChangeRouter.post('/internal/email-change/verify', async (req, res: Response) => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  if (!(await isPortalAssertion(body, { method: req.method, path: req.path }))) return res.status(401).json({ error: 'invalid_client' });

  let result;
  try{result=await completeEmailChange(qstr(body.token));}
  catch(error){return changeFailure(res,error);}
  if(result.replayed)return res.json({ok:true,kind:result.kind,replayed:true});
  const {oldEmail,identity:id,newEmail}=result;
  if (oldEmail) {
    // Fire-and-forget: the notice must never block the verify response.
    void (async () => {
      const [site, portal] = await Promise.all([siteName(), portalUrl()]);
      const sent = await sendEmail({
        to: oldEmail,
        ...renderEmailChangedEmail({
          siteName: site, username: id.username,
          newEmailMasked: maskEmail(newEmail), portalUrl: portal,
        }),
      });
      if (!sent.ok) console.warn(`email-change notice to old address failed: ${sent.reason}`);
    })().catch((e) => console.warn('email-change notice failed:', (e as Error).message));
  }
  res.json({ ok: true, kind: result.kind });
});
