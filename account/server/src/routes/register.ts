import { Router, type Request, type Response } from 'express';
import { getSession } from '../session.js';
import { SESSION_COOKIE } from './auth.js';
import { enforceTurnstileGate, s2sPost, mirror } from './reset.js';

// Public registration API for /register/start + /register/complete. The BFF
// gates mail sends and account creation with Turnstile; emailed mailbox-proof
// checks do not need another human challenge. The
// SSO owns binding, deadlines, delivery, quotas, identity creation and tickets.
// Mutations retain Turnstile -> invitation -> recipient-email validation order.
export const registerRouter = Router();

const qstr = (v: unknown): string => (typeof v === 'string' ? v : '');
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

// Retired: nonsecret invitation codes must not disclose recipient details.
registerRouter.post('/api/register/invitation',(_req:Request,res:Response)=>
  res.status(404).set('Cache-Control','no-store').json({error:'not_found'}));

// POST /api/register/start {email, code?, request_id?, turnstile_token?}
registerRouter.post('/api/register/start', async (req: Request, res: Response) => {
  const started=Date.now();
  res.set('Cache-Control','no-store');
  try {
    // Preserve the human gate before all invitation/email policy checks.
    if (!(await enforceTurnstileGate(req, res))) return;
    if (await getSession(req.cookies?.[SESSION_COOKIE])) return res.status(400).json({error:'already_authenticated'});
    const body=req.body??{},email=qstr(body.email).trim(),code=qstr(body.code).trim().toUpperCase().replace(/\s/g,''),requestId=qstr(body.request_id).toLowerCase();
    const remaining=19_000-(Date.now()-started);
    if(remaining<13_000)return res.status(504).json({error:'upstream_timeout'});
    const upstream=await s2sPost('/internal/register/start',{email,code:code||undefined,request_id:requestId||undefined},
      {timeoutMs:Math.min(15_000,remaining)});
    const data=await upstream.json().catch((error)=>{if(['AbortError','TimeoutError'].includes(error?.name))throw error;return null;}) as any;
    if(upstream.status===401)return res.status(502).json({error:'upstream_unreachable'});
    const validId=UUID_RE.test(requestId),echo=data?.request_id===requestId&&validId;
    // During a rolling update the old SSO acknowledges a durable invitation
    // queue, but its latest invitation mail state is not this request's result.
    const old=data?.invitation,normalizedEmail=email.toLowerCase();
    const legacyInvitation=upstream.status===200&&data?.result===undefined&&data?.request_id===undefined&&validId
      &&/^[A-Z0-9]{12}$/.test(code)&&old?.code===code&&data.email===normalizedEmail&&data.bound_email===normalizedEmail
      &&old.bound_email===normalizedEmail&&typeof old.role?.id==='string'&&typeof old.role?.name==='string'
      &&['unused','used','expired','revoked','unavailable'].includes(old.status)
      &&typeof old.created_at==='string'&&Number.isFinite(Date.parse(old.created_at))
      &&typeof old.expires_at==='string'&&Number.isFinite(Date.parse(old.expires_at))
      &&['none','queued','sending','sent','failed','unknown'].includes(old.mail?.state)
      &&typeof data.queued==='boolean'&&typeof data.sent==='boolean';
    if(legacyInvitation)return res.status(202).json({result:'pending',request_id:requestId,resend_backoff:5});
    // Legacy open registration already waited for provider acceptance. It has
    // no invitation queue/receipt, so preserve its positive result without
    // inventing a scoped retry identity or exposing any extra payload fields.
    const legacyOpen=upstream.status===200&&data?.sent===true&&data?.result===undefined
      &&data?.invitation===undefined&&data?.queued===undefined&&data?.request_id===undefined
      &&Object.keys(data).every(key=>['sent','resend_backoff'].includes(key))
      &&Number.isFinite(data.resend_backoff)&&data.resend_backoff>=0&&data.resend_backoff<=86400;
    if(legacyOpen)return res.json({result:'sent',sent:true,mail:{state:'sent',at:null,error_code:null},resend_backoff:data.resend_backoff});
    const response:Record<string,unknown>={};
    if(echo)response.request_id=requestId;
    if(typeof data?.expires_at==='string'&&Number.isFinite(Date.parse(data.expires_at)))response.expires_at=data.expires_at;
    for(const key of ['resend_backoff','retry_after'])if(Number.isFinite(data?.[key])&&data[key]>=0&&data[key]<=86400)response[key]=data[key];
    if(typeof data?.can_retry==='boolean')response.can_retry=data.can_retry;
    const safeErrors=['email_mismatch','invalid_email','email_taken','invalid_code','invalid_invitation','invalid_request_id','request_conflict','registration_closed','invitation_expired','invitation_used','invitation_revoked','invitation_unavailable','rate_limited','send_failed','email_not_configured','registration_unavailable'];
    const safeMailErrors=['delivery_unknown','send_failed','email_not_configured','invitation_unavailable','bounced','rejected'];
    if(['queued','sending','sent','failed','unknown'].includes(data?.mail?.state)){
      response.mail={state:data.mail.state,at:typeof data.mail.at==='string'&&Number.isFinite(Date.parse(data.mail.at))?data.mail.at:null,
        error_code:safeMailErrors.includes(data.mail.error_code)?data.mail.error_code:null};
    }
    if(upstream.status===200||upstream.status===202){
      const accepted=upstream.status===200&&data?.result==='sent'&&data?.mail?.state==='sent';
      const pending=upstream.status===202&&data?.result==='pending'&&(!data?.mail||['queued','sending'].includes(data.mail.state));
      const unknown=upstream.status===202&&data?.result==='unknown'&&data?.mail?.state==='unknown';
      if((data?.request_id!==undefined&&!echo)||!accepted&&!pending&&!unknown)return res.status(502).json({error:'upstream_unreachable'});
      response.result=data.result;
      if(accepted)response.sent=true; // Compatibility for an older cached Start page; never a queue acknowledgement.
      return res.status(upstream.status).json(response);
    }
    if(!safeErrors.includes(data?.error)&&!data?.errors)return res.status(502).json({error:'upstream_unreachable'});
    if(safeErrors.includes(data?.error))response.error=data.error;
    const errors:Record<string,string>={};
    for(const key of ['email','code'])if(safeErrors.includes(data?.errors?.[key]))errors[key]=data.errors[key];
    if(Object.keys(errors).length)response.errors=errors;
    if(!response.error&&!response.errors)return res.status(502).json({error:'upstream_unreachable'});
    return res.status(upstream.status).json(response);
  } catch(error) {
    const timeout=['AbortError','TimeoutError'].includes((error as Error)?.name);
    return res.status(timeout?504:502).json({error:timeout?'upstream_timeout':'upstream_unreachable'});
  }
});

// POST /api/register/validate {email, token} — is the emailed link usable?
registerRouter.post('/api/register/validate', async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    await mirror(res, await s2sPost('/internal/register/validate', {
      email: qstr(body.email).trim(), token: qstr(body.token),
    }));
  } catch (e) {
    console.error('register validate proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/check-username {email, token, username} — on-blur
// availability (token-gated upstream; not a public oracle).
registerRouter.post('/api/register/check-username', async (req: Request, res: Response) => {
  try {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const username = qstr(body.username).trim();
    if (!USERNAME_RE.test(username)) return res.status(422).json({ errors: { username: 'invalid_username' } });
    await mirror(res, await s2sPost('/internal/register/check-username', {
      email: qstr(body.email).trim(), token: qstr(body.token), username,
    }));
  } catch (e) {
    console.error('register check proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});

// POST /api/register/complete {email, token, username, display_name, password,
// confirm_password, turnstile_token?} — fresh Turnstile, then forward; the SSO
// answers {complete_url} for the /welcome sign-in hop.
registerRouter.post('/api/register/complete', async (req: Request, res: Response) => {
  try {
    // Turnstile FIRST — single-use token, consumed on every request (matches the
    // edge worker) so the client resets the widget after any error.
    if (!(await enforceTurnstileGate(req, res))) return;

    if (await getSession(req.cookies?.[SESSION_COOKIE])) {
      return res.status(400).json({ error: 'already_authenticated' });
    }

    const body = (req.body ?? {}) as Record<string, unknown>;
    const password = qstr(body.password);
    if (password !== qstr(body.confirm_password)) {
      return res.status(422).json({ errors: { confirm: 'mismatch' } });
    }
    await mirror(res, await s2sPost('/internal/register/complete', {
      email: qstr(body.email).trim(),
      token: qstr(body.token),
      username: qstr(body.username).trim(),
      display_name: qstr(body.display_name).trim(),
      password,
    }));
  } catch (e) {
    console.error('register complete proxy failed:', (e as Error).message);
    res.status(502).json({ error: 'upstream_unreachable' });
  }
});
