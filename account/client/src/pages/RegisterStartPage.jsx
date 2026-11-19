import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import { registerInvitation, registerStart } from '../api.js';
import { EMAIL_RE, emailValid, normalizeCode, INVITATION_CODE_RE, invitationStatus,
  invitationErrorStatus, registrationMessage, registrationRequestId, formatInvitationTime } from '../components/registration/invitation.js';
import { InvitationMeta, LockedEmail, RecipientButton, RecipientError, RecipientNotice, useRecipientFeedback } from '../components/registration/RecipientUi.jsx';

const TERMINAL_MAIL = ['sent', 'failed', 'unknown'];

export default function RegisterStartPage() {
  const { siteName, registrationEnabled, invitationRequired, turnstileSiteKey, ssoUrl, refreshSite } = useSite();
  const [params] = useSearchParams();
  const suppliedCode = normalizeCode(params.get('code') || '');
  const loginTxn = params.get('txn') || '';
  const signInHref = loginTxn && ssoUrl ? `${ssoUrl}/login?txn=${encodeURIComponent(loginTxn)}` : '/';
  const [code, setCode] = useState(suppliedCode);
  const [email, setEmail] = useState('');
  const [invitation, setInvitation] = useState(null);
  const [phase, setPhase] = useState(suppliedCode || invitationRequired ? 'code' : 'form');
  const [notice, setNotice] = useState(null);
  const [emailErr, setEmailErr] = useState(null);
  const [codeErr, setCodeErr] = useState(null);
  const [formErr, setFormErr] = useState(null);
  const [attemptedEmail, setAttemptedEmail] = useState('');
  const [uncertain, setUncertain] = useState(false);
  const [mailState, setMailState] = useState('none');
  const [sendDoneLabel, setSendDoneLabel] = useState('Queued');
  const [cooldownUntil, setCooldownUntil] = useState(0);
  const [now, setNow] = useState(Date.now());
  const [pollPaused, setPollPaused] = useState(false);
  const [pollError, setPollError] = useState(null);
  const [pollCycle, setPollCycle] = useState(0);
  const [checkingStatus, setCheckingStatus] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState(null);
  const resetRef = useRef(null);
  const previewSeq = useRef(0);
  const requestRef = useRef(null);
  const confirmedRequest = useRef(false);
  const mounted = useRef(true);
  const feedback = useRecipientFeedback();

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; previewSeq.current++; }; }, []);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);

  const applyInvitation = (next) => {
    setInvitation(next);
    if (next.bound_email) setEmail(next.bound_email);
    if (next.mail?.state) setMailState(next.mail.state);
    const state = invitationStatus(next);
    if (state !== 'unused') setNotice(state || 'unreachable');
  };

  async function preview(requested = code) {
    if (!INVITATION_CODE_RE.test(requested)) { setCodeErr('Codes are 12 letters and digits.'); return; }
    const seq = ++previewSeq.current;
    setPhase('checking'); setFormErr(null); setNotice(null);
    try {
      const data = await registerInvitation(requested);
      if (!mounted.current || seq !== previewSeq.current) return;
      if (!data?.invitation) throw new Error('invalid_response');
      const next = data.invitation; applyInvitation(next);
      const queued = ['queued', 'sending'].includes(next.mail?.state);
      setPhase(queued && next.bound_email ? 'sent' : 'form');
      if (queued) setAttemptedEmail(next.bound_email || '');
    } catch (err) {
      if (!mounted.current || seq !== previewSeq.current) return;
      setNotice(err.code === 'registration_closed' ? 'closed' : invitationErrorStatus(err) || 'unreachable');
      setPhase('code');
    }
  }

  useEffect(() => {
    previewSeq.current++; feedback.reset();
    setCode(suppliedCode); setInvitation(null); setNotice(null); setEmail('');
    setAttemptedEmail(''); setUncertain(false); setFormErr(null); setPollError(null); setMailState('none');
    setCheckingStatus(false); setCooldownUntil(0); setPollPaused(false); setSendDoneLabel('Queued');
    requestRef.current = null; confirmedRequest.current = false;
    if (suppliedCode) preview(suppliedCode);
    else setPhase(invitationRequired ? 'code' : 'form');
    // Only a new link or a changed registration policy starts a new ceremony.
  }, [suppliedCode, invitationRequired]); // eslint-disable-line react-hooks/exhaustive-deps

  // An acknowledged queue is a status, never a permanently busy button. Poll
  // only its read-only preview, for at most two minutes, then offer manual retry.
  useEffect(() => {
    if (phase !== 'sent' || !invitation?.code || !['queued', 'sending'].includes(mailState) || notice || checkingStatus) return undefined;
    let alive = true, timer;
    const started = Date.now();
    setPollPaused(false);
    const poll = async () => {
      try {
        const data = await registerInvitation(invitation.code);
        if (!alive) return;
        if (!data?.invitation) throw new Error('invalid_response');
        applyInvitation(data.invitation); setPollError(null);
        if (TERMINAL_MAIL.includes(data.invitation.mail?.state) || invitationStatus(data.invitation) !== 'unused') return;
      } catch {
        if (!alive) return;
        setPollError('We could not refresh the email status. The queued request is unchanged.');
      }
      if (!alive) return;
      if (Date.now() - started >= 120000) { setPollPaused(true); return; }
      timer = setTimeout(poll, 2000);
    };
    timer = setTimeout(poll, 2000);
    return () => { alive = false; clearTimeout(timer); };
  }, [phase, invitation?.code, mailState, notice, pollCycle, checkingStatus]); // eslint-disable-line react-hooks/exhaustive-deps

  const state = invitationStatus(invitation, now);
  const effectiveNotice = registrationEnabled === false ? 'closed' : notice || (state && state !== 'unused' ? state : null);
  const boundEmail = invitation?.bound_email || '';
  const shownEmail = boundEmail || attemptedEmail || email;
  const cooldown = Math.max(0, Math.ceil((cooldownUntil - now) / 1000));
  const queued = ['queued', 'sending'].includes(mailState);
  const locked = !!boundEmail || uncertain || feedback.busy;
  const humanReady = !turnstileSiteKey || !!turnstileToken;

  async function checkStatus() {
    if (!invitation?.code || checkingStatus) return;
    const operationSeq = previewSeq.current;
    setCheckingStatus(true); setFormErr(null);
    try {
      const data = await registerInvitation(invitation.code);
      if (!mounted.current || operationSeq !== previewSeq.current) return;
      if (!data?.invitation) throw new Error('invalid_response');
      applyInvitation(data.invitation); setPollCycle((value) => value + 1);
    } catch (err) {
      if (mounted.current && operationSeq === previewSeq.current) setFormErr(registrationMessage(err));
    } finally { if (mounted.current && operationSeq === previewSeq.current) setCheckingStatus(false); }
  }

  async function submit(event) {
    event?.preventDefault();
    if (feedback.held || queued || cooldown > 0 || !humanReady || effectiveNotice) return;
    const address = (boundEmail || (phase === 'sent' ? attemptedEmail : email)).trim().toLowerCase();
    if (!emailValid(address)) { setEmailErr(EMAIL_RE.test(address) ? 'Email addresses are at most 254 characters.' : 'Enter a valid email address.'); return; }
    if ((invitationRequired || code) && !invitation) { await preview(); return; }
    if (invitation && invitationStatus(invitation) !== 'unused') { setNotice(invitationStatus(invitation)); return; }
    const operationSeq = previewSeq.current;
    if (!feedback.start()) return;
    setFormErr(null); setEmailErr(null); setAttemptedEmail(address);
    const key = (invitation?.code || '') + ':' + address;
    if (invitation && (!requestRef.current || requestRef.current.key !== key || (confirmedRequest.current && TERMINAL_MAIL.includes(mailState)))) {
      requestRef.current = { key, id: registrationRequestId(invitation.code, address, confirmedRequest.current) };
    }
    confirmedRequest.current = false;
    setUncertain(true);
    try {
      const data = await registerStart(address, invitation?.code || undefined, turnstileToken, requestRef.current?.id);
      if (!mounted.current || operationSeq !== previewSeq.current) return;
      if (data?.queued !== true && data?.sent !== true && !TERMINAL_MAIL.includes(data?.invitation?.mail?.state)) throw new Error('invalid_response');
      confirmedRequest.current = true; setUncertain(false);
      if (data?.invitation) applyInvitation(data.invitation);
      if (data?.bound_email) setEmail(data.bound_email);
      setCooldownUntil(Date.now() + Math.max(0, Number(data?.resend_backoff) || 60) * 1000);
      const reportedMail = data.invitation?.mail?.state;
      const nextMail = data.queued ? (['queued', 'sending', ...TERMINAL_MAIL].includes(reportedMail) ? reportedMail : 'queued')
        : TERMINAL_MAIL.includes(reportedMail) ? reportedMail : 'sent';
      setMailState(nextMail); setSendDoneLabel(nextMail === 'sent' ? 'Sent' : 'Queued');
      setTurnstileToken(null); resetRef.current?.();
      feedback.finish(['failed', 'unknown'].includes(nextMail) ? 'fail' : 'done', () => setPhase('sent'));
    } catch (err) {
      if (!mounted.current || operationSeq !== previewSeq.current) return;
      let showSendStatus = false;
      setTurnstileToken(null); resetRef.current?.();
      if (err.data?.invitation) {
        applyInvitation(err.data.invitation);
        showSendStatus = err.data.invitation.mail?.state !== 'none' && !!err.data.invitation.mail?.state;
      }
      const ended = invitationErrorStatus(err);
      if (ended) setNotice(ended);
      const fields = err.data?.errors || {};
      if (fields.email === 'email_taken' || err.code === 'email_taken') setEmailErr('This email address is already registered.');
      else if (fields.email || err.code === 'invalid_email') setEmailErr('Enter a valid email address.');
      else if (fields.code) { setCodeErr('This invitation code cannot be used.'); setNotice('invalid'); }
      else setFormErr(registrationMessage(err));
      if (err.code === 'registration_closed') { setNotice('closed'); refreshSite(); }
      if (err.code === 'turnstile_failed' && !turnstileSiteKey) refreshSite();
      if (err.status === 429) setCooldownUntil(Date.now() + Math.max(1, Number(err.data?.retry_after) || 60) * 1000);
      const definitelyRejected = err.status >= 400 && err.status < 500;
      if (definitelyRejected || TERMINAL_MAIL.includes(err.data?.invitation?.mail?.state)
          || (!invitation && ['send_failed', 'email_not_configured'].includes(err.code))) setUncertain(false);
      // Binding is authoritative even when sending failed. A read can discover
      // it, but cannot authorize a new UUID for this uncertain operation.
      if (invitation?.code && !err.data?.invitation) {
        try {
          const data = await registerInvitation(invitation.code);
          if (mounted.current && operationSeq === previewSeq.current && data?.invitation) {
            applyInvitation(data.invitation);
            showSendStatus = data.invitation.mail?.state !== 'none' && !!data.invitation.mail?.state;
          }
        } catch { /* keep the entered address locked until the request is resolved */ }
      }
      feedback.finish('fail', () => { if (showSendStatus) setPhase('sent'); });
    }
  }

  if (effectiveNotice) return <AuthCard docTitle="Create account"><RecipientNotice status={effectiveNotice} invitation={invitation}
    signInHref={signInHref} onRetry={effectiveNotice === 'unreachable' ? () => preview() : undefined} /></AuthCard>;
  if (phase === 'checking') return <AuthCard docTitle="Create account"><div className="auth-spinner" aria-hidden="true" /><p className="auth-wait">Checking your invitation…</p></AuthCard>;
  if (phase === 'code') return <AuthCard docTitle="Create account" title="Use your invitation"
    sub="Enter your invitation code to see the access it offers" cta={<>Already have an account? <a href={signInHref}>Sign in</a></>}>
    <form className="recipient-form" noValidate onSubmit={(event) => { event.preventDefault(); preview(); }}>
      <div className={'auth-grp' + (codeErr ? ' bad' : '')}><label htmlFor="reg-code">Invitation code</label>
        <input id="reg-code" className="auth-input mono" value={code} autoFocus autoComplete="off" autoCapitalize="characters" maxLength={12}
          onChange={(event) => { setCode(normalizeCode(event.target.value)); setCodeErr(null); }} />
        <span className="auth-ferr">{codeErr}</span></div>
      <button type="submit" className="auth-btn">Continue</button>
      {!invitationRequired && <button type="button" className="auth-alt" onClick={() => { setCode(''); setCodeErr(null); setPhase('form'); }}>Continue without an invitation</button>}
      <RecipientError error={formErr} />
    </form>
  </AuthCard>;

  if (phase === 'sent') {
    const failed = mailState === 'failed';
    const unknown = mailState === 'unknown';
    const title = queued ? 'Email queued' : uncertain ? 'Request not confirmed' : failed ? 'Email not sent' : unknown ? 'Email status unknown' : 'Check your email';
    const intro = queued ? 'Your registration email is queued for sending to '
      : uncertain ? 'We could not confirm the request for '
        : failed ? 'The latest email could not be sent to ' : unknown ? 'The send result could not be confirmed for ' : 'The mail provider accepted a registration link for ';
    return <AuthCard docTitle="Create account"><div className="auth-done recipient-notice info"><Icon name="mail" size={26} /></div>
      <h1 className="auth-h1">{title}</h1><p className="auth-msg">{intro}<strong>{shownEmail}</strong>.</p>
      {invitation ? <p className="auth-msg">This invitation stays reserved for that address. The link works until {formatInvitationTime(invitation.expires_at)}; sending again does not extend its deadline.</p>
        : <p className="auth-msg">Open the link to choose your username and password. It expires in 30 minutes.</p>}
      {queued && <p className="recipient-queued">{pollPaused ? 'It is still queued. Check the status again shortly.' : 'We are checking the send status. This does not mean the email was delivered.'}</p>}
      {(queued || uncertain) && <button type="button" className="auth-alt" disabled={checkingStatus} onClick={checkStatus}>{checkingStatus ? 'Checking status…' : 'Check status'}</button>}
      {!queued && cooldown <= 0 && <Turnstile onToken={setTurnstileToken} onExpire={() => setTurnstileToken(null)} onError={() => setTurnstileToken(null)} resetRef={resetRef} />}
      <RecipientButton type="button" onClick={submit} feedback={feedback} rest={queued ? 'Queued for sending' : cooldown > 0 ? `Resend in ${cooldown}s` : uncertain ? 'Retry request' : 'Resend email'}
        done={sendDoneLabel} fail="Not sent" disabled={queued || cooldown > 0 || !humanReady} />
      <RecipientError error={formErr || pollError || (failed ? 'We could not send the email. Try sending again to the same address.' : unknown ? 'A previous email may still arrive. You can request another for the same address.' : null)} />
      {invitation ? <p className="recipient-meta">Wrong address? Ask the person who invited you for a new invitation. This one cannot move to another address.</p>
        : <a className="recipient-signin" href="/register/start">Use a different address</a>}
      <InvitationMeta invitation={invitation} />
    </AuthCard>;
  }

  return <AuthCard docTitle="Create account" title={invitation ? `Join ${siteName || 'DreamSSO'}` : 'Create your account'}
    sub={invitation ? `${invitation.role?.name ? `You are invited as a ${invitation.role.name}.` : 'You are invited.'} ${boundEmail ? 'Send a registration link to your invited address.' : 'Enter your email to get a registration link.'}` : 'Enter your email address to get started'}
    cta={<>Already have an account? <a href={signInHref}>Sign in</a></>}>
    {invitation && <div className="auth-chip"><span>Invitation <code>{invitation.code}</code></span></div>}
    <form className="recipient-form" noValidate onSubmit={submit}>
      {boundEmail ? <LockedEmail email={boundEmail} /> : <div className={'auth-grp' + (emailErr ? ' bad' : '')}>
        <label htmlFor="reg-email">Email address</label><input id="reg-email" type="email" inputMode="email" className="auth-input" autoFocus autoComplete="email" autoCapitalize="none" autoCorrect="off" spellCheck="false" maxLength={254}
          readOnly={locked} value={email} onChange={(event) => { setEmail(event.target.value.replace(/\s/g, '')); setEmailErr(null); }}
          onBlur={() => { if (email && !emailValid(email.trim())) setEmailErr('Enter a valid email address.'); }} />
        <span className="auth-ferr">{emailErr}</span>
        {invitation && <span className="recipient-hint">The first address submitted is tied to this invitation permanently.</span>}
      </div>}
      <Turnstile onToken={setTurnstileToken} onExpire={() => setTurnstileToken(null)} onError={() => setTurnstileToken(null)} resetRef={resetRef} />
      <RecipientButton type="submit" feedback={feedback} rest={uncertain ? 'Retry request' : 'Send registration email'} done={invitation ? sendDoneLabel : 'Sent'} fail="Not sent" disabled={!emailValid((boundEmail || email).trim()) || !humanReady || cooldown > 0} />
      <RecipientError error={formErr || emailErr} />
    </form>
    {!invitation && !invitationRequired && <button type="button" className="auth-alt" onClick={() => setPhase('code')}>Use an invitation code</button>}
    <InvitationMeta invitation={invitation} />
  </AuthCard>;
}
