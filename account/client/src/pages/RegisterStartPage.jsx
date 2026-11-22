import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import { registerStart } from '../api.js';
import { EMAIL_RE, emailValid, normalizeCode, INVITATION_CODE_RE, invitationStatus,
  invitationErrorStatus, registrationMessage, registrationRequestId, retireRegistrationRequest } from '../components/registration/invitation.js';
import { RecipientButton, RecipientError, RecipientNotice, useRecipientFeedback } from '../components/registration/RecipientUi.jsx';

const TERMINAL_MAIL = ['sent', 'failed', 'unknown'];
const codeReason = (status, value) => ({
  expired: 'This invitation has expired. Ask for a new invitation.',
  used: 'This invitation has already been used.',
  revoked: 'This invitation has been revoked. Ask for a new invitation.',
  unavailable: 'This invitation is no longer available. Ask for a new invitation.',
  invalid: 'This invitation code was not found. Check it and try again.',
})[status] || (value ? 'This invitation code is invalid. Check it and try again.' : 'An invitation code is required.');
const privateSafeInvitation = (data) => data.invitation ? { status: data.invitation.status, expires_at: data.invitation.expires_at } : data.expires_at ? { status: 'unused', expires_at: data.expires_at } : null;

export default function RegisterStartPage() {
  const { registrationEnabled, invitationRequired, turnstileSiteKey, ssoUrl, refreshSite } = useSite();
  const [params] = useSearchParams();
  const suppliedCode = invitationRequired ? normalizeCode(params.get('code') || '') : '';
  const loginTxn = params.get('txn') || '';
  const signInHref = loginTxn && ssoUrl ? `${ssoUrl}/login?txn=${encodeURIComponent(loginTxn)}` : '/';
  const [code, setCode] = useState(suppliedCode), [email, setEmail] = useState('');
  const [invitation, setInvitation] = useState(null), [phase, setPhase] = useState('form');
  const [notice, setNotice] = useState(null), [emailErr, setEmailErr] = useState(null), [codeErr, setCodeErr] = useState(null), [formErr, setFormErr] = useState(null);
  const [attemptedEmail, setAttemptedEmail] = useState(''), [uncertain, setUncertain] = useState(false);
  const [mailState, setMailState] = useState('none'), [cooldownUntil, setCooldownUntil] = useState(0), [now, setNow] = useState(Date.now());
  const [sendBlocked, setSendBlocked] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState(null);
  const ceremonySeq = useRef(0), requestRef = useRef(null), confirmedRequest = useRef(false), mounted = useRef(true);
  const [challengeVersion, setChallengeVersion] = useState(0);
  const feedback = useRecipientFeedback();

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; ceremonySeq.current++; }; }, []);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  useEffect(() => {
    ceremonySeq.current++; feedback.reset(); setCode(suppliedCode); setEmail(''); setInvitation(null); setNotice(null);
    setAttemptedEmail(''); setUncertain(false); setFormErr(null); setEmailErr(null); setCodeErr(null); setMailState('none');
    setSendBlocked(false); setCooldownUntil(0); setTurnstileToken(null); setPhase('form');
    requestRef.current = null; confirmedRequest.current = false;
  }, [suppliedCode, invitationRequired]); // eslint-disable-line react-hooks/exhaustive-deps

  const state = invitationStatus(invitation, now);
  const effectiveNotice = registrationEnabled === false ? 'closed' : notice || (state && state !== 'unused' ? state : null);
  const cooldown = Math.max(0, Math.ceil((cooldownUntil - now) / 1000));
  const locked = uncertain || feedback.busy;
  const codeReady = !invitationRequired || (INVITATION_CODE_RE.test(code) && !codeErr);
  const address = (phase === 'sent' ? attemptedEmail : email).trim().toLowerCase();
  const eligible = !effectiveNotice && !feedback.held && !sendBlocked && cooldown === 0 && codeReady && emailValid(address) && !emailErr;
  // Field validity gates the button, not human verification. Keep the widget
  // mounted while a submitted request is waiting for its response.
  const showHuman = !effectiveNotice && !sendBlocked && cooldown === 0;
  const humanReady = !turnstileSiteKey || !!turnstileToken;
  useEffect(() => { if (!showHuman) setTurnstileToken(null); }, [showHuman]);

  async function submit(event) {
    event?.preventDefault();
    if (!eligible || !humanReady) return;
    const submittedCode = invitationRequired ? code : undefined;
    const sequence = ceremonySeq.current;
    if (!feedback.start()) return;
    const proof = turnstileToken; setTurnstileToken(null);
    setFormErr(null); setEmailErr(null); setCodeErr(null); setAttemptedEmail(address);
    const key = (submittedCode || '') + ':' + address;
    if (submittedCode && (!requestRef.current || requestRef.current.key !== key || (confirmedRequest.current && TERMINAL_MAIL.includes(mailState)))) {
      requestRef.current = { key, code: submittedCode, email: address, id: registrationRequestId(submittedCode, address, confirmedRequest.current) };
    }
    const wasUncertain = uncertain;
    confirmedRequest.current = false; setUncertain(true);
    try {
      const data = await registerStart(address, submittedCode, proof, submittedCode ? requestRef.current?.id : undefined);
      if (!mounted.current || sequence !== ceremonySeq.current) return;
      if (data?.request_id && data.request_id !== requestRef.current?.id) throw new Error('invalid_response');
      const nextMail = data.mail?.state || data.invitation?.mail?.state || (data.sent === true ? 'sent' : data.result === 'pending' ? 'pending' : data.queued === true ? 'queued' : null);
      if (!['pending', 'queued', 'sending', ...TERMINAL_MAIL].includes(nextMail)) throw new Error('invalid_response');
      const pending = ['pending', 'queued', 'sending'].includes(nextMail);
      confirmedRequest.current = !pending; setUncertain(pending);
      setInvitation(privateSafeInvitation(data)); setMailState(nextMail);
      setCooldownUntil(Date.now() + (pending ? 5 : Math.max(0, Number(data.resend_backoff ?? data.retry_after) || 60)) * 1000);
      feedback.reset(); setPhase('sent');
    } catch (err) {
      if (!mounted.current || sequence !== ceremonySeq.current) return;
      const fields = err.data?.errors || {};
      const definite = err.status >= 400 && err.status < 500;
      const ended = definite ? invitationErrorStatus(err) : null;
      const mismatch = ['email_bound', 'email_mismatch'].includes(err.code) || ['email_bound', 'email_mismatch'].includes(fields.email);
      const fieldRejection = mismatch || fields.email || fields.code || ['email_taken', 'invalid_email'].includes(err.code) || (definite && ended);
      const inlineCode = invitationRequired && definite && (fields.code || ended);
      if (phase === 'sent' && fieldRejection) { setPhase('form'); setMailState('none'); setInvitation(null); setNotice(null); }
      // A rejection never replaces the entered email with upstream metadata.
      if (err.code === 'already_authenticated') setFormErr('You’re already signed in. Sign out before creating another account.');
      else if (['invalid_request_id', 'request_conflict'].includes(err.code)) setFormErr('This request can’t be retried. Start registration in a new tab.');
      else if (mismatch) setEmailErr('This email address can’t be used with this invitation.');
      else if (inlineCode) setCodeErr(codeReason(ended, code));
      else if (fields.email === 'email_taken' || err.code === 'email_taken') setEmailErr('This email address is already registered.');
      else if (fields.email || err.code === 'invalid_email') setEmailErr('Enter a valid email address.');
      else if (fields.code || ended === 'invalid') setCodeErr(codeReason(ended, code));
      else if (['timeout', 'network', 'upstream_timeout', 'upstream_unreachable'].includes(err.code)) setFormErr('We couldn’t confirm your request. Try again with the same details.');
      else if (err.data?.mail?.error_code === 'bounced') setFormErr('The email service could not send to this address. Contact the person who invited you.');
      else if (err.data?.mail?.error_code === 'rejected') setFormErr('The email service rejected this message. Please try again later.');
      else setFormErr(registrationMessage(err));
      if (ended && !inlineCode && ended !== 'invalid') setNotice(ended);
      if (!invitationRequired && (fields.code || ended === 'invalid')) refreshSite();
      if (err.code === 'registration_closed') { setNotice('closed'); refreshSite(); }
      if (err.code === 'turnstile_failed' && !turnstileSiteKey) refreshSite();
      // Both resend backoff and exhausted daily quota arrive as 429 with the
      // authoritative retry_after; neither depends on current field validity.
      if (err.status === 429) setCooldownUntil(Date.now() + Math.max(1, Number(err.data?.retry_after) || 60) * 1000);
      const ownReceipt = !!requestRef.current && err.data?.request_id === requestRef.current.id;
      const settledMail = !fieldRejection && ownReceipt && TERMINAL_MAIL.includes(err.data?.mail?.state) ? err.data.mail.state : null;
      if (settledMail) {
        if (settledMail === 'failed') retireRegistrationRequest(submittedCode, address, requestRef.current.id);
        confirmedRequest.current = true; setUncertain(false); setMailState(settledMail); setPhase('sent');
        setInvitation(privateSafeInvitation(err.data));
        setCooldownUntil(Date.now() + Math.max(0, Number(err.data.resend_backoff ?? err.data.retry_after) || 60) * 1000);
      } else if (mismatch || inlineCode || fields.email || fields.code || ['email_taken', 'invalid_email', 'registration_closed'].includes(err.code)) {
        setUncertain(false);
      } else if (err.status === 429 || err.code === 'turnstile_failed') setUncertain(wasUncertain);
      else if (!submittedCode && ['send_failed', 'email_not_configured'].includes(err.code)) setUncertain(false);
      // No detail/status lookup. Ambiguous retries keep this request's UUID;
      // the send endpoint itself replays its recorded outcome without resending.
      if (err.code === 'email_not_configured') { setSendBlocked(true); setUncertain(false); }
      if (['already_authenticated', 'invalid_request_id', 'request_conflict'].includes(err.code)) { setSendBlocked(true); setUncertain(wasUncertain); }
      if (mounted.current && sequence === ceremonySeq.current) { setChallengeVersion(value => value + 1); feedback.reset(); }
    }
  }

  const human = <Turnstile key={suppliedCode + ':' + invitationRequired} active={showHuman} manualRefresh paused={feedback.busy}
    resetKey={challengeVersion} onToken={setTurnstileToken} onExpire={() => setTurnstileToken(null)} onError={() => setTurnstileToken(null)} />;
  if (effectiveNotice) return <AuthCard motionKey={effectiveNotice} docTitle="Create account"><RecipientNotice status={effectiveNotice} expiresAt={invitation?.expires_at} signInHref={signInHref} /></AuthCard>;
  if (phase === 'sent') {
    const pending = ['pending', 'queued', 'sending'].includes(mailState), failed = mailState === 'failed', unknown = mailState === 'unknown';
    const title = pending ? 'Still confirming your request' : failed ? 'Email not sent' : unknown ? 'Check your inbox' : 'Check your email';
    const message = pending ? 'We haven’t confirmed the email to' : failed ? 'We couldn’t send a registration link to' : unknown ? 'Your registration email may have been sent to' : 'We sent a registration link to';
    return <AuthCard motionKey="sent" docTitle="Create account">
      <div className="auth-done recipient-notice info"><Icon name="mail" size={26} /></div>
      <h1 className="auth-h1">{title}</h1><p className="auth-msg">{message}<br/><strong>{attemptedEmail}</strong>.</p>
      <p className="recipient-queued">{pending ? 'Retry to confirm this request without sending a duplicate.' : unknown ? 'Check your inbox before sending another.' : failed ? 'You can try again shortly.' : 'Open the link to finish creating your account.'}</p>
      {human}
      <RecipientButton type="button" onClick={submit} feedback={feedback}
        rest={cooldown > 0 ? `${pending || uncertain ? 'Retry' : 'Resend'} in ${cooldown}s` : pending || uncertain ? 'Retry request' : unknown ? 'Send another email' : 'Resend email'} disabled={!eligible || !humanReady} />
      <RecipientError error={formErr || emailErr || codeErr} />
      {!invitationRequired && <a className="recipient-signin" href="/register/start">Use a different address</a>}
    </AuthCard>;
  }
  return <AuthCard motionKey="form" docTitle="Create account" title="Create your account"
    sub={invitationRequired ? 'Enter your email and invitation code.' : 'Enter your email to get started.'}
    cta={<>Already have an account? <a href={signInHref}>Sign in</a></>}>
    <form className="recipient-form" noValidate onSubmit={submit}>
      <div className={'auth-grp' + (emailErr ? ' bad' : '')}>
        <label htmlFor="reg-email">Email address</label><input id="reg-email" type="email" inputMode="email" className="auth-input" autoFocus autoComplete="email" autoCapitalize="none" autoCorrect="off" spellCheck="false" maxLength={254}
          aria-invalid={!!emailErr} aria-describedby={emailErr ? 'reg-email-error' : undefined} readOnly={locked} value={email}
          onChange={(event) => { if (!locked) { setEmail(event.target.value.replace(/\s/g, '')); setEmailErr(null); } }}
          onBlur={() => { if (email && !emailValid(email.trim())) setEmailErr(EMAIL_RE.test(email.trim()) ? 'Email addresses are at most 254 characters.' : 'Enter a valid email address.'); }} />
        <span id="reg-email-error" className="auth-ferr" role={emailErr ? 'alert' : undefined}>{emailErr}</span>
      </div>
      {invitationRequired && <div className={'auth-grp' + (codeErr ? ' bad' : '')}>
        <label htmlFor="reg-code">Invitation code</label><input id="reg-code" className="auth-input mono" value={code} autoComplete="off" autoCapitalize="characters" autoCorrect="off" spellCheck="false" maxLength={64}
          required aria-required="true" aria-invalid={!!codeErr} aria-describedby={codeErr ? 'reg-code-error' : undefined} readOnly={locked}
          onBlur={() => { if (!INVITATION_CODE_RE.test(code)) setCodeErr(code ? 'Use a 12-character invitation code containing only A–Z and 0–9.' : 'An invitation code is required.'); }}
          onChange={(event) => { if (locked) return; ceremonySeq.current++; setCode(normalizeCode(event.target.value)); setCodeErr(null); setEmailErr(null); setInvitation(null); setNotice(null); setMailState('none'); requestRef.current = null; confirmedRequest.current = false; }} />
        <span id="reg-code-error" className="auth-ferr" role={codeErr ? 'alert' : undefined}>{codeErr}</span>
      </div>}
      {human}
      <RecipientButton type="submit" feedback={feedback} rest={cooldown > 0 ? `Try again in ${cooldown}s` : uncertain ? 'Retry request' : 'Send registration email'} disabled={!eligible || !humanReady} />
      <RecipientError error={formErr || (!invitationRequired ? codeErr : null)} />
    </form>
  </AuthCard>;
}
