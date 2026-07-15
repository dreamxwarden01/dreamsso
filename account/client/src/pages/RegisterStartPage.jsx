import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import { registerStart } from '../api.js';

// Registration step 1: email + invitation code (+ Turnstile). Same blur-
// validation contract as /forgot. Unlike the reset flow this page is STATEFUL
// — a code-holder is semi-trusted, so "email taken", "code invalid", rate
// limits, and delivery failures all surface honestly, and the sent state
// carries a Resend button on the server-provided backoff countdown.
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CODE_RE = /^[A-Z0-9]{12}$/;
const emailOk = (v) => EMAIL_RE.test(v) && v.length <= 254;

export default function RegisterStartPage() {
  const { registrationEnabled, invitationRequired, turnstileSiteKey, ssoUrl, refreshSite } = useSite();
  const [params] = useSearchParams();
  // The SSO's "Sign up" strip carries its login txn — "Sign in" leads BACK to
  // that exact transaction (unintentional clicks). Direct invite-link visits
  // have no txn: fall back to the portal sign-in.
  const loginTxn = params.get('txn') || '';
  const signInHref = loginTxn && ssoUrl ? `${ssoUrl}/login?txn=${encodeURIComponent(loginTxn)}` : '/';
  const signInCta = (
    <>Already have an account? <a href={signInHref}>Sign in</a></>
  );
  const [email, setEmail] = useState('');
  const [code, setCode] = useState((params.get('code') || '').toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12));
  const [emailErr, setEmailErr] = useState(null); // string message | null
  const [codeErr, setCodeErr] = useState(null);
  const [formErr, setFormErr] = useState(null); // { msg, code } banner
  const [submitting, setSubmitting] = useState(false);
  const [phase, setPhase] = useState('form'); // 'form' | 'sent'
  const [sentTo, setSentTo] = useState('');
  const [cooldown, setCooldown] = useState(0); // resend backoff countdown (s)
  const [turnstileToken, setTurnstileToken] = useState(null);
  const resetRef = useRef(null);

  useEffect(() => {
    if (cooldown <= 0) return undefined;
    const t = setTimeout(() => setCooldown((c) => c - 1), 1000);
    return () => clearTimeout(t);
  }, [cooldown]);

  const codeNeeded = invitationRequired || code.length > 0;
  const valid = emailOk(email.trim()) && (!codeNeeded || CODE_RE.test(code));
  const canSubmit = valid && !submitting && (!turnstileSiteKey || turnstileToken) && registrationEnabled !== false;

  const submit = async (e) => {
    e?.preventDefault();
    if (phase === 'form' && !canSubmit) return;
    setSubmitting(true);
    setFormErr(null);
    try {
      const d = await registerStart(email.trim(), codeNeeded ? code : undefined, turnstileToken);
      setSentTo(email.trim().toLowerCase());
      setCooldown(d?.resend_backoff ?? 60);
      setPhase('sent');
      setTurnstileToken(null);
      resetRef.current?.();
    } catch (err) {
      const fieldErrs = err.data?.errors || {};
      if (err.status === 403 && err.code === 'turnstile_failed') {
        setFormErr({ msg: 'Human verification failed — try again.', code: err.code });
        setTurnstileToken(null);
        resetRef.current?.();
        if (!turnstileSiteKey) refreshSite();
      } else if (err.status === 403 && err.code === 'registration_closed') {
        setFormErr({ msg: 'Registration is currently closed.', code: err.code });
        refreshSite();
      } else if (fieldErrs.code) {
        setCodeErr('This invitation code is invalid, expired, or no longer usable.');
      } else if (fieldErrs.email === 'email_taken') {
        setEmailErr('This email address is already registered.');
      } else if (fieldErrs.email) {
        setEmailErr('Enter a valid email address.');
      } else if (err.status === 429) {
        const mins = Math.ceil((err.data?.retry_after ?? 60) / 60);
        setFormErr({
          msg: err.data?.can_retry
            ? `Too soon — you can resend in ${err.data.retry_after}s.`
            : `Too many emails for this address — try again in about ${mins} minute${mins === 1 ? '' : 's'}.`,
          code: 'rate_limited',
        });
        if (err.data?.can_retry) setCooldown(err.data.retry_after);
      } else if (err.status === 400 && err.code === 'already_authenticated') {
        setFormErr({ msg: "You're already signed in.", code: err.code });
      } else if (err.status === 503) {
        setFormErr({
          msg: err.code === 'email_not_configured'
            ? 'Email sending isn’t set up yet — contact your administrator.'
            : 'We couldn’t send the email — try again.',
          code: err.code,
        });
      } else {
        setFormErr({ msg: 'Something went wrong — try again.', code: err.code || 'http_' + (err.status ?? 'network') });
        setTurnstileToken(null);
        resetRef.current?.();
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (registrationEnabled === false) {
    return (
      <AuthCard docTitle="Create account">
        <div className="auth-done"><Icon name="lock" size={26} /></div>
        <h1 className="auth-h1">Registration is closed</h1>
        <p className="auth-msg">New accounts can&rsquo;t be created right now. If you were invited, contact the person who invited you.</p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box' }} href="/">
          Return to sign in
        </a>
      </AuthCard>
    );
  }

  if (phase === 'sent') {
    return (
      <AuthCard docTitle="Create account">
        <div className="auth-done"><Icon name="mail" size={26} /></div>
        <h1 className="auth-h1">Check your email</h1>
        <p className="auth-msg">
          We&rsquo;ve sent a link to <strong>{sentTo}</strong>. Open it to choose your username
          and password. The link expires in 30 minutes.
        </p>
        {formErr && <div className="auth-err">{formErr.msg} [{formErr.code}]</div>}
        <Turnstile
          onToken={setTurnstileToken}
          onExpire={() => setTurnstileToken(null)}
          onError={() => setTurnstileToken(null)}
          resetRef={resetRef}
        />
        <button
          type="button" className="auth-btn"
          disabled={cooldown > 0 || submitting || (!!turnstileSiteKey && !turnstileToken)}
          onClick={submit}
        >
          {submitting ? 'Sending…' : cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend the link'}
        </button>
        <p className="auth-msg" style={{ fontSize: 13, color: 'var(--faint)', marginTop: 12 }}>
          Wrong address? <a href="#form" onClick={(e) => { e.preventDefault(); setPhase('form'); setFormErr(null); }}>Start over</a>
        </p>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      docTitle="Create account"
      title="Create your account"
      sub="Enter your email address and invitation code to get started"
      cta={signInCta}
    >
      {formErr && <div className="auth-err">{formErr.msg} [{formErr.code}]</div>}
      <form onSubmit={submit} noValidate>
        <div className={'auth-grp' + (emailErr ? ' bad' : '')}>
          <label htmlFor="reg-email">Email Address</label>
          <input
            id="reg-email" className="auth-input" autoFocus
            autoCapitalize="none" autoCorrect="off" spellCheck="false" autoComplete="email"
            value={email}
            onChange={(e) => { setEmail(e.target.value.replace(/\s/g, '')); setEmailErr(null); }}
            onBlur={() => { const v = email.trim(); if (v && !emailOk(v)) setEmailErr('Enter a valid email address.'); }}
          />
          <span className="auth-ferr">{emailErr || 'Enter a valid email address.'}</span>
        </div>
        <div className={'auth-grp' + (codeErr ? ' bad' : '')}>
          <label htmlFor="reg-code">Invitation Code{invitationRequired ? '' : ' (optional)'}</label>
          <input
            id="reg-code" className="auth-input mono"
            autoCapitalize="characters" autoCorrect="off" spellCheck="false" autoComplete="off"
            placeholder="ABCD1234EFGH" maxLength={12}
            value={code}
            onChange={(e) => { setCode(e.target.value.toUpperCase().replace(/[^A-Z0-9]/g, '').slice(0, 12)); setCodeErr(null); }}
            onBlur={() => { if (code && !CODE_RE.test(code)) setCodeErr('Codes are 12 letters and digits.'); }}
          />
          <span className="auth-ferr">{codeErr || 'Codes are 12 letters and digits.'}</span>
        </div>
        <Turnstile
          onToken={setTurnstileToken}
          onExpire={() => setTurnstileToken(null)}
          onError={() => setTurnstileToken(null)}
          resetRef={resetRef}
        />
        <button type="submit" className="auth-btn" disabled={!canSubmit}>
          {submitting ? 'Sending…' : 'Continue'}
        </button>
      </form>
    </AuthCard>
  );
}
