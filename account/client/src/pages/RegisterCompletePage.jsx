import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import PasswordRules, { passwordValid } from '../components/PasswordRules.jsx';
import { registerValidate, registerCheckUsername, registerComplete } from '../api.js';
import { invitationStatus, invitationErrorStatus, registrationMessage } from '../components/registration/invitation.js';
import { InvitationMeta, LockedEmail, RecipientButton, RecipientError, RecipientNotice, useRecipientFeedback } from '../components/registration/RecipientUi.jsx';

// Registration step 2 (from the emailed link): username + display name +
// password. Same blur-validation contract as /reset, plus an on-blur username
// AVAILABILITY check (token-gated upstream — not a public oracle). Success
// navigates through the SSO's /welcome ticket hop: session -> KMSI -> portal.
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

export default function RegisterCompletePage() {
  const { turnstileSiteKey, refreshSite } = useSite();
  const [params] = useSearchParams();
  const queryEmail = (params.get('email') || '').trim();
  const [registration, setRegistration] = useState(null);
  const [accountCreated, setAccountCreated] = useState(false);
  const [handoff, setHandoff] = useState(null);
  const navigatedHandoff = useRef(null);
  const [notice, setNotice] = useState(null);
  const [now, setNow] = useState(Date.now());
  const email = registration?.bound_email || registration?.email || queryEmail;
  const feedback = useRecipientFeedback();
  const mounted = useRef(true);
  const token = params.get('token') || '';
  const proofContext = queryEmail + '\0' + token;
  const proofContextRef = useRef(proofContext);
  proofContextRef.current = proofContext;

  const [phase, setPhase] = useState('loading'); // loading | invalid | closed | form | redirect
  const [username, setUsername] = useState('');
  const [displayName, setDisplayName] = useState('');
  const [pw, setPw] = useState('');
  const [confirm, setConfirm] = useState('');
  const [userErr, setUserErr] = useState(null); // string | null
  const [nameErr, setNameErr] = useState(null);
  const [pwBad, setPwBad] = useState(false);
  const [cfErr, setCfErr] = useState(null);
  const [formErr, setFormErr] = useState(null);
  const busy = feedback.held;
  const [turnstileToken, setTurnstileToken] = useState(null);
  const resetRef = useRef(null);
  const checkSeq = useRef(0); // stale availability responses must not land

  useEffect(() => { mounted.current = true; return () => { mounted.current = false; }; }, []);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 1000); return () => clearInterval(timer); }, []);
  const [validationAttempt, setValidationAttempt] = useState(0);
  useEffect(() => {
    let alive = true;
    checkSeq.current++; feedback.reset();
    setPhase('loading'); setNotice(null); setRegistration(null); setAccountCreated(false); setHandoff(null);
    setUsername(''); setDisplayName(''); setPw(''); setConfirm('');
    setUserErr(null); setNameErr(null); setPwBad(false); setCfErr(null); setFormErr(null);
    if (!queryEmail || !token) { setNotice('link'); setPhase('invalid'); return undefined; }
    (async () => {
      try {
        const data = await registerValidate(queryEmail, token);
        if (!alive) return;
        if (!data?.email || (data.bound_email && data.email.toLowerCase() !== data.bound_email.toLowerCase())) throw new Error('invalid_response');
        setRegistration(data);
        const status = invitationStatus(data.invitation);
        if (status && status !== 'unused') { setNotice(status); setPhase('invalid'); }
        else setPhase('form');
      } catch (err) {
        if (!alive) return;
        setRegistration(err.data || null);
        setNotice(err.code === 'registration_closed' ? 'closed' : invitationErrorStatus(err) || (err.code === 'invalid_token' ? 'link' : 'unreachable'));
        setPhase('invalid');
      }
    })();
    return () => { alive = false; checkSeq.current++; };
  }, [queryEmail, token, validationAttempt]);

  // Commit the successful screen before navigating. The one-use welcome URL
  // is followed once, without keeping a success button visible for two seconds.
  useEffect(() => {
    if (phase !== 'redirect' || !handoff || handoff.context !== proofContext || navigatedHandoff.current === handoff) return;
    navigatedHandoff.current = handoff;
    window.location.replace(handoff.url);
  }, [phase, handoff, proofContext]);

  const nameOk = displayName.trim().length > 0 && displayName.trim().length <= 100;
  const pwOk = passwordValid(pw) && !/\s/.test(pw);
  const canSubmit =
    phase === 'form' && !accountCreated && !busy && USERNAME_RE.test(username) && !userErr && nameOk && pwOk &&
    confirm.length > 0 && confirm === pw && (!turnstileSiteKey || turnstileToken);

  const checkAvailability = async () => {
    if (!USERNAME_RE.test(username)) return;
    const seq = ++checkSeq.current;
    try {
      const d = await registerCheckUsername(email, token, username);
      if (seq === checkSeq.current && d && d.available === false) {
        setUserErr('This username is already taken.');
      }
    } catch { /* availability is best-effort — submit re-checks server-side */ }
  };

  const submit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    const operationContext = proofContext;
    if (!feedback.start()) return;
    setFormErr(null);
    try {
      const d = await registerComplete({
        email, token,
        username, display_name: displayName.trim(),
        password: pw, confirm_password: confirm,
        turnstile_token: turnstileToken ?? undefined,
      });
      if (!mounted.current || operationContext !== proofContextRef.current) return;
      if (typeof d?.complete_url !== 'string' || !d.complete_url) throw new Error('missing_complete_url');
      setAccountCreated(true);
      setHandoff({ context: operationContext, url: d.complete_url });
      setPhase('redirect');
    } catch (err) {
      if (!mounted.current || operationContext !== proofContextRef.current) return;
      feedback.finish('fail');
      const errs = err.data?.errors || {};
      if (err.data?.invitation) setRegistration((old) => ({ ...old, invitation: err.data.invitation }));
      const ended = invitationErrorStatus(err);
      if (ended) { setNotice(ended); setPhase('invalid'); }
      // Turnstile is verified first, so any non-2xx means the single-use token is
      // spent — reset the widget so a retry re-solves for a fresh one.
      setTurnstileToken(null);
      resetRef.current?.();
      if (err.status === 403 && err.code === 'turnstile_failed') {
        setFormErr({ msg: 'Human verification failed — try again.', code: err.code });
        if (!turnstileSiteKey) refreshSite();
      } else if (err.status === 403 && err.code === 'registration_closed') {
        setNotice('closed'); setPhase('invalid');
      } else if (err.code === 'invalid_token') {
        setNotice('link'); setPhase('invalid');
      } else if (err.code === 'invitation_gone') {
        setFormErr({ msg: 'Your invitation was withdrawn — contact the person who invited you.', code: err.code });
      } else if (Object.keys(errs).length) {
        setFormErr({ msg: 'Check the highlighted fields and try again.' });
        if (errs.username) setUserErr(errs.username === 'username_taken' ? 'This username is already taken.' : 'Usernames are 3–20 characters: letters, digits, - and _.');
        if (errs.display_name) setNameErr('Display names are 1–100 characters.');
        if (errs.password) setPwBad(true);
        if (errs.email) setFormErr({ msg: 'This email address is already registered.', code: 'email_taken' });
        if (errs.confirm) setCfErr('Passwords do not match.');
      } else if (err.code === 'timeout') {
        setFormErr({ msg: 'That took too long — try again.', code: 'timeout' });
      } else {
        setFormErr({ msg: registrationMessage(err), code: err.code || 'http_' + (err.status ?? 'network') });
      }
    }
  };

  if (phase === 'loading') {
    return (
      <AuthCard motionKey={notice || phase} docTitle="Create account">
        <div className="auth-spinner" aria-hidden="true" />
        <p className="auth-wait">Checking your registration link…</p>
      </AuthCard>
    );
  }

  const currentStatus = invitationStatus(registration?.invitation, now);
  const ended = !accountCreated && currentStatus && currentStatus !== 'unused' ? currentStatus : null;
  if (phase === 'invalid' || ended) return <AuthCard motionKey={ended || notice || phase} docTitle="Create account">
    <RecipientNotice status={ended || notice || 'link'} invitation={registration?.invitation}
      onRetry={(ended || notice) === 'unreachable' ? () => setValidationAttempt((value) => value + 1) : undefined} />
  </AuthCard>;

  if (phase === 'redirect') {
    return (
      <AuthCard motionKey={notice || phase} docTitle="Create account">
        <div className="auth-done"><Icon name="check" size={26} /></div>
        <h1 className="auth-h1">Account created</h1>
        <p className="auth-msg">Signing you in…</p>
        <div className="auth-spinner" aria-hidden="true" />
      </AuthCard>
    );
  }

  return (
    <AuthCard motionKey={notice || phase}
      docTitle="Create account"
      title="Choose your details"
      sub={registration?.invitation ? `${registration.invitation.role?.name ? `You are invited as a ${registration.invitation.role.name}.` : 'You are invited.'} Choose how you will sign in.` : 'Almost done — choose a username and password'}
    >
      <form className="recipient-form" onSubmit={submit} noValidate>
        <LockedEmail email={email} hint={registration?.invitation ? 'This invitation is for this address and cannot be changed.' : 'This address was verified by your registration link.'} />
        <div className={'auth-grp' + (userErr ? ' bad' : '')}>
          <label htmlFor="reg-username">Username</label>
          <input
            id="reg-username" className="auth-input" autoFocus
            autoCapitalize="none" autoCorrect="off" spellCheck="false" autoComplete="username"
            value={username} readOnly={busy} maxLength={20}
            onChange={(e) => { checkSeq.current++; setUsername(e.target.value.replace(/\s/g, '')); setUserErr(null); }}
            onBlur={() => {
              if (!username) return;
              if (!USERNAME_RE.test(username)) setUserErr('Usernames are 3–20 characters: letters, digits, - and _.');
              else checkAvailability();
            }}
          />
          <span className="auth-ferr">{userErr || 'Usernames are 3–20 characters: letters, digits, - and _.'}</span>
        </div>
        <div className={'auth-grp' + (nameErr ? ' bad' : '')}>
          <label htmlFor="reg-name">Display Name</label>
          <input
            id="reg-name" className="auth-input"
            autoCorrect="off" autoComplete="name" maxLength={100}
            value={displayName} readOnly={busy}
            onChange={(e) => { setDisplayName(e.target.value); setNameErr(null); }}
            onBlur={() => { const v = displayName.trim(); if (displayName && !v) setNameErr('Display names are 1–100 characters.'); }}
          />
          <span className="auth-ferr">{nameErr || 'Display names are 1–100 characters.'}</span>
        </div>
        <div className={'auth-grp' + (pwBad ? ' bad' : '')}>
          <label htmlFor="reg-pw">Password</label>
          <input
            id="reg-pw" className="auth-input" type="password" autoComplete="new-password"
            value={pw} readOnly={busy}
            onChange={(e) => { setPw(e.target.value.replace(/\s/g, '')); setPwBad(false); }}
            onBlur={() => { if (pw && !pwOk) setPwBad(true); }}
          />
          <PasswordRules password={pw} />
        </div>
        <div className={'auth-grp' + (cfErr ? ' bad' : '')}>
          <label htmlFor="reg-cf">Confirm Password</label>
          <input
            id="reg-cf" className="auth-input" type="password" autoComplete="new-password"
            value={confirm} readOnly={busy}
            onChange={(e) => { setConfirm(e.target.value.replace(/\s/g, '')); setCfErr(null); }}
            onBlur={() => { if (confirm && confirm !== pw) setCfErr('Passwords do not match.'); }}
          />
          <span className="auth-ferr">{cfErr || 'Passwords do not match.'}</span>
        </div>
        <Turnstile
          onToken={setTurnstileToken}
          onExpire={() => setTurnstileToken(null)}
          onError={() => setTurnstileToken(null)}
          resetRef={resetRef}
        />
        <RecipientButton type="submit" feedback={feedback} rest="Create account" busy="Creating account…" done="Account created" disabled={!canSubmit} />
        <RecipientError error={formErr} />
      </form>
      <InvitationMeta invitation={registration?.invitation} expiresAt={registration?.expires_at} />
    </AuthCard>
  );
}
