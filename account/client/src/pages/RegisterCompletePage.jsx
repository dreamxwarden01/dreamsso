import { useEffect, useRef, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import PasswordRules, { passwordValid } from '../components/PasswordRules.jsx';
import { registerValidate, registerCheckUsername, registerComplete } from '../api.js';

// Registration step 2 (from the emailed link): username + display name +
// password. Same blur-validation contract as /reset, plus an on-blur username
// AVAILABILITY check (token-gated upstream — not a public oracle). Success
// navigates through the SSO's /welcome ticket hop: session -> KMSI -> portal.
const USERNAME_RE = /^[A-Za-z0-9_-]{3,20}$/;

export default function RegisterCompletePage() {
  const { turnstileSiteKey, refreshSite } = useSite();
  const [params] = useSearchParams();
  const email = (params.get('email') || '').trim();
  const token = params.get('token') || '';

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
  const [busy, setBusy] = useState(false);
  const [turnstileToken, setTurnstileToken] = useState(null);
  const resetRef = useRef(null);
  const checkSeq = useRef(0); // stale availability responses must not land

  useEffect(() => {
    let alive = true;
    (async () => {
      try {
        await registerValidate(email, token);
        if (alive) setPhase('form');
      } catch (err) {
        if (!alive) return;
        setPhase(err.status === 403 && err.code === 'registration_closed' ? 'closed' : 'invalid');
      }
    })();
    return () => { alive = false; };
  }, [email, token]);

  const nameOk = displayName.trim().length > 0 && displayName.trim().length <= 100;
  const pwOk = passwordValid(pw) && !/\s/.test(pw);
  const canSubmit =
    !busy && USERNAME_RE.test(username) && !userErr && nameOk && pwOk &&
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
    setBusy(true);
    setFormErr(null);
    try {
      const d = await registerComplete({
        email, token,
        username, display_name: displayName.trim(),
        password: pw, confirm_password: confirm,
        turnstile_token: turnstileToken ?? undefined,
      });
      setPhase('redirect');
      window.location.replace(d.complete_url);
    } catch (err) {
      const errs = err.data?.errors || {};
      if (err.status === 403 && err.code === 'turnstile_failed') {
        setFormErr({ msg: 'Human verification failed — try again.', code: err.code });
        setTurnstileToken(null);
        resetRef.current?.();
        if (!turnstileSiteKey) refreshSite();
      } else if (err.status === 403 && err.code === 'registration_closed') {
        setPhase('closed');
      } else if (err.code === 'invalid_token') {
        setPhase('invalid');
      } else if (err.code === 'invitation_gone') {
        setFormErr({ msg: 'Your invitation was withdrawn — contact the person who invited you.', code: err.code });
      } else if (Object.keys(errs).length) {
        if (errs.username) setUserErr(errs.username === 'username_taken' ? 'This username is already taken.' : 'Usernames are 3–20 characters: letters, digits, - and _.');
        if (errs.display_name) setNameErr('Display names are 1–100 characters.');
        if (errs.password) setPwBad(true);
        if (errs.email) setFormErr({ msg: 'This email address is already registered.', code: 'email_taken' });
        if (errs.confirm) setCfErr('Passwords do not match.');
      } else {
        setFormErr({ msg: 'Something went wrong — try again.', code: err.code || 'http_' + (err.status ?? 'network') });
        setTurnstileToken(null);
        resetRef.current?.();
      }
    } finally {
      setBusy(false);
    }
  };

  if (phase === 'loading') {
    return (
      <AuthCard docTitle="Create account">
        <div className="auth-spinner" aria-hidden="true" />
        <p className="auth-wait">Checking your registration link…</p>
      </AuthCard>
    );
  }

  if (phase === 'closed') {
    return (
      <AuthCard docTitle="Create account" title="Registration is closed">
        <p className="auth-msg">New accounts can&rsquo;t be created right now. If you were invited, contact the person who invited you.</p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }} href="/">
          Return to sign in
        </a>
      </AuthCard>
    );
  }

  if (phase === 'invalid') {
    return (
      <AuthCard docTitle="Create account" title="Link expired">
        <p className="auth-msg">This registration link is invalid, has expired, or was replaced by a newer one. Start over to get a fresh link.</p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }} href="/register/start">
          Start over
        </a>
      </AuthCard>
    );
  }

  if (phase === 'redirect') {
    return (
      <AuthCard docTitle="Create account">
        <div className="auth-done"><Icon name="check" size={26} /></div>
        <h1 className="auth-h1">Account created</h1>
        <p className="auth-msg">Signing you in…</p>
        <div className="auth-spinner" aria-hidden="true" />
      </AuthCard>
    );
  }

  return (
    <AuthCard
      docTitle="Create account"
      title="Choose your details"
      sub={`Almost done — pick a username and password for ${email}`}
    >
      {formErr && <div className="auth-err">{formErr.msg} [{formErr.code}]</div>}
      <form onSubmit={submit} noValidate>
        <div className={'auth-grp' + (userErr ? ' bad' : '')}>
          <label htmlFor="reg-username">Username</label>
          <input
            id="reg-username" className="auth-input" autoFocus
            autoCapitalize="none" autoCorrect="off" spellCheck="false" autoComplete="username"
            value={username}
            onChange={(e) => { setUsername(e.target.value.replace(/\s/g, '')); setUserErr(null); }}
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
            value={displayName}
            onChange={(e) => { setDisplayName(e.target.value); setNameErr(null); }}
            onBlur={() => { const v = displayName.trim(); if (displayName && !v) setNameErr('Display names are 1–100 characters.'); }}
          />
          <span className="auth-ferr">{nameErr || 'Display names are 1–100 characters.'}</span>
        </div>
        <div className={'auth-grp' + (pwBad ? ' bad' : '')}>
          <label htmlFor="reg-pw">Password</label>
          <input
            id="reg-pw" className="auth-input" type="password" autoComplete="new-password"
            value={pw}
            onChange={(e) => { setPw(e.target.value.replace(/\s/g, '')); setPwBad(false); }}
            onBlur={() => { if (pw && !pwOk) setPwBad(true); }}
          />
          <PasswordRules password={pw} />
        </div>
        <div className={'auth-grp' + (cfErr ? ' bad' : '')}>
          <label htmlFor="reg-cf">Confirm Password</label>
          <input
            id="reg-cf" className="auth-input" type="password" autoComplete="new-password"
            value={confirm}
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
        <button type="submit" className="auth-btn" disabled={!canSubmit}>
          {busy ? 'Creating…' : 'Create account'}
        </button>
      </form>
    </AuthCard>
  );
}
