import { useRef, useState } from 'react';
import { useSite } from '../context/SiteContext.jsx';
import AuthCard from '../components/AuthCard.jsx';
import Turnstile from '../components/Turnstile.jsx';
import Icon from '../components/Icon.jsx';
import { resetRequest } from '../api.js';

// Identifier rule (shared with the BFF and the SSO): a bare username is
// videosite's 3–20 of [A-Za-z0-9_-]; anything containing @ is an email
// (dots fine, RFC 5321 length cap).
function identifierOk(id) {
  if (id.includes('@')) return id.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(id);
  return /^[A-Za-z0-9_-]{3,20}$/.test(id);
}

export default function ForgotPage() {
  const { turnstileSiteKey, refreshSite } = useSite();
  const [identifier, setIdentifier] = useState('');
  // Blur-validation contract: the error (red border + line) appears when an
  // INVALID value loses focus, and clears the moment the user comes back and
  // changes anything. The button is greyed on invalid input regardless.
  const [showErr, setShowErr] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [formErr, setFormErr] = useState(null); // { msg, code } banner
  const [phase, setPhase] = useState('form'); // 'form' | 'sent'
  const [sentId, setSentId] = useState('');
  const [turnstileToken, setTurnstileToken] = useState(null);
  const resetRef = useRef(null);

  const valid = identifierOk(identifier.trim());
  const canSubmit = valid && !submitting && (!turnstileSiteKey || turnstileToken);

  const submit = async (e) => {
    e.preventDefault();
    if (!canSubmit) return;
    setSubmitting(true);
    setFormErr(null);
    const id = identifier.trim();
    try {
      await resetRequest(id, turnstileToken);
      setSentId(id.includes('@') ? id.toLowerCase() : id);
      setPhase('sent');
    } catch (err) {
      // Turnstile is verified first (edge worker or origin), so ANY non-2xx here
      // means the single-use token was already spent. Always reset the widget so
      // a retry carries a fresh token — the button stays greyed until it re-solves.
      setTurnstileToken(null);
      resetRef.current?.();
      if (err.status === 403 && err.code === 'turnstile_failed') {
        setFormErr({ msg: 'Human verification failed — try again.', code: err.code });
        // The server enforces Turnstile but we cached it as off — re-fetch so
        // the widget mounts on the next render (videosite's stale-key path).
        if (!turnstileSiteKey) refreshSite();
      } else if (err.status === 422) {
        setShowErr(true);
      } else if (err.status === 400 && err.code === 'already_authenticated') {
        setFormErr({ msg: "You're already signed in — change your password from Security instead.", code: err.code });
      } else if (err.status === 503 && err.code === 'email_not_configured') {
        setFormErr({ msg: 'Email sending isn’t set up yet — contact your administrator.', code: err.code });
      } else if (err.code === 'timeout') {
        setFormErr({ msg: 'That took too long — try again.', code: 'timeout' });
      } else {
        setFormErr({ msg: 'Something went wrong — try again.', code: err.code || 'http_' + (err.status ?? 'network') });
      }
    } finally {
      setSubmitting(false);
    }
  };

  if (phase === 'sent') {
    return (
      <AuthCard docTitle="Reset password">
        <div className="auth-done">
          <Icon name="mail" size={26} />
        </div>
        <h1 className="auth-h1">Check your email</h1>
        <p className="auth-msg">
          If <strong>{sentId}</strong> matches an account, we&rsquo;ve sent a reset link to its
          email address. The link works once and expires in 30 minutes.
        </p>
        <p className="auth-msg" style={{ fontSize: 13, color: 'var(--faint)' }}>
          Didn&rsquo;t get it? Check your spam folder, or try again later.
        </p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box' }} href="/">
          Return to sign in
        </a>
      </AuthCard>
    );
  }

  return (
    <AuthCard
      docTitle="Reset password"
      title="Reset your password"
      sub="Enter your username or email address and we'll send you a reset link"
    >
      {formErr && <div className="auth-err">{formErr.msg} [{formErr.code}]</div>}
      <form onSubmit={submit} noValidate>
        <div className={'auth-grp' + (showErr ? ' bad' : '')}>
          <label htmlFor="identifier">Username or Email Address</label>
          <input
            id="identifier"
            className="auth-input"
            autoFocus
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck="false"
            autoComplete="username"
            value={identifier}
            onChange={(e) => {
              setIdentifier(e.target.value.replace(/\s/g, ''));
              setShowErr(false);
            }}
            onBlur={() => {
              const v = identifier.trim();
              if (v && !identifierOk(v)) setShowErr(true);
            }}
          />
          <span className="auth-ferr">
            {identifier.includes('@')
              ? 'Enter a valid email address.'
              : 'Usernames are 3–20 characters: letters, digits, - and _.'}
          </span>
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
