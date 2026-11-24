import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import AuthCard from '../components/AuthCard.jsx';
import Icon from '../components/Icon.jsx';
import { verifyEmail } from '../api.js';

// The emailed verification link lands here (change + confirm-current). The
// single-use token authorizes — the clicker may be signed out. Verification
// commits server-side on load; this page only reports the outcome.
export default function VerifyEmailPage() {
  const [params] = useSearchParams();
  const token = params.get('token') || '';
  const [phase, setPhase] = useState('working'); // working | changed | confirmed | invalid | taken | unavailable
  const [retry, setRetry] = useState(0);
  useEffect(() => {
    let alive = true;
    setPhase('working');
    verifyEmail(token)
      .then((d) => { if (alive) setPhase(d?.kind === 'confirm' ? 'confirmed' : 'changed'); })
      .catch((e) => {
        if (!alive) return;
        const temporary = e.status >= 500 || e.status === 429 || e.status === 0 || ['network', 'timeout', 'network_error', 'request_timeout', 'upstream_timeout', 'upstream_unreachable'].includes(e.code);
        setPhase(e.code === 'email_taken' ? 'taken' : temporary ? 'unavailable' : 'invalid');
      });
    return () => { alive = false; };
  }, [token, retry]);

  if (phase === 'working') {
    return (
      <AuthCard docTitle="Verify email">
        <div className="auth-spinner" aria-hidden="true" />
        <p className="auth-wait">Verifying your email…</p>
      </AuthCard>
    );
  }
  if (phase === 'invalid') {
    return (
      <AuthCard docTitle="Verify email" title="Link expired">
        <p className="auth-msg">
          This verification link is invalid, has expired, or was already used.
          Start the change again from your profile to get a fresh one.
        </p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }} href="/">
          Open the account portal
        </a>
      </AuthCard>
    );
  }
  if (phase === 'unavailable') {
    return (
      <AuthCard docTitle="Verify email" title="Verification unavailable">
        <p className="auth-msg">We couldn’t confirm your email right now. Retry this same verification link.</p>
        <button className="auth-btn" type="button" onClick={() => setRetry(value => value + 1)}>Retry</button>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }} href="/">
          Open the account portal
        </a>
      </AuthCard>
    );
  }
  if (phase === 'taken') {
    return (
      <AuthCard docTitle="Verify email" title="Address already in use">
        <p className="auth-msg">
          Another account claimed this email address in the meantime — your current
          email is unchanged. Pick a different address and try again.
        </p>
        <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box', marginTop: 14 }} href="/">
          Open the account portal
        </a>
      </AuthCard>
    );
  }
  return (
    <AuthCard docTitle="Verify email">
      <div className="auth-done"><Icon name="check" size={26} /></div>
      <h1 className="auth-h1">{phase === 'changed' ? 'Email updated' : 'Email verified'}</h1>
      <p className="auth-msg">
        {phase === 'changed'
          ? 'Your account now uses the new address for sign-in codes and notifications.'
          : 'Your email address is verified.'}
      </p>
      <a className="auth-btn" style={{ display: 'block', textAlign: 'center', textDecoration: 'none', boxSizing: 'border-box' }} href="/">
        Open the account portal
      </a>
    </AuthCard>
  );
}
