import { useEffect, useRef, useState } from 'react';
import Icon from '../Icon.jsx';
import { formatInvitationTime } from './invitation.js';
import './recipient.css';

export function useRecipientFeedback() {
  const [phase, setPhase] = useState('idle');
  const timer = useRef(null);
  const phaseRef = useRef('idle');
  const mounted = useRef(true);
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; clearTimeout(timer.current); }; }, []);
  const reset = () => { clearTimeout(timer.current); phaseRef.current = 'idle'; setPhase('idle'); };
  const start = () => {
    if (phaseRef.current !== 'idle') return false;
    clearTimeout(timer.current); phaseRef.current = 'busy'; setPhase('busy'); return true;
  };
  const finish = (next, after) => {
    if (!mounted.current) return;
    clearTimeout(timer.current); phaseRef.current = next; setPhase(next);
    timer.current = setTimeout(() => {
      if (!mounted.current) return;
      phaseRef.current = 'idle'; setPhase('idle'); after?.();
    }, 2000);
  };
  return { phase, start, finish, reset, held: phase !== 'idle', busy: phase === 'busy' };
}

export function RecipientButton({ feedback, rest, busy = 'Sending…', done = 'Queued', fail = 'Try again', disabled, ...props }) {
  const labels = { idle: rest, busy, done, fail };
  return <button {...props} className="auth-btn recipient-button" data-phase={feedback.phase}
    disabled={disabled || feedback.held} aria-busy={feedback.busy} aria-label={labels[feedback.phase]}>
    <span className="recipient-button-label" aria-hidden="true">
      {Object.entries(labels).map(([phase, label]) => <span key={phase} className={phase === feedback.phase ? 'on' : ''}>{label}</span>)}
    </span>
    <span className="recipient-button-icon" aria-hidden="true">
      {feedback.phase === 'busy' ? <span className="recipient-spin" />
        : feedback.phase === 'done' ? <Icon name="check" size={17} />
          : feedback.phase === 'fail' ? <span className="recipient-cross">×</span> : null}
    </span>
  </button>;
}

export function RecipientError({ error }) {
  return <div className="recipient-feedback" aria-live="polite">
    {error && <div className="auth-err" role="alert">{typeof error === 'string' ? error : error.msg}</div>}
  </div>;
}

export function InvitationMeta({ invitation, expiresAt }) {
  return <div className="recipient-meta">
    {invitation?.code && <div>Invitation <code>{invitation.code}</code></div>}
    {invitation?.label && <div>{invitation.label}</div>}
    {(expiresAt || invitation?.expires_at) && <div>Complete by <time dateTime={expiresAt || invitation.expires_at}>{formatInvitationTime(expiresAt || invitation.expires_at)}</time></div>}
  </div>;
}

export function LockedEmail({ email, hint = 'This invitation is for this address and cannot be changed.' }) {
  return <div className="auth-grp">
    <label htmlFor="recipient-email">Email address</label>
    <div className="recipient-lock-wrap">
      <input id="recipient-email" className="auth-input recipient-locked" value={email} readOnly aria-readonly="true" autoComplete="email" />
      <Icon name="lock" size={16} />
    </div>
    <span className="recipient-hint">{hint}</span>
  </div>;
}

export function RecipientNotice({ status, invitation, signInHref = '/', onRetry }) {
  const messages = {
    expired: ['This invitation has expired', `Its deadline was ${formatInvitationTime(invitation?.expires_at)}. Invitations cannot be extended or completed late.`],
    used: ['This invitation has already been used', 'Each invitation creates one account. If that was you, sign in instead.'],
    revoked: ['This invitation was withdrawn', 'It can no longer be used to create an account.'],
    unavailable: ['This invitation is no longer available', 'The access it offered has changed, so it cannot be used.'],
    invalid: ['Invitation not found', 'Check the invitation code or ask the person who invited you for a new invitation.'],
    link: ['Registration link unavailable', 'This registration link is invalid or has expired. Check the full link in your email or ask for a new invitation.'],
    closed: ['Registration is closed', 'New accounts cannot be created right now. Contact the person who invited you.'],
    unreachable: ['Unable to check this invitation', 'The service could not be reached. Your invitation has not been consumed. Please try again.'],
  };
  const [title, message] = messages[status] || messages.unreachable;
  return <>
    <div className={'auth-done recipient-notice ' + (status === 'used' ? 'info' : '')}><Icon name={status === 'used' ? 'check' : 'lock'} size={26} /></div>
    <h1 className="auth-h1">{title}</h1><p className="auth-msg">{message}</p>
    {!['closed', 'unreachable', 'link', 'invalid'].includes(status) && <p className="auth-msg">If you still need access, ask the person who invited you for a new invitation.</p>}
    {onRetry && <button type="button" className="auth-btn" onClick={onRetry}>Try again</button>}
    {['link', 'invalid'].includes(status) && <a className="recipient-signin" href="/register/start">{status === 'link' ? 'Request a new registration link' : 'Enter an invitation code'}</a>}
    <a className="recipient-signin" href={signInHref}>{status === 'used' ? 'Sign in' : 'Return to sign in'}</a>
    {invitation && <InvitationMeta invitation={invitation} />}
  </>;
}
