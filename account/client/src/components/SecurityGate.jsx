import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { getStepupStatus } from '../api.js';
import StepUpModal from './StepUpModal.jsx';

// Entry gate for the factor-management pages (Authenticator / Passkeys): a fresh
// sudo window (FALLBACK tier) is required to enter — the destination page's own
// skeleton shows underneath while the challenge runs (gate-skeleton convention,
// like OrgGate). Zero-factor accounts don't pass free any more: the fallback tier
// challenges for a password (or email) unless a recent login already proved it —
// so first enrollment rides a fresh login silently, then re-challenges once the
// window lapses. The server independently re-checks on every action, so this gate
// is UX, not the security boundary.
//
// Stricter reuse for factor management: the stamp only counts for 10 minutes
// here (server cap), and entering with less than 3 minutes of that left
// triggers a fresh challenge up front rather than mid-flow.
const FACTOR_WINDOW_S = 600;
const ENTRY_MIN_LEFT_S = 180;

export default function SecurityGate({ skeleton, children }) {
  const nav = useNavigate();
  const [state, setState] = useState('checking'); // checking | modal | ok
  const [status, setStatus] = useState(null);

  useEffect(() => {
    let on = true;
    getStepupStatus('fallback')
      .then((s) => {
        if (!on) return;
        setStatus(s);
        const freshEnough =
          s.verified && s.age_seconds != null && s.age_seconds < FACTOR_WINDOW_S - ENTRY_MIN_LEFT_S;
        setState(s.methods?.length && !freshEnough ? 'modal' : 'ok');
      })
      .catch(() => {
        if (on) setState('ok'); // fail open — the server still gates every action
      });
    return () => {
      on = false;
    };
  }, []);

  if (state === 'ok') return children;
  return (
    <>
      {skeleton}
      {state === 'modal' && (
        <StepUpModal status={status} onSuccess={() => setState('ok')} onCancel={() => nav('/security')} />
      )}
    </>
  );
}
