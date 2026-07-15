import { useEffect, useRef, useState } from 'react';
import { browserSupportsWebAuthn } from '@simplewebauthn/browser';
import { orgApi } from '../api.js';
import { useSite } from '../context/SiteContext.jsx';
import Icon from './Icon.jsx';
import ChallengeModal from './ChallengeModal.jsx';

// One-time action ceremony for very sensitive org actions (MFA reset). Unlike the
// sudo window, pre-clearance does NOT count — the actor passes a FRESH strong
// challenge that mints a single-use token bound to (actor, action, target). Same
// card as ChallengeModal; only the data source differs (action-challenge fetches
// the accepted methods + passkey options, action-token exchanges the proof for a
// token). action-token returns strong methods only, so email/password never appear.
export default function ActionChallengeModal({ action, targetSub, onToken, onCancel }) {
  const { siteName } = useSite();
  const name = siteName || 'DreamSSO';
  const [ready, setReady] = useState(null); // null=loading · 'error' · { accepted }
  const pkRef = useRef(null);

  useEffect(() => {
    let alive = true;
    orgApi('POST', '/action-challenge', {})
      .then((d) => {
        if (!alive) return;
        let m = d.methods || [];
        if (!browserSupportsWebAuthn()) m = m.filter((x) => x !== 'passkey');
        pkRef.current = d.passkey_options;
        setReady({ accepted: m });
      })
      .catch((e) => {
        if (!alive) return;
        if (e.message !== 'unauthenticated') setReady('error');
      });
    return () => { alive = false; };
  }, []);

  if (ready === null || ready === 'error') {
    return (
      <div className="ch-scrim">
        <div className="ch-wrap">
          <div className="auth-card" role="dialog" aria-modal="true">
            <div className="auth-brand">
              <span className="auth-badge"><Icon name="shield-lock" size={24} /></span>
              <span className="auth-wordmark">{name}</span>
            </div>
            {ready === 'error' ? (
              <>
                <h1 className="auth-h1">Verification unavailable</h1>
                <p className="auth-sub ch-sub">Couldn’t start verification. Try again in a moment.</p>
                <button className="ch-ghost" onClick={onCancel}>Close</button>
              </>
            ) : (
              <p className="wait" style={{ margin: '14px 0 4px' }}>Preparing verification…</p>
            )}
          </div>
          <div className="auth-foot"><Icon name="lock" size={12} /> Protected by {name}</div>
        </div>
      </div>
    );
  }

  return (
    <ChallengeModal
      accepted={ready.accepted}
      getPasskeyOptions={() => Promise.resolve(pkRef.current)}
      verify={({ method, code, credential }) =>
        orgApi('POST', '/action-token', {
          action,
          target_sub: targetSub,
          method,
          ...(method === 'passkey' ? { credential: JSON.stringify(credential) } : { code }),
        }).then((d) => d.action_token)
      }
      onSuccess={(tok) => onToken(tok)}
      onCancel={onCancel}
    />
  );
}
