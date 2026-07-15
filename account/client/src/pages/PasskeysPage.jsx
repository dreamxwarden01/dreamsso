import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { startRegistration, browserSupportsWebAuthn } from '@simplewebauthn/browser';
import {
  getSecurity,
  getStepupStatus,
  passkeyRegisterOptions,
  passkeyRegister,
  renamePasskey,
  removePasskey,
} from '../api.js';
import Icon from '../components/Icon.jsx';
import Modal from '../components/Modal.jsx';
import MethodRow from '../components/MethodRow.jsx';
import SecurityGate from '../components/SecurityGate.jsx';
import StepUpModal from '../components/StepUpModal.jsx';
import { MethodRowSkeleton } from '../components/Skeleton.jsx';
import { fmtDate } from './SecurityPage.jsx';

const MAX_PASSKEYS = 10;

// Default generic name (user can edit before saving): Passkey-XXXXXX.
function rand6() {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const bytes = crypto.getRandomValues(new Uint8Array(6));
  let s = '';
  for (let i = 0; i < 6; i++) s += alphabet[bytes[i] % alphabet.length];
  return s;
}

// Page chrome + skeleton — doubles as the gate's underlay (gate-skeleton
// convention: real chrome, shimmering values).
function PageChrome({ nav, children }) {
  return (
    <>
      <button className="back" onClick={() => nav('/security')}>
        <Icon name="chevron" size={16} className="back-chev" />
        Security
      </button>
      <h1>Passkeys and security keys</h1>
      <p className="sub">
        Sign in with Touch ID, Windows Hello, or a hardware security key — no password needed.
      </p>
      {children}
    </>
  );
}

function PageSkeleton({ nav }) {
  return (
    <PageChrome nav={nav}>
      <div className="card">
        <MethodRowSkeleton icon="key" />
        <MethodRowSkeleton icon="key" />
      </div>
      <button className="btn btn-primary">
        <Icon name="plus" size={15} />
        Add a passkey
      </button>
    </PageChrome>
  );
}

export default function PasskeysPage() {
  const nav = useNavigate();
  const [list, setList] = useState(null);
  const [err, setErr] = useState(false);

  // add flow: idle -> (ceremony) -> naming -> idle
  const [phase, setPhase] = useState('idle'); // idle | naming
  const [credential, setCredential] = useState(null);
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [maxErr, setMaxErr] = useState(null); // inline "reached the maximum" notice
  const [failure, setFailure] = useState(null); // { title, message, code, onRetry? } -> modal

  // mid-action sudo-window lapse -> challenge, then retry the action
  const [stepup, setStepup] = useState(null); // { status, retry }
  const demandStepup = async (retry) => setStepup({ status: await getStepupStatus('fallback'), retry });
  // Proactive 7-min buffer: challenge FIRST when the sudo window is older than 7
  // min (or unverified) so the passkey ceremony doesn't 403 after the server's
  // 10-min cap lapses mid-flow. Reactive 403 stays as the backstop.
  const withFreshStepup = async (action) => {
    try {
      const s = await getStepupStatus('fallback');
      if (s.verified && s.age_seconds != null && s.age_seconds <= 420) return action();
      setStepup({ status: s, retry: action });
    } catch (e) {
      if (e.message !== 'unauthenticated') action();
    }
  };

  const load = () =>
    getSecurity()
      .then((d) => setList(d.mfa.passkeys))
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const atLimit = (list?.length ?? 0) >= MAX_PASSKEYS;

  const failAdd = (code, onRetry) =>
    setFailure({
      title: "Couldn't add your passkey",
      message: 'Something went wrong. You can return and try again.',
      code,
      onRetry,
    });

  // Step 1: get options, run the browser ceremony, then move to naming.
  const startAdd = async () => {
    setMaxErr(null);
    if (!browserSupportsWebAuthn()) {
      setFailure({
        title: 'Passkeys not supported',
        message: "This browser doesn't support passkeys. Try a different browser or device.",
        code: 'webauthn_unsupported',
      });
      return;
    }
    setBusy(true);
    try {
      const options = await passkeyRegisterOptions();
      let cred;
      try {
        cred = await startRegistration({ optionsJSON: options });
      } catch (e) {
        // User dismissed the system prompt, or the device declined.
        failAdd(e.name || 'passkey_error', startAdd);
        return;
      }
      setCredential(cred);
      setName('Passkey-' + rand6());
      setPhase('naming');
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') return demandStepup(() => startAdd());
      if (e.data?.error === 'limit_reached' || String(e.data?.error || '').startsWith('maximum')) {
        setMaxErr(`You've reached the maximum of ${MAX_PASSKEYS} passkeys.`);
      } else {
        failAdd(e.data?.error || `http_${e.status}`, startAdd);
      }
    } finally {
      setBusy(false);
    }
  };

  // Restart the whole flow (used as the retry — the ceremony credential/challenge
  // may no longer be valid after a failure).
  const retryAdd = () => {
    setPhase('idle');
    setCredential(null);
    setName('');
    startAdd();
  };

  // Step 2: persist with the chosen (or generic) name.
  const saveName = async () => {
    setBusy(true);
    try {
      await passkeyRegister(credential, name.trim() || null);
      setPhase('idle');
      setCredential(null);
      setName('');
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') return demandStepup(() => saveName());
      failAdd(e.data?.error || `http_${e.status}`, retryAdd);
    } finally {
      setBusy(false);
    }
  };

  const cancelNaming = () => {
    setPhase('idle');
    setCredential(null);
    setName('');
  };

  // Remove: intercept a lapsed sudo window (challenge + retry); everything else
  // bubbles to MethodRow's inline "Remove failed."
  const doRemove = async (id) => {
    try {
      await removePasskey(id);
      await load();
    } catch (e) {
      if (e.code === 'step_up_required') {
        await demandStepup(() => doRemove(id));
        return;
      }
      throw e;
    }
  };

  return (
    <SecurityGate skeleton={<PageSkeleton nav={nav} />}>
      <PageChrome nav={nav}>
        {err && <p className="err">Couldn't load passkeys.</p>}

        {list === null ? (
          <>
            <div className="card">
              <MethodRowSkeleton icon="key" />
              <MethodRowSkeleton icon="key" />
            </div>
            <button className="btn btn-primary">
              <Icon name="plus" size={15} />
              Add a passkey
            </button>
          </>
        ) : (
          <>
            {list.length > 0 && (
              <div className="card">
                {list.map((p) => (
                  <MethodRow
                    key={p.id}
                    icon="key"
                    title={p.label || 'Passkey'}
                    subtitle={`Added ${fmtDate(p.created_at) || '—'} · Last used ${fmtDate(p.last_used_at) || 'never'}`}
                    onRename={(label) => renamePasskey(p.id, label).then(load)}
                    onRemove={() => doRemove(p.id)}
                  />
                ))}
              </div>
            )}
            {list.length === 0 && phase === 'idle' && (
              <div className="stub" style={{ marginBottom: 16 }}>
                <Icon name="key" size={30} />
                <h3>No passkeys yet</h3>
                <p>Add one for fast, phishing-resistant sign-in.</p>
              </div>
            )}

            {phase === 'naming' ? (
              <div className="card pad">
                <h3 style={{ margin: '0 0 4px', fontSize: 16 }}>Name your passkey</h3>
                <p className="hint" style={{ marginTop: 0 }}>
                  Give it a name so you can recognize this device later.
                </p>
                <div className="form" style={{ marginTop: 12 }}>
                  <label className="field">
                    <span>Passkey name</span>
                    <input
                      className="input wide"
                      autoFocus
                      maxLength={100}
                      value={name}
                      onChange={(e) => setName(e.target.value)}
                      onKeyDown={(e) => {
                        if (e.key === 'Enter') saveName();
                      }}
                    />
                  </label>
                  <div className="form-actions">
                    <button className="btn btn-primary" onClick={saveName} disabled={busy}>
                      {busy ? 'Saving…' : 'Save passkey'}
                    </button>
                    <button className="btn" onClick={cancelNaming} disabled={busy}>
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            ) : (
              <>
                {maxErr && <p className="err">{maxErr}</p>}
                <button className="btn btn-primary" onClick={() => withFreshStepup(startAdd)} disabled={busy || atLimit}>
                  <Icon name="plus" size={15} />
                  {busy ? 'Waiting for your device…' : 'Add a passkey'}
                </button>
                {atLimit && <p className="hint">Limit reached — you can add up to {MAX_PASSKEYS} passkeys.</p>}
              </>
            )}
          </>
        )}

        {failure && (
          <Modal title={failure.title} onClose={() => setFailure(null)}>
            <p className="modal-msg">{failure.message}</p>
            <p className="errcode">[{failure.code}]</p>
            <div className="modal-actions">
              {failure.onRetry && (
                <button
                  className="btn btn-primary"
                  onClick={() => {
                    const r = failure.onRetry;
                    setFailure(null);
                    r();
                  }}
                >
                  Try again
                </button>
              )}
              <button className="btn" onClick={() => setFailure(null)}>
                Close
              </button>
            </div>
          </Modal>
        )}

        {stepup && (
          <StepUpModal
            status={stepup.status}
            onSuccess={() => {
              const r = stepup.retry;
              setStepup(null);
              r?.();
            }}
            onCancel={() => setStepup(null)}
          />
        )}
      </PageChrome>
    </SecurityGate>
  );
}
