import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  getSecurity,
  getStepupStatus,
  authenticatorSetup,
  authenticatorConfirm,
  renameAuthenticator,
  removeAuthenticator,
} from '../api.js';
import Icon from '../components/Icon.jsx';
import MethodRow from '../components/MethodRow.jsx';
import SecurityGate from '../components/SecurityGate.jsx';
import StepUpModal from '../components/StepUpModal.jsx';
import { MethodRowSkeleton } from '../components/Skeleton.jsx';
import { fmtDate } from './SecurityPage.jsx';

const MAX_AUTHENTICATORS = 5;

// Setup key shown in a copy-field: the full key may be truncated (it's always
// copied in full), with the copy control pinned inside on the right.
function KeyField({ value }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard unavailable */
    }
  };
  return (
    <div className="keyfield">
      <span className="k">Setup key</span>
      <div className="keybox">
        <code className="keytext">{value}</code>
        <button type="button" className="keycopy" onClick={copy} title="Copy setup key" aria-label="Copy setup key">
          <Icon name={copied ? 'check' : 'copy'} size={15} />
        </button>
      </div>
    </div>
  );
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
      <h1>Authenticator apps</h1>
      <p className="sub">
        Use an app like 1Password, Google Authenticator, or Authy to generate sign-in codes.
      </p>
      {children}
    </>
  );
}

function PageSkeleton({ nav }) {
  return (
    <PageChrome nav={nav}>
      <div className="card">
        <MethodRowSkeleton icon="qr" />
        <MethodRowSkeleton icon="qr" />
      </div>
      <button className="btn btn-primary">
        <Icon name="plus" size={15} />
        Add authenticator
      </button>
    </PageChrome>
  );
}

export default function AuthenticatorPage() {
  const nav = useNavigate();
  const [list, setList] = useState(null);
  const [err, setErr] = useState(false);

  // add flow
  const [setup, setSetup] = useState(null); // { id, secret, otpauth_uri, qr_data_url }
  const [code, setCode] = useState('');
  const [name, setName] = useState('');
  const [busy, setBusy] = useState(false);
  const [addErr, setAddErr] = useState(null);

  // mid-action sudo-window lapse -> challenge, then retry the action
  const [stepup, setStepup] = useState(null); // { status, retry }
  const demandStepup = async (retry) => setStepup({ status: await getStepupStatus('fallback'), retry });
  // Proactive 7-min buffer: before a multi-step add flow, challenge FIRST when the
  // sudo window is older than 7 min (or unverified), so the final step doesn't 403
  // after the server's 10-min cap lapses mid-flow (which would lose a rotated code).
  const withFreshStepup = async (action) => {
    try {
      const s = await getStepupStatus('fallback');
      if (s.verified && s.age_seconds != null && s.age_seconds <= 420) return action();
      setStepup({ status: s, retry: action });
    } catch (e) {
      if (e.message !== 'unauthenticated') action(); // probe failed -> reactive 403 backstop
    }
  };

  const load = () =>
    getSecurity()
      .then((d) => setList(d.mfa.authenticators))
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const atLimit = (list?.length ?? 0) >= MAX_AUTHENTICATORS;

  const startAdd = async () => {
    setBusy(true);
    setAddErr(null);
    try {
      const s = await authenticatorSetup();
      setSetup(s);
      setCode('');
      setName('');
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') return demandStepup(() => startAdd());
      setAddErr(
        e.data?.error === 'limit_reached'
          ? `You've reached the maximum of ${MAX_AUTHENTICATORS} authenticator apps.`
          : "Couldn't start setup. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  const cancelAdd = () => {
    setSetup(null);
    setCode('');
    setName('');
    setAddErr(null);
  };

  const confirmAdd = async () => {
    setBusy(true);
    setAddErr(null);
    try {
      await authenticatorConfirm({ id: setup.id, code: code.trim(), label: name.trim() || null });
      cancelAdd();
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      if (e.code === 'step_up_required') return demandStepup(() => confirmAdd());
      setAddErr(
        e.data?.error === 'invalid_code'
          ? 'That code is incorrect or expired — enter the current one.'
          : e.data?.error === 'limit_reached'
            ? `You've reached the maximum of ${MAX_AUTHENTICATORS} authenticator apps.`
            : "Couldn't confirm. Please try again.",
      );
    } finally {
      setBusy(false);
    }
  };

  // Remove: intercept a lapsed sudo window (challenge + retry); everything else
  // bubbles to MethodRow's inline "Remove failed."
  const doRemove = async (id) => {
    try {
      await removeAuthenticator(id);
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
        {err && <p className="err">Couldn't load authenticators.</p>}

        {list === null ? (
          <>
            <div className="card">
              <MethodRowSkeleton icon="qr" />
              <MethodRowSkeleton icon="qr" />
            </div>
            <button className="btn btn-primary">
              <Icon name="plus" size={15} />
              Add authenticator
            </button>
          </>
        ) : (
          <>
            {list.length > 0 && (
              <div className="card">
                {list.map((a) => (
                  <MethodRow
                    key={a.id}
                    icon="qr"
                    title={a.label || 'Authenticator'}
                    subtitle={`Added ${fmtDate(a.created_at) || '—'} · Last used ${fmtDate(a.last_used_at) || 'never'}`}
                    onRename={(label) => renameAuthenticator(a.id, label).then(load)}
                    onRemove={() => doRemove(a.id)}
                  />
                ))}
              </div>
            )}
            {list.length === 0 && !setup && (
              <div className="stub" style={{ marginBottom: 16 }}>
                <Icon name="qr" size={30} />
                <h3>No authenticator apps yet</h3>
                <p>Add one to use time-based codes as a second factor.</p>
              </div>
            )}

            {!setup ? (
              <>
                {addErr && <p className="err">{addErr}</p>}
                <button className="btn btn-primary" onClick={() => withFreshStepup(startAdd)} disabled={busy || atLimit}>
                  <Icon name="plus" size={15} />
                  {busy ? 'Starting…' : 'Add authenticator'}
                </button>
                {atLimit && (
                  <p className="hint">Limit reached — you can add up to {MAX_AUTHENTICATORS} authenticator apps.</p>
                )}
              </>
            ) : (
              <div className="card pad">
                <h3 style={{ margin: '0 0 4px', fontSize: 16 }}>Scan the QR code</h3>
                <p className="hint" style={{ marginTop: 0 }}>
                  Scan it with your authenticator app, or enter the setup key manually.
                </p>
                <img
                  className="qr"
                  src={setup.qr_data_url}
                  alt="Authenticator QR code"
                  width="168"
                  height="168"
                  style={{ marginTop: 4 }}
                />
                <KeyField value={setup.secret} />
                <div className="form" style={{ marginTop: 14 }}>
                  <label className="field">
                    <span>Enter the 6-digit code</span>
                    <input
                      className="input code"
                      inputMode="numeric"
                      autoComplete="one-time-code"
                      maxLength={6}
                      value={code}
                      placeholder="000000"
                      onChange={(e) => setCode(e.target.value.replace(/\D/g, ''))}
                    />
                  </label>
                  <label className="field">
                    <span>Name (optional)</span>
                    <input
                      className="input wide"
                      value={name}
                      placeholder="e.g. iPhone, 1Password"
                      onChange={(e) => setName(e.target.value)}
                    />
                  </label>
                  {addErr && <p className="err">{addErr}</p>}
                  <div className="form-actions">
                    <button className="btn btn-primary" onClick={confirmAdd} disabled={busy || code.length !== 6}>
                      {busy ? 'Verifying…' : 'Verify & add'}
                    </button>
                    <button className="btn" onClick={cancelAdd} disabled={busy}>
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            )}
          </>
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
