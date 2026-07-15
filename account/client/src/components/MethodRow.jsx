import { useState } from 'react';
import Icon from './Icon.jsx';

// A managed MFA method row (authenticator or passkey): icon + black title + grey
// subtitle, with inline rename and a two-step remove confirm. onRename(label) and
// onRemove() return promises; the parent reloads the list inside them.
export default function MethodRow({ icon, title, subtitle, onRename, onRemove }) {
  const [mode, setMode] = useState(null); // null | 'rename' | 'remove'
  const [label, setLabel] = useState(title);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState(null);

  const doRename = async () => {
    if (!label.trim()) return;
    setBusy(true);
    setErr(null);
    try {
      await onRename(label.trim());
      setMode(null);
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr('Rename failed.');
    } finally {
      setBusy(false);
    }
  };

  const doRemove = async () => {
    setBusy(true);
    setErr(null);
    try {
      await onRemove();
    } catch (e) {
      if (e.message !== 'unauthenticated') {
        setErr('Remove failed.');
        setBusy(false);
      }
    }
  };

  return (
    <div className="row">
      <div className="mfa-lhs">
        <span className="mfa-ico">
          <Icon name={icon} size={20} />
        </span>
        <div className="row-main">
          {mode === 'rename' ? (
            <div className="edit">
              <input
                className="input"
                autoFocus
                value={label}
                disabled={busy}
                onChange={(e) => setLabel(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') doRename();
                  if (e.key === 'Escape') setMode(null);
                }}
              />
              <button className="btn btn-primary" onClick={doRename} disabled={busy}>
                Save
              </button>
              <button
                className="btn"
                onClick={() => {
                  setMode(null);
                  setLabel(title);
                }}
                disabled={busy}
              >
                Cancel
              </button>
            </div>
          ) : (
            <>
              <p className="mfa-title">{title}</p>
              <p className="k">{subtitle}</p>
            </>
          )}
          {err && <p className="err">{err}</p>}
        </div>
      </div>
      {mode === 'remove' ? (
        <div className="row-actions">
          <span className="confirm-q">Remove?</span>
          <button className="btn btn-danger" onClick={doRemove} disabled={busy}>
            {busy ? 'Removing…' : 'Remove'}
          </button>
          <button className="btn" onClick={() => setMode(null)} disabled={busy}>
            Cancel
          </button>
        </div>
      ) : mode === null ? (
        <div className="row-actions">
          <button
            className="btn"
            onClick={() => {
              setLabel(title);
              setMode('rename');
            }}
          >
            <Icon name="edit" size={14} />
            Rename
          </button>
          <button className="btn btn-danger" onClick={() => setMode('remove')}>
            <Icon name="trash" size={14} />
            Remove
          </button>
        </div>
      ) : null}
    </div>
  );
}
