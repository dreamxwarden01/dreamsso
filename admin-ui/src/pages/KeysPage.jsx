import { useEffect, useState } from 'react';
import { getKeys, rotateKeys } from '../api.js';
import Icon from '../Icon.jsx';
import { SkelListRow } from '../Skel.jsx';

const fmt = (iso) =>
  iso ? new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '—';

function Modal({ title, children, onClose }) {
  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal" role="dialog" aria-modal="true" onClick={(e) => e.stopPropagation()}>
        <h3 className="modal-title">{title}</h3>
        {children}
      </div>
    </div>
  );
}

function statusPill(k) {
  if (k.status === 'current') return <span className="pill pill-ok">current</span>;
  if (k.status === 'next') return <span className="pill pill-warn">next</span>;
  // retired: still verifying while it remains in the published JWKS (24h window)
  return k.in_jwks ? (
    <span className="pill pill-warn">retired · verifying</span>
  ) : (
    <span className="pill pill-mut">retired</span>
  );
}

export default function KeysPage() {
  const [data, setData] = useState(null);
  const [err, setErr] = useState(false);
  const [modal, setModal] = useState(false);
  const [busy, setBusy] = useState(false);
  const [actErr, setActErr] = useState(null);

  const load = () =>
    getKeys()
      .then(setData)
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const rotate = async () => {
    setBusy(true);
    setActErr(null);
    try {
      await rotateKeys();
      setModal(false);
      await load();
    } catch (e) {
      if (e.message === 'unauthenticated') return;
      setActErr(`Rotation failed. [${e.data?.error || 'http_' + e.status}]`);
      setModal(false);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1>Signing keys</h1>
        <button className="btn btn-primary" onClick={() => setModal(true)} disabled={data === null || busy}>
          <Icon name="key" size={14} />
          Rotate key
        </button>
      </div>
      <p className="sub">Keys used to sign tokens (id_token, access token, logout/event tokens).</p>
      {err && <p className="err">Couldn't load keys.</p>}
      {actErr && <p className="err">{actErr}</p>}
      {data === null ? (
        <div className="card">
          <SkelListRow icon="key" tileStyle={{ background: 'var(--blue-bg)', color: 'var(--blue)' }} />
        </div>
      ) : (
        <div className="card">
          {data.keys.map((k) => {
            const dim = k.status === 'retired';
            return (
              <div className="row" key={k.kid}>
                <span className="lhs">
                  <span
                    className="tile"
                    style={dim ? { color: 'var(--faint)' } : { background: 'var(--blue-bg)', color: 'var(--blue)' }}
                  >
                    <Icon name="key" size={17} />
                  </span>
                  <span style={{ minWidth: 0 }}>
                    <p
                      className="row-title mono"
                      style={{
                        overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        ...(dim ? { color: 'var(--mut)' } : {}),
                      }}
                    >
                      {k.kid}
                    </p>
                    <p className="k">
                      {k.alg} · activated {fmt(k.activated_at)}
                      {k.retired_at ? ` · retired ${fmt(k.retired_at)}` : ''}
                    </p>
                  </span>
                </span>
                {statusPill(k)}
              </div>
            );
          })}
        </div>
      )}
      <p className="hint">
        The JWKS is published at /jwks (advertised in the OIDC discovery document). A retired key keeps verifying
        existing tokens for 24 hours, then drops out of the published set.
      </p>

      {modal && (
        <Modal title="Rotate the signing key?" onClose={() => (busy ? null : setModal(false))}>
          <p className="modal-msg">
            A new key is generated and starts signing all tokens immediately. The current key is retired but keeps
            verifying already-issued tokens for 24 hours, so no one is signed out and nothing breaks mid-flight.
          </p>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={rotate} disabled={busy}>
              {busy ? 'Rotating…' : 'Rotate now'}
            </button>
            <button className="btn" onClick={() => setModal(false)} disabled={busy}>
              Cancel
            </button>
          </div>
        </Modal>
      )}
    </>
  );
}
