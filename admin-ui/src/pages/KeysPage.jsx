import { useEffect, useState, useRef } from 'react';
import { getKeys, rotateKeys } from '../api.js';
import Icon from '../Icon.jsx';
import { SkelListRow } from '../Skel.jsx';

const fmt = (iso) =>
  iso ? new Date(iso).toLocaleString(undefined, { year: 'numeric', month: 'short', day: 'numeric', hour: 'numeric', minute: '2-digit' }) : '—';

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
  if (k.status === 'next') return <span className="pill pill-warn">scheduled</span>;
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
  const [uncertain, setUncertain] = useState(false);
  const unresolved = useRef(null);
  const readGeneration = useRef(0);

  const load = () => {
    const generation = ++readGeneration.current;
    return getKeys()
      .then(value => {
        if (generation !== readGeneration.current) return null;
        setData(value);setErr(false);setUncertain(false);
        if (unresolved.current) {
          const { previousKid, code } = unresolved.current;
          setActErr(value.rotation?.rotation || value.rotation?.kid !== previousKid
            ? null : `No rotation was scheduled. Check the service before retrying. [${code}]`);
          unresolved.current = null;
        }
        return value;
      })
      .catch((e) => {
        if (generation !== readGeneration.current) return null;
        if (e.message !== 'unauthenticated') setErr(true);
        return null;
      });
  };
  useEffect(() => {
    load();
  }, []);
  const pending = data?.rotation?.rotation;
  useEffect(() => {
    if (!pending && !uncertain) return;
    const timer = setInterval(() => { if (document.visibilityState === 'visible') void load(); }, 15000);
    return () => clearInterval(timer);
  }, [pending?.id, uncertain]);

  const rotate = async () => {
    setBusy(true);
    setActErr(null);
    const previousKid = data?.rotation?.kid;
    unresolved.current = null;
    readGeneration.current++;
    try {
      const rotation = await rotateKeys();
      readGeneration.current++;
      setData(current => current && ({ ...current, rotation }));
      setUncertain(true);
      setModal(false);
      await load();
    } catch (e) {
      readGeneration.current++;
      if (e.message === 'unauthenticated') return;
      unresolved.current = { previousKid, code: e.data?.error || 'http_' + e.status };
      setUncertain(true);
      setActErr(`Couldn't confirm the rotation. Refresh status before trying again. [${e.data?.error || 'http_' + e.status}]`);
      setModal(false);
      await load();
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1>Signing keys</h1>
        <button className="btn btn-primary" onClick={() => setModal(true)} disabled={data === null || busy || !!pending || uncertain}>
          <Icon name="key" size={14} />
          {pending ? 'Rotation scheduled' : 'Rotate key'}
        </button>
      </div>
      <p className="sub">Keys used to sign tokens (id_token, access token, logout/event tokens).</p>
      {err && <p className="err">Couldn't load keys.</p>}
      {actErr && <p className="err">{actErr}</p>}
      {(uncertain || err) && <button className="btn" onClick={() => void load()}>Refresh status</button>}
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
                      {k.alg} · {k.status === 'next' ? (k.activate_after ? `starts no earlier than ${fmt(k.activate_after)}` : 'publishing') : `activated ${fmt(k.activated_at)}`}
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
            The new public key is published first and can start signing after at least five minutes.
            The current key remains available to verify existing tokens for 24 hours after activation.
          </p>
          <div className="modal-actions">
            <button className="btn btn-primary" onClick={rotate} disabled={busy}>
              {busy ? 'Scheduling…' : 'Schedule rotation'}
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
