import { useEffect, useState } from 'react';
import { getSessions, terminateSession, terminateOtherSessions } from '../api.js';
import Icon from '../components/Icon.jsx';
import Modal from '../components/Modal.jsx';
import { Ph } from '../components/Skeleton.jsx';
import { fmtDate } from './SecurityPage.jsx';

const DEVICE_ICON = { desktop: 'laptop', mobile: 'phone', tablet: 'tablet' };

// cf-ipcountry (2-char ISO) -> human label. T1 = Tor exit; null/XX/unknown -> Unknown.
function fmtCountry(code) {
  if (!code || code === 'XX') return 'Unknown';
  if (code === 'T1') return 'Tor network';
  try {
    return new Intl.DisplayNames(undefined, { type: 'region' }).of(code) || code;
  } catch {
    return code;
  }
}

export default function DevicesPage() {
  const [sessions, setSessions] = useState(null);
  const [err, setErr] = useState(false);
  const [selected, setSelected] = useState(null); // sid in detail view, or null for the list
  const [confirm, setConfirm] = useState(null); // { kind: 'one'|'others', sid? }
  const [busy, setBusy] = useState(false);
  const [actErr, setActErr] = useState(false);

  const load = () =>
    getSessions()
      .then((d) => setSessions(d.sessions))
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  useEffect(() => {
    load();
  }, []);

  const current = sessions?.find((s) => s.sid === selected) ?? null;
  const otherCount = (sessions ?? []).filter((s) => !s.is_current).length;

  const runConfirm = async () => {
    setBusy(true);
    setActErr(false);
    try {
      if (confirm.kind === 'one') await terminateSession(confirm.sid);
      else await terminateOtherSessions();
      setConfirm(null);
      setSelected(null); // back to list (the detail's session may be gone)
      await load();
    } catch (e) {
      if (e.message !== 'unauthenticated') setActErr(true);
    } finally {
      setBusy(false);
    }
  };

  // ---- detail view ----
  if (current) {
    return (
      <>
        <button className="back" onClick={() => setSelected(null)}>
          <Icon name="chevron" size={16} className="back-chev" />
          Devices
        </button>

        <div className="card pad">
          <div className="devhead">
            <span className="dev-ico dev-ico-lg">
              <Icon name={DEVICE_ICON[current.device_type] || 'devices'} size={26} />
            </span>
            <div className="row-main">
              <h1 className="devhead-name">{current.device_name}</h1>
              <p className="k">{fmtCountry(current.country)}</p>
              {current.is_current && (
                <span className="this-device">
                  <Icon name="check-circle" size={15} /> This device
                </span>
              )}
              <p className="k devhead-since">First sign-in: {fmtDate(current.first_signin) || '—'}</p>
            </div>
          </div>
        </div>

        <h2 className="section">Apps and services</h2>
        <div className="card pad">
          {current.apps.length === 0 ? (
            <p className="k" style={{ margin: 0 }}>No apps or services accessed in this session.</p>
          ) : (
            <>
              <div className="appgrid">
                {current.apps.map((a) => (
                  <div className="appitem" key={a.client_id}>
                    <span className="dev-ico">
                      <Icon name="appwindow" size={18} />
                    </span>
                    <span className="appname">{a.name}</span>
                  </div>
                ))}
              </div>
              <p className="hint" style={{ marginBottom: 0 }}>
                Apps and services you accessed from this session.
              </p>
            </>
          )}
        </div>

        {!current.is_current && (
          <button className="btn btn-danger" onClick={() => setConfirm({ kind: 'one', sid: current.sid })}>
            <Icon name="trash" size={15} />
            Sign out this device
          </button>
        )}

        {confirm && (
          <ConfirmModal
            confirm={confirm}
            busy={busy}
            actErr={actErr}
            onCancel={() => setConfirm(null)}
            onConfirm={runConfirm}
          />
        )}
      </>
    );
  }

  // ---- list view ----
  return (
    <>
      <h1>Devices</h1>
      <p className="sub">Browsers and devices where you're signed in to your account.</p>
      {err && <p className="err">Couldn't load your devices.</p>}

      {sessions === null ? (
        /* placeholder rows mirror the real ones; the icon tile shimmers too
           because its glyph depends on the device type */
        <div className="card">
          {Array.from({ length: 2 }).map((_, i) => (
            <div className="row" key={i}>
              <div className="mfa-lhs">
                <span className="skeleton" style={{ width: 38, height: 38, borderRadius: 9, flexShrink: 0 }} />
                <div className="row-main">
                  <p className="mfa-title"><Ph w={170 - i * 30} /></p>
                  <p className="k"><Ph w={200} /></p>
                </div>
              </div>
              <Icon name="chevron" size={18} className="chev" />
            </div>
          ))}
        </div>
      ) : (
        <>
          <div className="card">
            {sessions.map((s) => (
              <button className="row row-link" key={s.sid} onClick={() => setSelected(s.sid)}>
                <div className="mfa-lhs">
                  <span className="dev-ico">
                    <Icon name={DEVICE_ICON[s.device_type] || 'devices'} size={20} />
                  </span>
                  <div className="row-main">
                    <p className="mfa-title">
                      {s.device_name}
                      {s.is_current && <span className="this-device inline"> · This device</span>}
                    </p>
                    <p className="k">
                      {fmtCountry(s.country)} · Last seen {fmtDate(s.last_seen) || '—'}
                    </p>
                  </div>
                </div>
                <Icon name="chevron" size={18} className="chev" />
              </button>
            ))}
          </div>

          {otherCount > 0 && (
            <button className="btn btn-danger" onClick={() => setConfirm({ kind: 'others' })}>
              Sign out all other devices
            </button>
          )}
        </>
      )}

      {confirm && (
        <ConfirmModal
          confirm={confirm}
          busy={busy}
          actErr={actErr}
          onCancel={() => setConfirm(null)}
          onConfirm={runConfirm}
        />
      )}
    </>
  );
}

function ConfirmModal({ confirm, busy, actErr, onCancel, onConfirm }) {
  const others = confirm.kind === 'others';
  return (
    <Modal title={others ? 'Sign out all other devices?' : 'Sign out this device?'} onClose={onCancel}>
      <p className="modal-msg">
        {others
          ? 'This signs you out everywhere except the device you’re using now. Apps on those devices will be signed out too.'
          : 'This signs out that device from your account and the apps it was using.'}
      </p>
      {actErr && <p className="errcode">[sign_out_failed]</p>}
      <div className="modal-actions">
        <button className="btn btn-danger" onClick={onConfirm} disabled={busy}>
          {busy ? 'Signing out…' : 'Sign out'}
        </button>
        <button className="btn" onClick={onCancel} disabled={busy}>
          Cancel
        </button>
      </div>
    </Modal>
  );
}
