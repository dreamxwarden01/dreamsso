import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { listClients } from '../api.js';
import Icon from '../Icon.jsx';
import { SkelListRow } from '../Skel.jsx';

export default function ClientsPage() {
  const nav = useNavigate();
  const [clients, setClients] = useState(null);
  const [err, setErr] = useState(false);

  useEffect(() => {
    listClients()
      .then((d) => setClients(d.clients))
      .catch((e) => {
        if (e.message !== 'unauthenticated') setErr(true);
      });
  }, []);

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <h1>Clients</h1>
        <button className="btn btn-primary" onClick={() => nav('/clients/new')}>
          <Icon name="plus" size={14} />
          Register client
        </button>
      </div>
      <p className="sub">Applications that sign in through DreamSSO.</p>
      {err && <p className="err">Couldn't load clients.</p>}

      {clients === null ? (
        <div className="card">
          <SkelListRow icon="appwindow" chevron />
          <SkelListRow icon="appwindow" chevron />
        </div>
      ) : (
        <div className="card">
          {clients.map((c) => (
            <button key={c.client_id} className="row row-link" onClick={() => nav('/clients/' + encodeURIComponent(c.client_id))}>
              <span className="lhs">
                <span className="tile" style={c.disabled_at ? { color: 'var(--faint)' } : undefined}>
                  <Icon name="appwindow" size={17} />
                </span>
                <span style={{ minWidth: 0 }}>
                  <p className="row-title" style={c.disabled_at ? { color: 'var(--mut)' } : undefined}>{c.name}</p>
                  <p className="k mono">
                    {c.client_id} · {c.jwks_uri ? 'jwks_uri' : c.has_inline_jwks ? 'inline key' : 'no key'}
                  </p>
                </span>
              </span>
              <span style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                {c.is_system && <span className="pill pill-mut">System</span>}
                {c.disabled_at ? (
                  <span className="pill pill-warn">Disabled</span>
                ) : (
                  <span className="pill pill-ok">Active</span>
                )}
                <Icon name="chevron" size={15} className="chev" />
              </span>
            </button>
          ))}
          {clients.length === 0 && (
            <div className="row">
              <p className="k">No clients registered yet.</p>
            </div>
          )}
        </div>
      )}
    </>
  );
}
