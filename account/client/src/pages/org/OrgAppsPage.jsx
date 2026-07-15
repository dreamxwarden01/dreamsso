import { useCallback, useEffect, useState } from 'react';
import { useAuth } from '../../context/AuthContext.jsx';
import { orgApi } from '../../api.js';
import Icon from '../../components/Icon.jsx';
import { Ph } from '../../components/Skeleton.jsx';
import { fmtAgo } from '../../format.js';

// Pane skeleton (also used by the org gate): static chrome for real, only
// the app header + role rows shimmer.
export function AppsSkeleton() {
  return (
    <>
      <h1>Apps</h1>
      <p className="sub">Role catalogs reported by each application.</p>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
        <h2 className="section" style={{ margin: 0 }}><Ph w={100} /></h2>
        <span className="fhint"><Ph w={90} /></span>
      </div>
      <div className="card">
        {Array.from({ length: 3 }).map((_, i) => (
          <div className="row" key={i}>
            <p className="row-title" style={{ margin: 0, minWidth: 140 }}><Ph w={90} /></p>
            <p className="k" style={{ margin: 0, fontSize: 12 }}><Ph w={110} /></p>
          </div>
        ))}
      </div>
    </>
  );
}

// Each app's role catalog, mirrored over the event channel. Refresh asks the
// app (roles.sync_request) to push its latest list — lands in a few seconds.
export default function OrgAppsPage() {
  const { can } = useAuth();
  const [data, setData] = useState(null);
  const [err, setErr] = useState(null);
  const [refreshing, setRefreshing] = useState(null); // client_id

  const load = useCallback(() => {
    orgApi('GET', '/apps').then(setData).catch((e) => { if (e.message !== 'unauthenticated') setErr(e.code || 'error'); });
  }, []);
  useEffect(() => { load(); }, [load]);

  const refresh = async (clientId) => {
    setRefreshing(clientId);
    try {
      await orgApi('POST', `/apps/${clientId}/request-sync`, {});
      // The reply rides the event channel (2s debounce each way) — poll briefly.
      await new Promise((r) => setTimeout(r, 5500));
      load();
    } catch (e) {
      if (e.message !== 'unauthenticated') setErr(e.code || 'error');
    } finally {
      setRefreshing(null);
    }
  };

  if (err && !data) return (<><h1>Apps</h1><p className="err">Couldn't load. [{err}]</p></>);
  if (!data) return <AppsSkeleton />;

  return (
    <>
      <h1>Apps</h1>
      <p className="sub">Role catalogs reported by each application.</p>
      {err && <p className="err">Failed. [{err}]</p>}
      {data.apps.length === 0 && <div className="card"><div className="row"><p className="k">No app catalogs synced yet.</p></div></div>}
      {data.apps.map((app) => (
        <div key={app.client_id} style={{ marginBottom: 18 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
            <h2 className="section" style={{ margin: 0 }}>{app.name || app.client_id}</h2>
            <span className="fhint">synced {fmtAgo(app.synced_at)}</span>
            {app.default_role_id == null && <span className="pill pill-warn">no default role</span>}
            <span style={{ flex: 1 }} />
            {can('org.apps.sync') && (
              <button className="btn" disabled={refreshing === app.client_id} onClick={() => refresh(app.client_id)}>
                <Icon name="chevron" size={14} style={{ transform: 'rotate(90deg)' }} />
                {refreshing === app.client_id ? 'Refreshing…' : 'Refresh'}
              </button>
            )}
          </div>
          <div className="card">
            {app.roles.map((r) => (
              <div className="row" key={r.role_id}>
                <p className="row-title" style={{ margin: 0, minWidth: 140 }}>{r.name}</p>
                <p className="k" style={{ margin: 0, fontSize: 12 }}>level {r.level} · id {r.role_id}</p>
                <span style={{ flex: 1 }} />
                {r.is_system && <span className="pill">system</span>}
                {r.role_id === app.default_role_id && <span className="pill pill-ok">default</span>}
              </div>
            ))}
          </div>
        </div>
      ))}
    </>
  );
}
