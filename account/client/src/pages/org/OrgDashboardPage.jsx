import { useEffect, useState } from 'react';
import { Link, Navigate } from 'react-router-dom';
import { useAuth } from '../../context/AuthContext.jsx';
import { getOrgDashboard } from '../../api.js';
import { fmtAgo } from '../../format.js';
import { Ph } from '../../components/Skeleton.jsx';

// Loading: every static piece renders for real (titles, stat labels, section
// headers — including Recent activity, which the client can predict from its
// own /api/me permission set); only the variable values shimmer, sized by the
// surrounding text so nothing shifts when data lands. Exported so the org
// gate can paint the same pixels while the step-up check runs.
export function DashboardSkeleton({ showRecent }) {
  return (
    <>
      <h1>Dashboard</h1>
      <p className="sub">Organization overview.</p>
      <div className="org-cards">
        {['Users', 'Active sessions', 'MFA adoption', 'App catalogs'].map((k) => (
          <div className="org-stat" key={k}>
            <p className="k">{k}</p>
            <p className="v"><Ph w={46} /></p>
            <p className="s"><Ph w={96} /></p>
          </div>
        ))}
      </div>
      <h2 className="section">Users by role</h2>
      <div className="card">
        {Array.from({ length: 3 }).map((_, i) => (
          <div className="row" key={i}>
            <p className="k" style={{ fontSize: 13, minWidth: 170, margin: 0 }}><Ph w={120 - i * 15} /></p>
            <div className="org-bar"><span className="skeleton" style={{ display: 'block', height: '100%', width: `${62 - i * 18}%` }} /></div>
            <p style={{ margin: 0, minWidth: 28, textAlign: 'right', fontSize: 13 }}><Ph w={18} /></p>
          </div>
        ))}
      </div>
      <h2 className="section">Apps</h2>
      <div className="card">
        <div className="row">
          <p className="k" style={{ fontSize: 13, margin: 0 }}><Ph w={90} /></p>
          <p className="text-faint" style={{ margin: 0, fontSize: 12 }}><Ph w={140} /></p>
        </div>
      </div>
      {showRecent && (
        <>
          <h2 className="section" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            Recent activity
            <Link to="/organization/logs" style={{ fontSize: 12, fontWeight: 500 }}>View all</Link>
          </h2>
          <div className="card">
            {Array.from({ length: 3 }).map((_, i) => (
              <div className="row" key={i}>
                <p className="k" style={{ fontSize: 13, margin: 0, flex: 1 }}><Ph w={`${58 - i * 8}%`} /></p>
                <p className="text-faint" style={{ margin: 0, fontSize: 12 }}><Ph w={48} /></p>
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}

export default function OrgDashboardPage() {
  const { can } = useAuth();
  const [d, setD] = useState(null);
  const [err, setErr] = useState(null);

  useEffect(() => {
    if (!can('org.dashboard')) return;
    getOrgDashboard().then(setD).catch((e) => {
      if (e.message !== 'unauthenticated') setErr(e.code || 'error');
    });
  }, [can]);

  // Landing rule: no org.dashboard -> fall to the first pane the caller holds.
  if (!can('org.dashboard')) {
    if (can('org.logs.view')) return <Navigate to="/organization/logs" replace />;
    return <p className="sub">No organization panes available for your permissions.</p>;
  }

  if (err) return (<><h1>Dashboard</h1><p className="err">Couldn't load the dashboard. [{err}]</p></>);
  if (!d) return <DashboardSkeleton showRecent={can('org.logs.view')} />;

  const mfaPct = d.users.total ? Math.round((d.users.mfa_on / d.users.total) * 100) : 0;
  const maxMembers = Math.max(1, ...d.roles.map((r) => r.members));

  return (
    <>
      <h1>Dashboard</h1>
      <p className="sub">Organization overview.</p>

      <div className="org-cards">
        <div className="org-stat">
          <p className="k">Users</p>
          <p className="v">{d.users.total}</p>
          <p className="s">{d.users.suspended ? `${d.users.suspended} suspended` : 'all active'}</p>
        </div>
        <div className="org-stat">
          <p className="k">Active sessions</p>
          <p className="v">{d.sessions_active}</p>
          <p className="s">across all devices</p>
        </div>
        <div className="org-stat">
          <p className="k">MFA adoption</p>
          <p className="v">{mfaPct}%</p>
          <p className="s">{d.users.mfa_on} of {d.users.total} users</p>
        </div>
        <div className="org-stat">
          <p className="k">App catalogs</p>
          <p className="v">{d.apps.length}</p>
          <p className="s">
            {d.apps.length
              ? `latest sync ${fmtAgo(d.apps.reduce((a, b) => (a.synced_at > b.synced_at ? a : b)).synced_at)}`
              : 'none synced yet'}
          </p>
        </div>
      </div>

      <h2 className="section">Users by role</h2>
      <div className="card">
        {d.roles.map((r) => (
          <div className="row" key={r.slug}>
            <p className="k" style={{ fontSize: 13, minWidth: 170 }}>
              {r.label} <span className="text-faint">· lvl {r.level}</span>
              {r.slug === d.default_org_role && <span className="pill pill-ok" style={{ marginLeft: 6 }}>default</span>}
            </p>
            <div className="org-bar"><i style={{ width: `${Math.round((r.members / maxMembers) * 100)}%` }} /></div>
            <p style={{ margin: 0, minWidth: 28, textAlign: 'right', fontSize: 13 }}>{r.members}</p>
          </div>
        ))}
      </div>

      <h2 className="section">Apps</h2>
      <div className="card">
        {d.apps.length === 0 && <div className="row"><p className="k">No app catalogs synced yet.</p></div>}
        {d.apps.map((a) => (
          <div className="row" key={a.client_id}>
            <p className="k" style={{ fontSize: 13 }}>{a.name || a.client_id}</p>
            <p className="text-faint" style={{ margin: 0, fontSize: 12 }}>
              {a.roles} roles · synced {fmtAgo(a.synced_at)}
            </p>
          </div>
        ))}
      </div>

      {Array.isArray(d.recent) && (
        <>
          <h2 className="section" style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            Recent activity
            <Link to="/organization/logs" style={{ fontSize: 12, fontWeight: 500 }}>View all</Link>
          </h2>
          <div className="card">
            {d.recent.length === 0 && <div className="row"><p className="k">Nothing yet.</p></div>}
            {d.recent.map((e) => (
              <div className="row" key={e.id}>
                <p className="k" style={{ fontSize: 13 }}>
                  <strong>{e.actor_label}</strong> · {e.action}
                  {e.target_label ? <> · {e.target_label}</> : null}
                </p>
                <p className="text-faint" style={{ margin: 0, fontSize: 12 }}>{fmtAgo(e.created_at)}</p>
              </div>
            ))}
          </div>
        </>
      )}
    </>
  );
}
