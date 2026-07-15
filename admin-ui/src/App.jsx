import { useCallback, useEffect, useRef, useState } from 'react';
import { Routes, Route, NavLink, Outlet, Navigate } from 'react-router-dom';
import { getMe, getPublicSettings } from './api.js';
import Icon from './Icon.jsx';
import ClientsPage from './pages/ClientsPage.jsx';
import ClientEditPage from './pages/ClientEditPage.jsx';
import KeysPage from './pages/KeysPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';

// Same rule as the account console: first letter of the first + last word of the
// display name; a single word (or a bare username fallback) gives one letter.
function initials(name) {
  if (!name) return '?';
  const parts = String(name).trim().split(/\s+/).filter(Boolean);
  if (parts.length === 0) return '?';
  if (parts.length === 1) return parts[0][0].toUpperCase();
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function ProfileMenu({ name, email, picture, orgName, viewAccountHref, onSignOut }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);
  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => { if (ref.current && !ref.current.contains(e.target)) setOpen(false); };
    const onKey = (e) => { if (e.key === 'Escape') setOpen(false); };
    document.addEventListener('click', onDoc);
    document.addEventListener('keydown', onKey);
    return () => { document.removeEventListener('click', onDoc); document.removeEventListener('keydown', onKey); };
  }, [open]);
  const av = (cls) => (picture ? <img className={cls} src={picture} alt="" /> : <div className={cls}>{initials(name)}</div>);
  return (
    <div className="pmenu" ref={ref}>
      <button className="pmenu-trigger" onClick={() => setOpen((v) => !v)} aria-expanded={open} aria-haspopup="true" aria-label="Profile menu">
        <span className="uname">{name}</span>
        {av('av-sm')}
      </button>
      {open && (
        <div className="pmenu-panel">
          <div className="pmenu-top">
            <span className="pmenu-org">{orgName}</span>
            <button className="pmenu-signout" onClick={onSignOut}>Sign out</button>
          </div>
          <div className="pmenu-body">
            {av('pmenu-av')}
            <div className="pmenu-info">
              <p className="pmenu-name">{name}</p>
              {email && <p className="pmenu-email">{email}</p>}
              {viewAccountHref && (
                <a className="pmenu-link" href={viewAccountHref} target="_blank" rel="noreferrer">View account</a>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

const NAV = [
  { to: '/clients', label: 'Clients', icon: 'appwindow' },
  { to: '/keys', label: 'Signing keys', icon: 'key' },
  { to: '/settings', label: 'Settings', icon: 'gear' },
];

function Shell({ me, siteName, refreshSite }) {
  const who = me.display_name || me.username;
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Icon name="shield" size={20} />
          <span>
            {siteName} <span className="brand-suffix">Admin</span>
          </span>
        </div>
        <div className="topbar-user">
          <ProfileMenu
            name={who}
            email={me.email}
            picture={me.avatar ? '/avatar/' + encodeURIComponent(me.avatar) : null}
            orgName={siteName || ''}
            viewAccountHref={me.portal || null}
            onSignOut={() => { location.href = '/logout'; }}
          />
        </div>
      </header>
      <div className="body">
        <nav className="side">
          {NAV.map((it) => (
            <NavLink
              key={it.to}
              to={it.to}
              end={it.end}
              className={({ isActive }) => 'nav' + (isActive ? ' active' : '')}
            >
              <Icon name={it.icon} size={17} />
              {it.label}
            </NavLink>
          ))}
        </nav>
        <main className="content">
          <div className="content-inner">
            <Outlet context={{ refreshSite }} />
          </div>
        </main>
      </div>
    </div>
  );
}

// Site-name cache (videosite's SiteContext pattern): lazy-init from localStorage
// so returning visitors get the right header + tab title on first paint; every
// successful /api/settings/public overwrites it. First visits render blank until
// the response lands (index.html ships an EMPTY <title> — no wrong-name flash).
const SITE_KEY = 'sso:siteName';
const readCachedSiteName = () => {
  try {
    return localStorage.getItem(SITE_KEY) || '';
  } catch {
    return '';
  }
};

export default function App() {
  const [me, setMe] = useState(null);
  const [siteName, setSiteName] = useState(readCachedSiteName);
  const refreshSite = useCallback(() => {
    getPublicSettings()
      .then((d) => {
        const name = d.site_name || 'DreamSSO';
        setSiteName(name);
        try {
          localStorage.setItem(SITE_KEY, name);
        } catch { /* private mode — cache miss next visit is fine */ }
      })
      .catch(() => {});
  }, []);
  useEffect(() => {
    getMe().then(setMe).catch(() => {});
    refreshSite();
  }, [refreshSite]);
  // Tab title follows the admin-editable site name; skip while unknown.
  useEffect(() => {
    if (siteName) document.title = `${siteName} Admin`;
  }, [siteName]);
  if (!me) {
    return (
      <div className="app">
        <div className="topbar">
          <div className="skel" style={{ width: 180, height: 30 }} />
        </div>
        <div className="body">
          <div className="side" />
          <main className="content">
            <div className="content-inner">
              <div className="skel" style={{ width: '60%', height: 24, marginBottom: 14 }} />
              <div className="skel" style={{ width: '100%', height: 160 }} />
            </div>
          </main>
        </div>
      </div>
    );
  }
  return (
    <Routes>
      <Route element={<Shell me={me} siteName={siteName} refreshSite={refreshSite} />}>
        <Route index element={<Navigate to="/clients" replace />} />
        <Route path="clients" element={<ClientsPage />} />
        <Route path="clients/new" element={<ClientEditPage />} />
        <Route path="clients/:id" element={<ClientEditPage />} />
        <Route path="keys" element={<KeysPage />} />
        <Route path="settings" element={<SettingsPage />} />
        <Route path="*" element={<Navigate to="/clients" replace />} />
      </Route>
    </Routes>
  );
}
