import { useEffect } from 'react';
import { Outlet } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useSite } from '../context/SiteContext.jsx';
import Sidebar from './Sidebar.jsx';
import Icon from './Icon.jsx';
import ProfileMenu from './ProfileMenu.jsx';
import { avatarUrl } from '../api.js';

export default function AppShell() {
  const { user, logout } = useAuth();
  const { siteName } = useSite();
  const p = user.profile;
  // Tab title follows the SSO's site_name setting; skip while unknown.
  useEffect(() => {
    if (siteName) document.title = `${siteName} account`;
  }, [siteName]);
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          <Icon name="shield-lock" size={20} />
          <span>{siteName || ''} account</span>
        </div>
        <div className="topbar-user">
          <ProfileMenu
            name={p.display_name || p.username}
            email={p.email}
            picture={p.picture ? avatarUrl(p.picture) : null}
            orgName={siteName || ''}
            onSignOut={logout}
          />
        </div>
      </header>
      <div className="body">
        <Sidebar />
        <main className="content">
          <div className="content-inner">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
