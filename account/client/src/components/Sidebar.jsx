import { NavLink, useLocation, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext.jsx';
import { useSite } from '../context/SiteContext.jsx';
import Icon from './Icon.jsx';

// Drill-in rail (approved design): the personal nav and the org nav share the
// SAME rail area; entering /organization/* slides to the org pane, whose top
// item ("← Organization") slides back to the personal nav. ROUTE-driven — the
// pane shown derives from the URL, so refresh and deep links land correctly
// and the transition is pure CSS.
const PERSONAL = [
  { to: '/', label: 'Profile', icon: 'user', end: true },
  { to: '/security', label: 'Security', icon: 'lock' },
  { to: '/devices', label: 'Devices', icon: 'devices' },
];

// Org panes appear only when the caller holds their permission; the entry
// button itself shows for anyone matching org.** (server enforces regardless).
const ORG = [
  { to: '/organization', label: 'Dashboard', icon: 'dashboard', end: true, perm: 'org.dashboard' },
  { to: '/organization/users', label: 'Users', icon: 'user', perm: 'org.users.view' },
  { to: '/organization/invites', label: 'Invitations', icon: 'mail', perm: 'org.invites.view' },
  { to: '/organization/roles', label: 'Roles', icon: 'shield-check', perm: 'org.roles.view' },
  { to: '/organization/apps', label: 'Apps', icon: 'appwindow', perm: 'org.apps.view' },
  { to: '/organization/logs', label: 'Logs', icon: 'list', perm: 'org.logs.view' },
];

export default function Sidebar() {
  const { can, canAny } = useAuth();
  const { ssoUrl } = useSite();
  const inOrg = useLocation().pathname.startsWith('/organization');

  return (
    <nav className="side side-drill">
      <div className={'side-track' + (inOrg ? ' org' : '')}>
        <div className="side-pane">
          {PERSONAL.map((it) => (
            <NavLink key={it.to} to={it.to} end={it.end}
              className={({ isActive }) => 'nav' + (isActive ? ' active' : '')}>
              <Icon name={it.icon} size={19} />
              {it.label}
            </NavLink>
          ))}
          {canAny('org.**') && (
            <Link to="/organization" className="nav">
              <Icon name="building" size={19} />
              Organization
              <Icon name="chevron" size={14} className="nav-chev" />
            </Link>
          )}
          <div className="side-spacer" />
          {can('org.siteSettings.sso') && ssoUrl && (
            <a className="nav" href={ssoUrl + '/admin'} target="_blank" rel="noreferrer">
              <Icon name="settings" size={19} />
              Site settings
              <Icon name="external" size={13} className="nav-chev" />
            </a>
          )}
        </div>
        <div className="side-pane">
          <Link to="/" className="nav nav-back">
            <Icon name="arrow-left" size={16} />
            Organization
          </Link>
          {ORG.filter((it) => can(it.perm)).map((it) => (
            <NavLink key={it.to} to={it.to} end={it.end}
              className={({ isActive }) => 'nav' + (isActive ? ' active' : '')}>
              <Icon name={it.icon} size={19} />
              {it.label}
            </NavLink>
          ))}
        </div>
      </div>
    </nav>
  );
}
