import { useEffect, useRef, useState } from 'react';
import { initials } from './Avatar.jsx';

// The cross-app profile dropdown: [avatar][display name] trigger on the header
// right; panel = org name + Sign out on top, big avatar + name/email (+ View
// account where the app isn't the portal itself) below. Click-outside and
// Escape close it.
export default function ProfileMenu({ name, email, picture, orgName, viewAccountHref, onSignOut }) {
  const [open, setOpen] = useState(false);
  const ref = useRef(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e) => {
      if (ref.current && !ref.current.contains(e.target)) setOpen(false);
    };
    const onKey = (e) => {
      if (e.key === 'Escape') setOpen(false);
    };
    document.addEventListener('click', onDoc);
    document.addEventListener('keydown', onKey);
    return () => {
      document.removeEventListener('click', onDoc);
      document.removeEventListener('keydown', onKey);
    };
  }, [open]);

  const av = (cls) =>
    picture ? <img className={cls} src={picture} alt="" /> : <div className={cls}>{initials(name)}</div>;

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
            <button className="pmenu-signout" onClick={onSignOut}>
              Sign out
            </button>
          </div>
          <div className="pmenu-body">
            {av('pmenu-av')}
            <div className="pmenu-info">
              <p className="pmenu-name">{name}</p>
              {email && <p className="pmenu-email">{email}</p>}
              {viewAccountHref && (
                <a className="pmenu-link" href={viewAccountHref} target="_blank" rel="noreferrer">
                  View account
                </a>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
