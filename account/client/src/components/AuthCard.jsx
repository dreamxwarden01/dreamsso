import { useEffect } from 'react';
import { useSite } from '../context/SiteContext.jsx';
import Icon from './Icon.jsx';

// Centered signed-out card — the SSO server pages' exact layout (brand badge,
// title, sub, "Protected by …" footer) for the portal's public pages
// (/forgot, /reset, /register/*). Branding comes from settings via
// SiteContext. `cta` renders as a separate boxed strip between the card and
// the footer (the login page's "Sign up" strip pattern).
export default function AuthCard({ docTitle, title, sub, cta, children }) {
  const { siteName } = useSite();
  const name = siteName || 'DreamSSO';

  useEffect(() => {
    if (docTitle) document.title = `${docTitle} · ${name}`;
  }, [docTitle, name]);

  return (
    <div className="auth-body">
      <div className="auth-wrap">
        <div className="auth-card">
          <div className="auth-brand">
            <span className="auth-badge">
              <Icon name="shield-lock" size={24} />
            </span>
            <span className="auth-wordmark">{name}</span>
          </div>
          {title && <h1 className="auth-h1">{title}</h1>}
          {sub && <p className="auth-sub">{sub}</p>}
          {children}
        </div>
        {cta && <div className="auth-cta">{cta}</div>}
        <div className="auth-foot">
          <Icon name="lock" size={12} />
          Protected by {name}
        </div>
      </div>
    </div>
  );
}
