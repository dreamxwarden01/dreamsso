import { useEffect, useLayoutEffect, useRef } from 'react';
import { createAuthCardMotion } from './authCardMotion.js';
import { useSite } from '../context/SiteContext.jsx';
import Icon from './Icon.jsx';

// Centered signed-out card — the SSO server pages' exact layout (brand badge,
// title, sub, "Protected by …" footer) for the portal's public pages
// (/forgot, /reset, /register/*). Branding comes from settings via
// SiteContext. `cta` renders as a separate boxed strip between the card and
// the footer (the login page's "Sign up" strip pattern).
export default function AuthCard({ docTitle, title, sub, cta, children, motionKey }) {
  const { siteName } = useSite();
  const name = siteName || 'DreamSSO';
  const wrap = useRef(null), card = useRef(null), surface = useRef(null), content = useRef(null);
  const main = useRef(null), ctaNode = useRef(null), foot = useRef(null), motion = useRef(null);
  const enabled = motionKey !== undefined;
  useLayoutEffect(() => {
    if (!enabled) return undefined;
    const current = createAuthCardMotion(() => ({ wrap: wrap.current, card: card.current,
      surface: surface.current, content: content.current, main: main.current, cta: ctaNode.current, foot: foot.current }));
    motion.current = current;
    return () => { current.destroy(); motion.current = null; };
  }, [enabled]);
  useLayoutEffect(() => { motion.current?.update(motionKey); });

  useEffect(() => {
    if (docTitle) document.title = `${docTitle} · ${name}`;
  }, [docTitle, name]);

  return (
    <div className="auth-body">
      <div className="auth-wrap" ref={wrap}>
        <div className="auth-card auth-card-motion" ref={card}>
          <div className="auth-card-surface" ref={surface} aria-hidden="true" />
          <div className="auth-card-content" ref={content}>
          <div className="auth-brand">
            <span className="auth-badge">
              <Icon name="shield-lock" size={24} />
            </span>
            <span className="auth-wordmark">{name}</span>
          </div>
          <div className="auth-card-main" ref={main}>
          {title && <h1 className="auth-h1">{title}</h1>}
          {sub && <p className="auth-sub">{sub}</p>}
          {children}
          </div>
          </div>
        </div>
        {cta && <div className="auth-cta" ref={ctaNode}>{cta}</div>}
        <div className="auth-foot" ref={foot}>
          <Icon name="lock" size={12} />
          Protected by {name}
        </div>
      </div>
    </div>
  );
}
