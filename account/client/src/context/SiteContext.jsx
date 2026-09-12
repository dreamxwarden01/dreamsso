import { createContext, useContext, useState, useEffect, useCallback } from 'react';

const SiteCtx = createContext(null);

// Site name shared from the SSO (videosite's SiteContext pattern): lazy-init from
// localStorage so returning visitors get the right header + tab title on first
// paint; every successful /api/settings/public (BFF proxy of the SSO's endpoint)
// overwrites the cache. index.html ships an EMPTY <title> — no wrong-name flash.
const SITE_KEY = 'acct:siteName';

function readCachedSiteName() {
  try {
    return localStorage.getItem(SITE_KEY) || '';
  } catch {
    return '';
  }
}

export function SiteProvider({ children }) {
  const [siteName, setSiteName] = useState(readCachedSiteName);
  // null = Turnstile off (or unknown) -> the widget doesn't render.
  const [turnstileSiteKey, setTurnstileSiteKey] = useState(null);
  const [ssoUrl, setSsoUrl] = useState(null); // "Site settings" -> {ssoUrl}/admin
  // Registration flags (fail closed until fetched): drive the /register pages.
  const [registrationEnabled, setRegistrationEnabled] = useState(null); // null = unknown
  const [invitationRequired, setInvitationRequired] = useState(true);

  const refreshSite = useCallback(async () => {
    try {
      const r = await fetch('/api/settings/public', { headers: { accept: 'application/json' } });
      if (!r.ok) return;
      const d = await r.json();
      const name = d.site_name || 'DreamSSO';
      setSiteName(name);
      setTurnstileSiteKey(d.turnstile_site_key ?? null);
      setSsoUrl(d.sso_url ?? null);
      // Only an EXPLICIT false closes the door. A payload without the flag
      // (older SSO, degraded proxy) is UNKNOWN, not "off" — treating absent as
      // false is what turned an upstream hiccup into a "Registration is
      // closed" card. Unknown falls through to the form and lets the SSO's own
      // 403 registration_closed be the authority.
      setRegistrationEnabled(
        typeof d.registration_enabled === 'boolean' ? d.registration_enabled : null,
      );
      setInvitationRequired(d.invitation_required !== false);
      try {
        localStorage.setItem(SITE_KEY, name);
      } catch { /* private mode — cache miss next visit is fine */ }
    } catch {
      /* keep current value on transient failure */
    }
  }, []);

  useEffect(() => {
    refreshSite();
  }, [refreshSite]);

  return (
    <SiteCtx.Provider value={{ siteName, turnstileSiteKey, ssoUrl, registrationEnabled, invitationRequired, refreshSite }}>
      {children}
    </SiteCtx.Provider>
  );
}

export const useSite = () => useContext(SiteCtx);
