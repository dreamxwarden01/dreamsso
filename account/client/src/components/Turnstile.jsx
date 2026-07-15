import { useEffect, useRef, useCallback } from 'react';
import { useSite } from '../context/SiteContext.jsx';

// Cloudflare Turnstile widget — ported from videosite's Turnstile.jsx, plus
// lazy script loading (only the public /forgot page needs it, so the bundle
// doesn't ship the loader tag globally). Auto-refresh comes from the widget's
// own expired-callback: the token is cleared (button greys) and Turnstile
// re-runs; resetRef lets the page force a fresh token after a failed submit.
//   onToken(token)  — token received
//   onExpire()      — token expired (widget refreshes itself)
//   onError()       — widget error
//   resetRef        — mutable ref; set to a reset fn for external resets
export default function Turnstile({ onToken, onExpire, onError, resetRef }) {
  const { turnstileSiteKey } = useSite();
  const containerRef = useRef(null);
  const widgetIdRef = useRef(null);

  const reset = useCallback(() => {
    if (widgetIdRef.current != null && window.turnstile) {
      window.turnstile.reset(widgetIdRef.current);
    }
  }, []);

  useEffect(() => {
    if (resetRef) resetRef.current = reset;
  }, [reset, resetRef]);

  useEffect(() => {
    if (!turnstileSiteKey || !containerRef.current) return;

    if (!window.turnstile && !document.getElementById('cf-turnstile-script')) {
      const s = document.createElement('script');
      s.id = 'cf-turnstile-script';
      s.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      s.async = true;
      s.defer = true;
      document.head.appendChild(s);
    }

    function renderWidget() {
      if (!window.turnstile || !containerRef.current) return;
      if (widgetIdRef.current != null) {
        try { window.turnstile.remove(widgetIdRef.current); } catch { /* already gone */ }
      }
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: turnstileSiteKey,
        callback: (token) => onToken?.(token),
        'expired-callback': () => onExpire?.(),
        'error-callback': () => onError?.(),
      });
    }

    if (window.turnstile) {
      renderWidget();
    } else {
      const interval = setInterval(() => {
        if (window.turnstile) {
          clearInterval(interval);
          renderWidget();
        }
      }, 100);
      return () => clearInterval(interval);
    }

    return () => {
      if (widgetIdRef.current != null && window.turnstile) {
        try { window.turnstile.remove(widgetIdRef.current); } catch { /* already gone */ }
        widgetIdRef.current = null;
      }
    };
  }, [turnstileSiteKey]); // eslint-disable-line react-hooks/exhaustive-deps

  if (!turnstileSiteKey) return null;

  // The label shows the moment we know the widget WILL render (site key set),
  // not after the script loads — the user sees it above the placeholder area.
  return (
    <>
      <div className="turnstile-label">Let us know you are human</div>
      <div ref={containerRef} className="turnstile-box" />
    </>
  );
}
