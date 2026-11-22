import { useEffect, useRef, useCallback } from 'react';
import { useSite } from '../context/SiteContext.jsx';

// A widget exists only while its protected operation can be attempted. Removing
// it also stops its automatic refresh; the caller discards a submitted token.
export default function Turnstile({ onToken, onExpire, onError, resetRef, active = true }) {
  const { turnstileSiteKey } = useSite();
  const containerRef = useRef(null), widgetIdRef = useRef(null);
  const callbacks = useRef({ onToken, onExpire, onError });
  const activeRef = useRef(active);
  callbacks.current = { onToken, onExpire, onError }; activeRef.current = active;

  const reset = useCallback(() => {
    if (activeRef.current && widgetIdRef.current != null && window.turnstile) window.turnstile.reset(widgetIdRef.current);
  }, []);
  useEffect(() => {
    if (resetRef) resetRef.current = reset;
    return () => { if (resetRef?.current === reset) resetRef.current = null; };
  }, [reset, resetRef]);

  useEffect(() => {
    if (!active || !turnstileSiteKey || !containerRef.current) return undefined;
    let alive = true, interval;
    if (!window.turnstile && !document.getElementById('cf-turnstile-script')) {
      const script = document.createElement('script');
      script.id = 'cf-turnstile-script';
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true; script.defer = true; document.head.appendChild(script);
    }
    function renderWidget() {
      if (!alive || !activeRef.current || !window.turnstile || !containerRef.current) return;
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: turnstileSiteKey,
        callback: (token) => { if (alive && activeRef.current) callbacks.current.onToken?.(token); },
        'expired-callback': () => { if (alive && activeRef.current) callbacks.current.onExpire?.(); },
        'error-callback': () => { if (alive && activeRef.current) callbacks.current.onError?.(); },
        'timeout-callback': () => { if (alive && activeRef.current) callbacks.current.onExpire?.(); },
      });
    }
    if (window.turnstile) renderWidget();
    else interval = setInterval(() => {
      if (window.turnstile) { clearInterval(interval); renderWidget(); }
    }, 100);
    // Both immediate and lazy script paths own the same complete cleanup.
    return () => {
      alive = false; clearInterval(interval);
      const id = widgetIdRef.current; widgetIdRef.current = null;
      if (id != null && window.turnstile) {
        try { window.turnstile.remove(id); } catch { /* already removed */ }
      }
    };
  }, [turnstileSiteKey, active]);

  if (!turnstileSiteKey || !active) return null;
  return <>
    <div className="turnstile-label">Let us know you are human</div>
    <div ref={containerRef} className="turnstile-box" />
  </>;
}
