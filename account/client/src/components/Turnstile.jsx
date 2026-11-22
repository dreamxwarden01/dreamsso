import { useEffect, useRef, useCallback } from 'react';
import { useSite } from '../context/SiteContext.jsx';

// Registration can retain a completed widget while its request is pending.
// Other flows keep the provider's automatic refresh behavior by default.
export default function Turnstile({ onToken, onExpire, onError, resetRef, active = true,
  manualRefresh = false, paused = false, resetKey = 0 }) {
  const { turnstileSiteKey } = useSite();
  const containerRef = useRef(null), widgetIdRef = useRef(null);
  const callbacks = useRef({ onToken, onExpire, onError });
  const control = useRef({ active, paused, manualRefresh, resetKey });
  const lastReset = useRef(resetKey), refreshNeeded = useRef(false), retryTimer = useRef(null), renderRef = useRef(null);
  callbacks.current = { onToken, onExpire, onError };
  control.current = { active, paused, manualRefresh, resetKey };

  const clearRetry = useCallback(() => { clearTimeout(retryTimer.current); retryTimer.current = null; }, []);
  const reset = useCallback(() => {
    if (!control.current.active || control.current.paused || widgetIdRef.current == null || !window.turnstile) return;
    clearRetry(); refreshNeeded.current = false; lastReset.current = control.current.resetKey;
    if (control.current.manualRefresh) callbacks.current.onExpire?.();
    window.turnstile.reset(widgetIdRef.current);
  }, [clearRetry]);
  useEffect(() => {
    if (resetRef) resetRef.current = reset;
    return () => { if (resetRef?.current === reset) resetRef.current = null; };
  }, [reset, resetRef]);

  useEffect(() => {
    if (!active || !turnstileSiteKey || !containerRef.current) return undefined;
    let alive = true, interval;
    refreshNeeded.current = false; lastReset.current = control.current.resetKey;
    if (!window.turnstile && !document.getElementById('cf-turnstile-script')) {
      const script = document.createElement('script');
      script.id = 'cf-turnstile-script';
      script.src = 'https://challenges.cloudflare.com/turnstile/v0/api.js?render=explicit';
      script.async = true; script.defer = true; document.head.appendChild(script);
    }
    const current = () => alive && control.current.active;
    const expired = () => {
      if (!current()) return;
      if (manualRefresh) refreshNeeded.current = true;
      if (control.current.paused) return;
      if (manualRefresh) reset();
      else callbacks.current.onExpire?.();
    };
    function renderWidget() {
      if (!current() || control.current.paused || widgetIdRef.current != null || !window.turnstile || !containerRef.current) return;
      lastReset.current = control.current.resetKey; refreshNeeded.current = false;
      widgetIdRef.current = window.turnstile.render(containerRef.current, {
        sitekey: turnstileSiteKey,
        ...(manualRefresh ? { retry: 'never', 'refresh-expired': 'never', 'refresh-timeout': 'never' } : {}),
        callback: (token) => {
          if (!current() || control.current.paused) return;
          // A callback queued before an in-place reset cannot restore its old proof.
          const id = widgetIdRef.current;
          if (manualRefresh && id != null && window.turnstile.getResponse(id) !== token) return;
          clearRetry(); refreshNeeded.current = false; callbacks.current.onToken?.(token);
        },
        'expired-callback': expired,
        'timeout-callback': expired,
        'error-callback': () => {
          if (!current()) return;
          if (manualRefresh) refreshNeeded.current = true;
          if (control.current.paused) return;
          callbacks.current.onError?.();
          if (manualRefresh) {
            clearRetry(); retryTimer.current = setTimeout(() => {
              retryTimer.current = null; if (current()) reset();
            }, 8000);
          }
        },
      });
    }
    renderRef.current = renderWidget;
    if (window.turnstile) renderWidget();
    else interval = setInterval(() => {
      if (window.turnstile) { clearInterval(interval); renderWidget(); }
    }, 100);
    // Both immediate and lazy script paths own the same complete cleanup.
    return () => {
      alive = false; clearInterval(interval); clearRetry(); refreshNeeded.current = false;
      if (renderRef.current === renderWidget) renderRef.current = null;
      const id = widgetIdRef.current; widgetIdRef.current = null;
      if (id != null && window.turnstile) {
        try { window.turnstile.remove(id); } catch { /* already removed */ }
      }
    };
  }, [turnstileSiteKey, active, manualRefresh, clearRetry, reset]);

  useEffect(() => {
    if (!active || paused) { clearRetry(); return; }
    if (widgetIdRef.current == null) renderRef.current?.();
    if (manualRefresh && (lastReset.current !== resetKey || refreshNeeded.current && !retryTimer.current)) reset();
  }, [active, paused, manualRefresh, resetKey, clearRetry, reset]);

  if (!turnstileSiteKey || !active) return null;
  return <>
    <div className="turnstile-label">Let us know you are human</div>
    <div ref={containerRef} className="turnstile-box" inert={paused || undefined} />
  </>;
}
