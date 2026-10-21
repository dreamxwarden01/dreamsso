import { createContext, useContext, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createSaveFeedback } from './saveFeedback.js';

export function useSaveFeedback() {
  const [state, setState] = useState('idle');
  const cycle = useRef(null);
  if (!cycle.current) cycle.current = createSaveFeedback({ emit: setState });
  useEffect(() => () => cycle.current.dispose(), []);
  return { state, ...cycle.current };
}

export const ClientErrorContext = createContext({});
export function ErrorInput({ as: Tag = 'input', errorKey, ...props }) {
  const marks = useContext(ClientErrorContext);
  const mark = marks[errorKey];
  if (!errorKey) return <Tag {...props} />;
  return <span className={'rp-input-wrap' + (Tag === 'textarea' ? ' rp-textarea-wrap' : '')}>
    <Tag {...props} data-error-key={errorKey} aria-invalid={mark ? true : undefined}
      aria-describedby={mark?.id} className={(props.className || '') + (mark ? ' bad rp-marked' : '')} />
    {mark && <span className="rp-field-mark" aria-hidden="true">{mark.number}</span>}
  </span>;
}

export function ErrorGroup({ errorKey, children, className = '' }) {
  const mark = useContext(ClientErrorContext)[errorKey];
  return <div className={className + (mark ? ' rp-error-group' : '')} data-error-key={errorKey}
    tabIndex={-1} aria-invalid={mark ? true : undefined} aria-describedby={mark?.id}>
    {children}{mark && <span className="rp-group-mark" aria-hidden="true">{mark.number}</span>}
  </div>;
}

// Keep enough document height when content below the button retracts. Returning
// space only below the viewport prevents bottom-scroll clamping from moving it.
export function useScrollReserve() {
  const spacer = useRef(null);
  const reserved = useRef(0);
  const until = useRef(0);
  const timers = useRef(new Set());
  const release = () => {
    if (!spacer.current || performance.now() < until.current) return;
    const below = Math.floor(document.documentElement.scrollHeight - (scrollY + innerHeight));
    reserved.current = Math.max(0, reserved.current - Math.max(0, below));
    spacer.current.style.height = `${reserved.current}px`;
  };
  const reserve = (element, duration) => {
    if (!element || !spacer.current) return;
    reserved.current += element.getBoundingClientRect().height;
    spacer.current.style.height = `${reserved.current}px`;
    const reduced = matchMedia('(prefers-reduced-motion: reduce)').matches;
    until.current = Math.max(until.current, performance.now() + (reduced ? 0 : duration) + 40);
    const timer = setTimeout(() => { timers.current.delete(timer); release(); }, (reduced ? 0 : duration) + 60);
    timers.current.add(timer);
  };
  useEffect(() => {
    let raf = 0;
    const changed = () => {
      if (!raf) raf = requestAnimationFrame(() => { raf = 0; release(); });
    };
    addEventListener('scroll', changed, { passive: true });
    addEventListener('resize', changed);
    return () => {
      removeEventListener('scroll', changed);
      removeEventListener('resize', changed);
      cancelAnimationFrame(raf);
      timers.current.forEach(clearTimeout);
      timers.current.clear();
    };
  }, []);
  return { spacer, reserve, release };
}

export function SaveButton({ state, label, disabled, onClick, describedBy }) {
  return <button className="btn btn-primary rp-submit" data-state={state} onClick={onClick}
    disabled={state === 'idle' && disabled} aria-disabled={state !== 'idle'} aria-describedby={describedBy}>
    <span className="rp-button-label">{label}</span>
    <span className="rp-button-spinner" aria-hidden="true"><i className="rp-spinner" /><i className="rp-static-busy">•••</i></span>
    <span className="rp-button-success" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 16 16"><path d="m3.5 8.5 3 3 6-6.5" /></svg></span>
    <span className="rp-button-error" aria-hidden="true"><svg width="16" height="16" viewBox="0 0 16 16"><path d="m4.5 4.5 7 7m0-7-7 7" /></svg></span>
  </button>;
}

export function OutcomePanel({ open, title, children, technical, reserve, release }) {
  const panel = useRef(null);
  const technicalBody = useRef(null);
  const wasOpen = useRef(false);
  const [details, setDetails] = useState(false);
  // Keep the previous panel's actual DOM content while it collapses.
  const lastContent = useRef({ title, children, technical });
  if (open) lastContent.current = { title, children, technical };
  const content = open ? { title, children, technical } : lastContent.current;
  // Reserve the currently rendered height before changing the CSS grid state.
  useLayoutEffect(() => {
    if (wasOpen.current && !open) reserve(panel.current, 180);
    if (!open) setDetails(false);
    if (panel.current) panel.current.dataset.open = String(open);
    wasOpen.current = open;
  }, [open]);
  useEffect(() => {
    if (!open) return;
    const timer = setTimeout(release, 280);
    return () => clearTimeout(timer);
  }, [open]);
  return <div ref={panel} className="rp-outcome" inert={!open}>
    <div className="rp-outcome-clip"><div className="rp-outcome-pad"><section className="rp-outcome-panel" aria-labelledby="rp-outcome-title">
      <p className="rp-outcome-title" id="rp-outcome-title">{content.title}</p>
      {content.children}
      {content.technical && <div className="rp-technical" data-open={details}>
        <button className="rp-technical-toggle" type="button" aria-expanded={details} aria-controls="rp-technical-body"
          onClick={() => {
            if (details) reserve(technicalBody.current, 120);
            setDetails(!details);
          }}><span className="rp-technical-arrow" aria-hidden="true">›</span>Technical details</button>
        <div className="rp-technical-body" id="rp-technical-body" ref={technicalBody} inert={!details}
          onTransitionEnd={release}><div className="rp-technical-clip"><pre>{content.technical}</pre></div></div>
      </div>}
    </section></div></div>
  </div>;
}
