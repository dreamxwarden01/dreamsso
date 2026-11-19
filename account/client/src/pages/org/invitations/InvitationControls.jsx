import React, { createContext, forwardRef, useCallback, useContext, useEffect, useId, useImperativeHandle, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import InvitationIcon from './InvitationIcon.jsx';
import { formatInvitationTime, manualPage, pageSlots, relativeInvitationTime } from './invitationModel.js';

const duration = (n) => matchMedia('(prefers-reduced-motion: reduce)').matches ? 0 : n;
export function useInvitationFeedback() {
  const [phase, setPhase] = useState('idle'), locked = useRef(false), generation = useRef(0), timers = useRef(new Set()), mounted = useRef(true);
  const clear = useCallback(() => { generation.current++; timers.current.forEach(clearTimeout); timers.current.clear(); locked.current = false; }, []);
  const later = (ms, fn) => { const g = generation.current, t = setTimeout(() => { timers.current.delete(t); if (g === generation.current) fn(); }, ms); timers.current.add(t); };
  useEffect(() => { mounted.current = true; return () => { mounted.current = false; clear(); }; }, [clear]);
  return { phase, reset() { clear(); setPhase('idle'); },
    begin() { if (!mounted.current || locked.current) return false; clear(); locked.current = true; setPhase('busy'); return true; },
    finish(outcome, afterHold) { if (!mounted.current) return; setPhase(outcome); later(2000, () => { setPhase('fading'); later(240, () => { locked.current = false; setPhase('idle'); }); }); if (afterHold) later(2050, afterHold); },
  };
}
function FeedbackMark({ kind }) {
  if (kind === 'spin') return <svg viewBox="0 0 16 16" aria-hidden="true"><g className="iv-ring"><circle cx="8" cy="8" r="6" fill="none" stroke="currentColor" strokeOpacity=".22" strokeWidth="1.8"/><path d="M8 2a6 6 0 0 1 6 6" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"/></g><g className="iv-dots" fill="currentColor"><circle cx="3.5" cy="8" r="1.4"/><circle cx="8" cy="8" r="1.4"/><circle cx="12.5" cy="8" r="1.4"/></g></svg>;
  return <svg viewBox="0 0 16 16" aria-hidden="true"><path d={kind === 'check' ? 'M3.5 8.4 6.6 11.4 12.6 5' : 'M4.5 4.5l7 7M11.5 4.5l-7 7'} fill="none" stroke="currentColor" strokeWidth="1.9" strokeLinecap="round" strokeLinejoin="round"/></svg>;
}
export function InvitationButton({ label, phase = 'idle', busyLabel = 'Working…', doneLabel = 'Done', failLabel = 'Try again', icon, className = '', iconOnly = false, onClick, disabled, type = 'button' }) {
  const rest = phase === 'idle' || phase === 'fading';
  return <button type={type} className={'iv-btn iv-action-feedback ' + className} data-phase={phase}
    disabled={disabled && rest} aria-disabled={!rest || disabled || undefined} aria-busy={phase === 'busy'}
    aria-label={iconOnly ? (rest ? label : phase === 'busy' ? busyLabel : phase === 'done' ? doneLabel : failLabel) : undefined}
    onClick={onClick}>
    <span className="iv-fb-slot" aria-hidden="true">
      {icon && <span className={'iv-fb-i' + (rest ? ' iv-on' : '')}><InvitationIcon name={icon}/></span>}
      <span className={'iv-fb-i iv-fb-spin' + (phase === 'busy' ? ' iv-on' : '')}><FeedbackMark kind="spin"/></span>
      <span className={'iv-fb-i iv-fb-check' + (phase === 'done' ? ' iv-on' : '')}><FeedbackMark kind="check"/></span>
      <span className={'iv-fb-i iv-fb-cross' + (phase === 'fail' ? ' iv-on' : '')}><FeedbackMark kind="cross"/></span>
    </span>
    <span className="iv-fb-label" aria-hidden={iconOnly || undefined}>
      <span className={rest || iconOnly ? 'iv-on' : ''}>{label}</span>
      {!iconOnly && <><span className={phase === 'busy' ? 'iv-on' : ''}>{busyLabel}</span><span className={phase === 'done' ? 'iv-on' : ''}>{doneLabel}</span><span className={phase === 'fail' ? 'iv-on' : ''}>{failLabel}</span></>}
    </span>
  </button>;
}
export function CopyInvitationButton({ text, label, className = '', icon = 'copy' }) {
  const feedback = useInvitationFeedback(), [error, setError] = useState(false);
  const copy = async () => {
    if (!feedback.begin()) return; setError(false); let copied = false;
    try { if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); copied = true; } } catch { /* fallback below */ }
    if (!copied) {
      const previous = document.activeElement, field = document.createElement('textarea');
      field.value = text; field.readOnly = true; field.style.cssText = 'position:fixed;top:-1000px;opacity:0'; document.body.append(field);
      try { field.select(); copied = document.execCommand('copy'); } catch { /* keep visible value available */ } finally { field.remove(); previous?.isConnected && previous.focus({ preventScroll: true }); }
    }
    feedback.finish(copied ? 'done' : 'fail'); setError(!copied);
  };
  return <><InvitationButton label={label} phase={feedback.phase} busyLabel="Copying…" doneLabel="Copied" failLabel="Not copied" icon={icon} className={className} onClick={copy}/>{error && <span className="iv-sr-only" role="alert">Couldn’t copy automatically. Select the visible value and copy it.</span>}</>;
}

export function InvitationPicker({ label, value, options, onChange, id, block = false, disabled = false }) {
  const generated = useId(), menuId = id ? id + '-menu' : generated;
  const trigger = useRef(null), menu = useRef(null), timer = useRef(null), [open, setOpen] = useState(false), [closing, setClosing] = useState(false);
  const close = useCallback((restore = false) => {
    if (restore || menu.current?.contains(document.activeElement)) trigger.current?.focus({ preventScroll: true });
    setOpen(false); setClosing(true); clearTimeout(timer.current); timer.current = setTimeout(() => setClosing(false), duration(100));
  }, []);
  const place = useCallback(() => {
    if (!menu.current || !trigger.current) return;
    const vv = window.visualViewport, r = trigger.current.getBoundingClientRect(), left = vv?.offsetLeft || 0, top = vv?.offsetTop || 0, width = vv?.width || innerWidth, height = vv?.height || innerHeight;
    const m = menu.current; m.style.width = Math.max(0, Math.min(Math.max(r.width, 220), width - 16)) + 'px'; m.style.maxHeight = '';
    const natural = m.scrollHeight + 2, below = Math.max(0, top + height - r.bottom - 14), above = Math.max(0, r.top - top - 14), up = below < natural && above > below;
    const max = Math.max(0, Math.min(height - 16, up ? above : below)), mh = Math.min(natural, max);
    m.style.maxHeight = max + 'px'; m.style.top = Math.max(top + 8, Math.min(up ? r.top - mh - 6 : r.bottom + 6, top + height - mh - 8)) + 'px';
    m.style.left = Math.max(left + 8, Math.min(r.left, left + width - m.offsetWidth - 8)) + 'px';
  }, []);
  const focusRow = (index) => {
    const rows = [...(menu.current?.querySelectorAll('[role=option]') || [])], row = rows[index]; if (!row) return;
    rows.forEach((r) => { r.tabIndex = r === row ? 0 : -1; }); row.focus({ preventScroll: true });
    const box = menu.current.getBoundingClientRect(), rect = row.getBoundingClientRect();
    if (rect.top < box.top + 4) menu.current.scrollTop -= box.top + 4 - rect.top;
    else if (rect.bottom > box.bottom - 4) menu.current.scrollTop += rect.bottom - box.bottom + 4;
  };
  useLayoutEffect(() => { if (open) { place(); const index = options.findIndex((o) => o.value === value); focusRow(Math.max(0, index)); } }, [open, place]);
  useEffect(() => {
    if (!open) return undefined;
    const outside = (e) => { if (!menu.current?.contains(e.target) && !trigger.current?.contains(e.target)) close(); };
    const scroll = (e) => { if (menu.current?.contains(e.target)) return; const r = trigger.current?.getBoundingClientRect(); if (!r || r.bottom < 0 || r.top > innerHeight) close(); else place(); };
    const hidden = () => { if (document.hidden) close(); }, hide = () => close();
    document.addEventListener('pointerdown', outside, true); document.addEventListener('focusin', outside); document.addEventListener('visibilitychange', hidden);
    window.addEventListener('resize', place); window.addEventListener('scroll', scroll, true); window.addEventListener('pagehide', hide);
    window.visualViewport?.addEventListener('resize', place); window.visualViewport?.addEventListener('scroll', place);
    return () => { document.removeEventListener('pointerdown', outside, true); document.removeEventListener('focusin', outside); document.removeEventListener('visibilitychange', hidden);
      window.removeEventListener('resize', place); window.removeEventListener('scroll', scroll, true); window.removeEventListener('pagehide', hide);
      window.visualViewport?.removeEventListener('resize', place); window.visualViewport?.removeEventListener('scroll', place); };
  }, [open, close, place]);
  useEffect(() => { if (disabled && open) close(); }, [disabled, open, close]);
  useEffect(() => () => clearTimeout(timer.current), []);
  const key = (e) => {
    if (e.isComposing) return;
    if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(true); }
    else if (e.key === 'Tab') close(true);
    else if (!e.altKey && !e.ctrlKey && !e.metaKey) {
      const rows = [...menu.current.querySelectorAll('[role=option]')], i = rows.indexOf(document.activeElement), n = rows.length;
      const next = e.key === 'ArrowDown' ? (i + 1) % n : e.key === 'ArrowUp' ? (i - 1 + n) % n : e.key === 'Home' ? 0 : e.key === 'End' ? n - 1 : null;
      if (next !== null) { e.preventDefault(); focusRow(next); }
    }
  };
  return <div className={'iv-settings-picker' + (block ? ' iv-block' : '')}>
    <button ref={trigger} id={id} type="button" disabled={disabled} className={'iv-settings-picker-trigger' + (block ? ' iv-block' : '')}
      aria-label={`${label}: ${options.find((o) => o.value === value)?.label || 'Choose'}`} aria-haspopup="listbox" aria-expanded={open} aria-controls={open ? menuId : undefined}
      onKeyDown={(e) => { if (['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) { e.preventDefault(); clearTimeout(timer.current); setClosing(false); setOpen(true); } }}
      onClick={() => { if (open) close(true); else { clearTimeout(timer.current); setClosing(false); setOpen(true); } }}>
      <span>{options.find((o) => o.value === value)?.label || 'Choose'}</span><InvitationIcon name="chev" className="iv-settings-chevron"/>
    </button>
    {(open || closing) && createPortal(<div ref={menu} id={menuId} className={'iv-ui iv-settings-picker-menu' + (closing ? ' iv-closing' : '')}
      role="listbox" aria-label={label} aria-hidden={!open} inert={!open} onKeyDown={key}>
      {options.map((o) => <button type="button" role="option" tabIndex={-1} aria-selected={o.value === value} key={o.value}
        onClick={() => { if (!open) return; close(true); if (o.value !== value) onChange(o.value); }}>
        <span className="iv-opt-main"><span className="iv-opt-label">{o.label}</span>{o.desc && <span className="iv-opt-desc">{o.desc}</span>}</span><span className="iv-opt-check" aria-hidden="true">{o.value === value ? '✓' : ''}</span>
      </button>)}
    </div>, document.body)}
  </div>;
}

export const InvitationModal = forwardRef(function InvitationModal({ labelId, busy = false, create = false, initialFocus, onClose, children }, ref) {
  const overlay = useRef(null), dialog = useRef(null), opener = useRef(document.activeElement), busyRef = useRef(busy), callback = useRef(onClose), timer = useRef(null), leaving = useRef(false), down = useRef(false);
  busyRef.current = busy; callback.current = onClose;
  const close = useCallback((force = false) => {
    if (leaving.current || busyRef.current && !force) return;
    leaving.current = true; const ms = duration(140);
    overlay.current?.animate?.([{ opacity: 1 }, { opacity: 0 }], { duration: ms, fill: 'forwards' });
    dialog.current?.animate?.([{ transform: 'none' }, { transform: 'scale(.98)' }], { duration: ms, fill: 'forwards' });
    timer.current = setTimeout(() => callback.current(), ms);
  }, []);
  useImperativeHandle(ref, () => ({ close: () => close(true) }), [close]);
  useLayoutEffect(() => {
    const previousOverflow = document.body.style.overflow, page = document.querySelector('.iv-page');
    const oldInert = page?.inert; if (page) page.inert = true; document.body.style.overflow = 'hidden';
    overlay.current?.animate?.([{ opacity: 0 }, { opacity: 1 }], { duration: duration(160) });
    dialog.current?.animate?.([{ opacity: 0, transform: 'scale(.97)' }, { opacity: 1, transform: 'none' }], { duration: duration(170) });
    const focusables = () => [...dialog.current.querySelectorAll('button,input,textarea,a[href],[tabindex]:not([tabindex="-1"])')].filter((n) => !n.disabled && n.getClientRects().length);
    (initialFocus?.current || focusables()[0])?.focus({ preventScroll: true });
    const key = (e) => {
      // Existing organization step-up overlays retain priority and own Escape.
      if (document.querySelector('.ch-scrim')) return;
      if (e.key === 'Escape') { e.preventDefault(); close(); return; }
      if (e.key !== 'Tab') return;
      const nodes = focusables(), first = nodes[0], last = nodes.at(-1); if (!first) { e.preventDefault(); return; }
      if (!dialog.current.contains(document.activeElement)) { e.preventDefault(); first.focus(); }
      else if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    };
    document.addEventListener('keydown', key);
    return () => { clearTimeout(timer.current); document.removeEventListener('keydown', key); document.body.style.overflow = previousOverflow; if (page) page.inert = oldInert;
      const target = opener.current?.isConnected ? opener.current : document.querySelector('.iv-seg [aria-pressed=true]') || document.querySelector('.iv-new-btn'); target?.focus({ preventScroll: true }); };
  }, [close]);
  return createPortal(<div ref={overlay} className="iv-ui iv-modal-overlay" onPointerDown={(e) => { down.current = e.target === e.currentTarget; }}
    onClick={(e) => { if (e.target === e.currentTarget && down.current) close(); }}>
    <div ref={dialog} className={'iv-modal' + (create ? ' iv-modal-create' : '')} role="dialog" aria-modal="true" aria-labelledby={labelId}>{children}</div>
  </div>, document.body);
});

export function InvitationPager({ data, wantedPage, onPage, position }) {
  const root = useRef(null), controls = useRef(null), win = useRef(null), manual = useRef(null), input = useRef(null), focusPage = useRef(null);
  const [draft, setDraft] = useState(null), [fit, setFit] = useState({ two: false, hidden: false });
  const pages = data?.pages ?? 1, page = data?.page ?? 1, total = data?.total ?? null, size = data?.pageSize ?? 10;
  const digits = String(pages).length, slots = pageSlots(page, pages);
  const fitNow = useCallback(() => {
    if (!root.current?.clientWidth || !win.current || !manual.current) return;
    if (matchMedia('(max-width:600px)').matches) { setFit((v) => v.two || v.hidden ? { two: false, hidden: false } : v); return; }
    win.current.style.display = 'grid'; const width = win.current.getBoundingClientRect().width; win.current.style.display = '';
    const next = { two: 80 + width + manual.current.getBoundingClientRect().width + 56 + 18 > root.current.clientWidth, hidden: width > root.current.clientWidth };
    setFit((v) => v.two === next.two && v.hidden === next.hidden ? v : next);
  }, []);
  useLayoutEffect(() => { fitNow(); }, [pages, fitNow]);
  useEffect(() => { const observer = new ResizeObserver(fitNow); observer.observe(root.current); return () => observer.disconnect(); }, [fitNow]);
  useLayoutEffect(() => {
    if (focusPage.current !== null && win.current.contains(document.activeElement)) {
      const buttons = [...win.current.querySelectorAll('button[data-page]')], target = buttons.find((n) => !n.hidden && Number(n.dataset.page) === focusPage.current) || buttons.find((n) => n.getAttribute('aria-current') === 'page');
      target?.focus({ preventScroll: true });
    }
  }, [page, pages]);
  const commit = () => { const next = manualPage(draft ?? wantedPage, wantedPage, pages); setDraft(null); if (total !== null) onPage(next); };
  const displayed = draft === null ? String(wantedPage) : draft;
  return <nav ref={root} className={'iv-pager' + (fit.two ? ' iv-pager-two-row' : '') + (fit.hidden ? ' iv-pager-window-hidden' : '')}
    aria-label={position + ' invitation pagination'} style={{ '--d': digits, '--sum': `${(total ?? 0).toLocaleString()}–${(total ?? 0).toLocaleString()} of ${(total ?? 0).toLocaleString()}`.length }}>
    <span className="iv-page-summary">{total === null ? 'Invitations loading…' : total ? `${((page - 1) * size + 1).toLocaleString()}–${Math.min(page * size, total).toLocaleString()} of ${total.toLocaleString()}` : '0 invitations'}</span>
    <div ref={controls} className="iv-page-controls">
      <button type="button" className="iv-btn iv-page-prev" aria-disabled={wantedPage <= 1 || total === null} onClick={(e) => { if (e.detail <= 1 && wantedPage > 1 && total !== null) onPage(wantedPage - 1); }}>Previous</button>
      <span ref={win} className="iv-page-window" aria-label="Nearby pages" style={{ '--cells': slots.length }}>
        {Array.from({ length: 7 }, (_, i) => <span className="iv-page-cell" hidden={i >= slots.length} key={i}>
          <button type="button" hidden={slots[i] == null} className="iv-btn iv-page-num" data-page={slots[i] ?? undefined} aria-current={slots[i] === page ? 'page' : undefined}
            onFocus={() => { focusPage.current = slots[i]; }} onBlur={(e) => { if (e.relatedTarget && !win.current?.contains(e.relatedTarget)) focusPage.current = null; }}
            onClick={(e) => { if (e.detail <= 1 && slots[i] != null && total !== null) onPage(slots[i]); }}>{slots[i]}</button><span className="iv-page-gap" hidden={slots[i] != null} aria-hidden="true">…</span>
        </span>)}
      </span>
      <form ref={manual} className="iv-page-manual" noValidate onSubmit={(e) => { e.preventDefault(); commit(); }}>
        <label>Page <input ref={input} className="iv-input" type="text" inputMode="numeric" pattern="[0-9]*" enterKeyHint="go" autoComplete="off" maxLength={digits}
          aria-label={'Go to page, ' + position + ' pagination'} value={displayed} onChange={(e) => setDraft(e.target.value.replace(/\D/g, ''))} onBlur={() => { if (draft !== null) commit(); }}/></label><span>of {pages}</span>
      </form>
      <button type="button" className="iv-btn iv-page-next" aria-disabled={wantedPage >= pages || total === null} onClick={(e) => { if (e.detail <= 1 && wantedPage < pages && total !== null) onPage(wantedPage + 1); }}>Next</button>
    </div>
  </nav>;
}

const TimeContext = createContext({ show() {}, close() {}, hold() {}, now: Date.now(), activeAnchor: null, tooltipId: '' });
export function InvitationTimeProvider({ children }) {
  const [shown, setShown] = useState(null), [closing, setClosing] = useState(false), [now, setNow] = useState(Date.now());
  const tooltip = useRef(null), hideTimer = useRef(null), closeTimer = useRef(null), motion = useRef(null), active = useRef(null), tooltipId = 'iv-exact-' + useId();
  const close = useCallback((immediate = true) => {
    clearTimeout(hideTimer.current); clearTimeout(closeTimer.current); active.current = null; motion.current?.cancel();
    if (immediate || !tooltip.current) { setShown(null); setClosing(false); return; }
    const node = tooltip.current, style = getComputedStyle(node), opacity = style.opacity, transform = style.transform;
    node.style.opacity = '0'; node.style.transform = 'translateY(4px)'; setClosing(true);
    const ms = duration(150); motion.current = node.animate?.([{ opacity, transform }, { opacity: 0, transform: 'translateY(4px)' }], { duration: ms, easing: 'cubic-bezier(.2,0,0,1)', fill: 'forwards' });
    closeTimer.current = setTimeout(() => { setShown(null); setClosing(false); }, ms);
  }, []);
  const release = useCallback(() => { clearTimeout(hideTimer.current); hideTimer.current = setTimeout(() => { const v = active.current; if (v && !v.pinned && !v.hover && !v.focus && !v.tip) close(false); }, 60); }, [close]);
  const show = useCallback((anchor, timestamp, reason) => {
    if (!anchor?.isConnected) return;
    clearTimeout(hideTimer.current); clearTimeout(closeTimer.current); motion.current?.cancel();
    let next = active.current?.anchor === anchor ? active.current : { anchor, timestamp, pinned: false, hover: false, focus: false, tip: false };
    if (reason === 'activate' && next.pinned) { close(false); return; }
    next = { ...next, timestamp, ...(reason === 'hover' ? { hover: true } : {}), ...(reason === 'focus' ? { focus: true } : {}), ...(reason === 'activate' ? { pinned: true } : {}) };
    active.current = next; setShown(next); setClosing(false);
  }, [close]);
  useLayoutEffect(() => {
    if (!shown || closing || !tooltip.current) return undefined;
    const place = () => {
      const a = active.current?.anchor, tip = tooltip.current; if (!a?.isConnected || !a.getClientRects().length || !tip) { close(); return; }
      const r = a.getBoundingClientRect(), vv = window.visualViewport, left = vv?.offsetLeft || 0, top = vv?.offsetTop || 0, width = vv?.width || innerWidth, height = vv?.height || innerHeight;
      if (r.bottom < top || r.top > top + height || r.right < left || r.left > left + width) { close(); return; }
      tip.style.maxWidth = Math.max(0, width - 16) + 'px'; const box = tip.getBoundingClientRect();
      let y = r.top - box.height - 6; if (y < top + 8) y = r.bottom + 6;
      tip.style.left = Math.max(left + 8, Math.min(r.left + r.width / 2 - box.width / 2, left + width - box.width - 8)) + 'px';
      tip.style.top = Math.max(top + 8, Math.min(y, top + height - box.height - 8)) + 'px';
    };
    place();
    if (!active.current) return undefined;
    const tip = tooltip.current, style = getComputedStyle(tip), opacity = style.opacity, transform = style.transform;
    tip.style.opacity = '1'; tip.style.transform = 'translateY(0)';
    motion.current = tip.animate?.([{ opacity, transform }, { opacity: 1, transform: 'translateY(0)' }], { duration: duration(200), easing: 'cubic-bezier(.2,0,0,1)' });
    const outside = (e) => { if (!shown.anchor.contains(e.target) && !tooltip.current?.contains(e.target)) close(false); };
    const key = (e) => { if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); close(false); } };
    const hidden = () => { if (document.hidden) close(); };
    document.addEventListener('pointerdown', outside, true); document.addEventListener('focusin', outside, true); document.addEventListener('keydown', key, true); document.addEventListener('visibilitychange', hidden);
    window.addEventListener('scroll', place, true); window.addEventListener('resize', place); window.addEventListener('blur', close); window.addEventListener('pagehide', close); window.visualViewport?.addEventListener('resize', place); window.visualViewport?.addEventListener('scroll', place);
    const observer = new MutationObserver(() => { if (!shown.anchor.isConnected || !shown.anchor.getClientRects().length) close(); }); observer.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ['hidden', 'aria-hidden'] });
    return () => { observer.disconnect(); document.removeEventListener('pointerdown', outside, true); document.removeEventListener('focusin', outside, true); document.removeEventListener('keydown', key, true); document.removeEventListener('visibilitychange', hidden);
      window.removeEventListener('scroll', place, true); window.removeEventListener('resize', place); window.removeEventListener('blur', close); window.removeEventListener('pagehide', close); window.visualViewport?.removeEventListener('resize', place); window.visualViewport?.removeEventListener('scroll', place); };
  }, [shown?.anchor, closing, close]);
  useEffect(() => {
    const clock = () => setNow(Date.now()); window.addEventListener('invitation-clock', clock);
    return () => { window.removeEventListener('invitation-clock', clock); clearTimeout(hideTimer.current); clearTimeout(closeTimer.current); motion.current?.cancel(); };
  }, []);
  const api = { now, show, close, tooltipId, activeAnchor: closing ? null : shown?.anchor,
    hold(anchor, key, value) { const a = active.current; if (a?.anchor === anchor) a[key] = value; if (!value) release(); } };
  return <TimeContext.Provider value={api}>{children}{shown && createPortal(<div ref={tooltip} id={tooltipId} role="tooltip" className="iv-ui iv-relative-time-tooltip" aria-hidden={closing ? 'true' : 'false'} style={{ opacity: 0, transform: 'translateY(4px)' }}
    onPointerEnter={() => { if (active.current) active.current.tip = true; clearTimeout(hideTimer.current); }} onPointerLeave={() => { if (active.current) active.current.tip = false; release(); }}>{formatInvitationTime(shown.timestamp)}</div>, document.body)}</TimeContext.Provider>;
}
export const useInvitationTime = () => useContext(TimeContext);
export function InvitationRelativeTime({ timestamp }) {
  const control = useInvitationTime(), anchor = useRef(null), label = relativeInvitationTime(timestamp, control.now);
  if (!Number.isFinite(timestamp)) return <span className="iv-relative-time-empty">—</span>;
  return <button ref={anchor} type="button" className="iv-relative-time" aria-label={label + '. Show exact timestamp.'}
    aria-describedby={control.activeAnchor === anchor.current ? control.tooltipId : undefined}
    onPointerEnter={(e) => { if (e.pointerType !== 'touch') control.show(anchor.current, timestamp, 'hover'); }} onPointerLeave={(e) => { if (e.pointerType !== 'touch') control.hold(anchor.current, 'hover', false); }}
    onFocus={() => control.show(anchor.current, timestamp, 'focus')} onBlur={() => control.hold(anchor.current, 'focus', false)}
    onClick={(e) => { e.stopPropagation(); control.show(anchor.current, timestamp, 'activate'); }}><time dateTime={new Date(timestamp).toISOString()}>{label}</time></button>;
}
