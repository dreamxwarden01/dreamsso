import { useEffect, useLayoutEffect, useRef, useState } from 'react';

// The floating save bar (approved design, frosted-glass variant): FIXED above
// the viewport bottom over the content area — spanning the full inner width
// (from the section rail's left boundary), regardless of where the staging
// section sits in the page flow. Shows staged-change count and AS MANY pending
// tags as the width allows (measured off-screen, re-fit on resize), folding
// the rest into "+N more…". When even one tag can't fit, the first tag fades
// out under the overlapping "+N more…" instead of hard-clipping. Clicking the
// left area (whenever some changes are folded) pops a list of ONLY the folded
// changes up above the bar — left-anchored blue tags, one per line, sized to
// the widest tag (that minimum outranks the "don't reach past Discard" cap),
// 5 rows then scroll; click again to fold. The list always starts folded on a
// fresh set of staged changes. Nothing is written until Save — the page
// batches everything into ONE request. The .savebar-tail spacer keeps the
// last rows scrollable above the bar.
export default function SaveBar({ items, busy, onSave, onDiscard }) {
  const [open, setOpen] = useState(false);
  const [closing, setClosing] = useState(false); // fold-away animation in flight
  const [fit, setFit] = useState(null); // measured tag count; null until first layout
  const [popMax, setPopMax] = useState(null); // px cap: bar left -> Discard left
  const pendRef = useRef(null); // visible tag area (width source of truth)
  const railRef = useRef(null); // hidden measuring rail with EVERY tag
  const wrapRef = useRef(null); // .savebar-wrap — the pop-list's anchor box
  const discardRef = useRef(null);

  useLayoutEffect(() => {
    const el = pendRef.current;
    const rail = railRef.current;
    if (!el || !rail) return undefined;
    const GAP = 7; // .sb-pending gap
    const compute = () => {
      const avail = el.clientWidth;
      const kids = [...rail.children];
      const moreW = kids[kids.length - 1].offsetWidth; // "+N more…" probe
      const tagW = kids.slice(0, -1).map((k) => k.offsetWidth);
      let used = 0;
      let n = 0;
      for (let i = 0; i < tagW.length; i++) {
        const w = tagW[i] + (i ? GAP : 0);
        // If tags would remain hidden after this one, the "+N more…" label
        // must still fit alongside.
        const reserve = i < tagW.length - 1 ? GAP + moreW : 0;
        if (used + w + reserve > avail) break;
        used += w;
        n++;
      }
      setFit(n);
      if (wrapRef.current && discardRef.current) {
        setPopMax(Math.max(
          0,
          discardRef.current.getBoundingClientRect().left - wrapRef.current.getBoundingClientRect().left - 10,
        ));
      }
    };
    compute();
    const ro = new ResizeObserver(compute);
    ro.observe(el);
    return () => ro.disconnect();
  }, [items]);

  const fitN = fit ?? Math.min(items.length, 2); // pre-measure paint only
  // The list shows ONLY what the bar doesn't: in squeeze mode the first tag
  // is (partially) on the bar, so the list matches the "+N more…" count.
  const folded = fitN > 0 ? items.slice(fitN) : items.slice(1);

  // A fresh set of staged changes always starts folded: when nothing is
  // folded anymore (discard, save, resize-wide), drop the open state.
  useEffect(() => {
    if (open && !folded.length) {
      setOpen(false);
      setClosing(false);
    }
  }, [open, folded.length]);

  // Fold with the reverse of the pop-in (timeout, not animationend — the
  // reduced-motion media rule disables the animation entirely).
  const toggle = () => {
    if (closing) return;
    if (!open) {
      setOpen(true);
      return;
    }
    setClosing(true);
    setTimeout(() => {
      setOpen(false);
      setClosing(false);
    }, 150);
  };

  if (!items.length) return null;

  const Tag = (it, i) => (
    <span key={i} className="sb-tag"><strong>{it.label}</strong>&nbsp;→&nbsp;{it.value}</span>
  );

  return (
    <>
      <div className="savebar-fix">
        <div className="savebar-wrap" ref={wrapRef}>
          {/* sibling of the bar, not a child: the bar's backdrop-filter would
              otherwise become the list's backdrop root and break its frost */}
          {open && folded.length > 0 && (
            <div className={'sb-pop' + (closing ? ' out' : '')} style={popMax != null ? { maxWidth: popMax } : undefined}>
              {folded.map(Tag)}
            </div>
          )}
          <div className="savebar">
            <div
              className={'sb-left' + (folded.length ? ' sb-click' : '')}
              title={folded.length ? (open ? 'Hide the other changes' : 'Show the other changes') : undefined}
              onClick={() => folded.length && toggle()}
            >
              <span className="sb-count">{items.length}</span>
              <div className="sb-pending" ref={pendRef}>
                {fitN > 0 ? (
                  <>
                    {items.slice(0, fitN).map(Tag)}
                    {folded.length > 0 && <span className="sb-more">+{folded.length} more…</span>}
                  </>
                ) : (
                  /* no room for even one tag: the first fades out under the
                     overlapping "+N more…" instead of hard-clipping */
                  <>
                    <span className="sb-tag sb-fadetag">
                      <strong>{items[0].label}</strong>&nbsp;→&nbsp;{items[0].value}
                    </span>
                    {folded.length > 0 && <span className="sb-more sb-overmore">+{folded.length} more…</span>}
                  </>
                )}
                <div className="sb-rail" ref={railRef} aria-hidden="true">
                  {items.map(Tag)}
                  <span className="sb-more">+{Math.max(items.length - 1, 1)} more…</span>
                </div>
              </div>
            </div>
            <button className="btn" ref={discardRef} onClick={onDiscard} disabled={busy}>Discard</button>
            <button className="btn btn-primary" onClick={onSave} disabled={busy}>{busy ? 'Saving…' : 'Save changes'}</button>
          </div>
        </div>
      </div>
      <div className="savebar-tail" />
    </>
  );
}
