const DURATION = 250;
const EASE = 'cubic-bezier(.2,0,0,1)';

// Only decorative surfaces move. Natural layout, live inputs and iframe identity
// remain owned by React/the browser; no snapshots of form contents are retained.
export function createAuthCardMotion(elements, win = window) {
  const media = win.matchMedia?.('(prefers-reduced-motion: reduce)');
  if (!media || !win.ResizeObserver || !elements().surface?.animate) return { update() {}, destroy() {} };
  let target = null, key, initialized = false, dead = false, active = false;
  let animations = [], generation = 0, deadline = 0;
  const viewport = () => [win.innerWidth, win.innerHeight, win.scrollX, win.scrollY,
    win.visualViewport?.width ?? win.innerWidth, win.visualViewport?.height ?? win.innerHeight,
    win.visualViewport?.scale ?? 1, win.visualViewport?.offsetLeft ?? 0, win.visualViewport?.offsetTop ?? 0];
  let view = viewport();
  const sameView = () => viewport().every((value, i) => Math.abs(value - view[i]) < .1);
  function matrix(node) {
    const value = node ? win.getComputedStyle(node).transform : 'none';
    if (!value || value === 'none') return [1, 0, 0, 1, 0, 0];
    const match = /^matrix\(([^)]+)\)$/.exec(value);
    const values = match?.[1].split(',').map(Number);
    if (!values || values.length !== 6 || !values.every(Number.isFinite) || values[1] !== 0 || values[2] !== 0) throw Error('unsupported transform');
    return values;
  }
  function rect(node) {
    if (!node) return null;
    const box = node.getBoundingClientRect(), m = matrix(node);
    return { x: box.left - m[4], y: box.top - m[5], w: box.width, h: box.height };
  }
  function measure() {
    const e = elements();
    return { card: rect(e.card), content: rect(e.content), cta: rect(e.cta), foot: rect(e.foot) };
  }
  function valid(box) {
    return box && Object.values(box).every(Number.isFinite) && box.w >= 120 && box.w <= 4096 && box.h >= 64 && box.h <= 8192;
  }
  function painted(box, node, scale = false) {
    if (!box || !node) return box;
    const m = matrix(node);
    return { x: box.x + m[4], y: box.y + m[5], w: box.w * (scale ? m[0] : 1), h: box.h * (scale ? m[3] : 1) };
  }
  function clear() {
    generation++;
    active = false;
    const previous = animations; animations = [];
    for (const animation of previous) {
      animation.onfinish = null; animation.oncancel = null;
      try { animation.cancel(); } catch { /* A detached visual can already be gone. */ }
    }
    const surface = elements().surface;
    if (surface) { surface.style.width = ''; surface.style.height = ''; }
  }
  function settle() {
    clear(); view = viewport();
    try { target = measure(); } catch { target = null; }
  }
  function animate(node, frames, options) {
    if (!node) return;
    const animation = node.animate(frames, options);
    animations.push(animation);
    return animation;
  }
  function changed(a, b) {
    return ['card', 'content', 'cta', 'foot'].some(name => {
      if (!a[name] || !b[name]) return a[name] !== b[name];
      return ['x', 'y', 'w', 'h'].some(k => Math.abs(a[name][k] - b[name][k]) > .25);
    });
  }
  function update(nextKey) {
    if (dead) return;
    const structural = initialized && nextKey !== key;
    key = nextKey;
    const e = elements();
    try {
      const next = measure();
      if (!initialized) { initialized = true; target = next; view = viewport(); return; }
      if (media.matches || Math.abs(viewport()[6] - 1) > .001 || !sameView() || win.document.visibilityState === 'hidden' || !valid(target?.card) || !valid(next.card)) { settle(); return; }
      if (!structural && !changed(target, next)) return;
      // A size-only change moves the frame without fading the live form.
      // Observer updates keep the same deadline, so an inner error transition
      // cannot restart a fresh 250ms chase on every frame.
      const before = {
        card: painted(target.card, e.surface, true), content: painted(target.content, e.content),
        cta: painted(target.cta, e.cta), foot: painted(target.foot, e.foot),
      };
      const opacity = Number(win.getComputedStyle(e.main).opacity);
      const now = win.performance.now();
      if (structural || !active) deadline = now + DURATION;
      const duration = Math.min(DURATION, deadline - now);
      clear(); target = next;
      if (duration < 16) return;
      const token = generation;
      e.surface.style.width = next.card.w + 'px'; e.surface.style.height = next.card.h + 'px';
      active = true;
      const options = { duration, easing: EASE };
      const frame = animate(e.surface, [
        { transform: `translate(${before.card.x - next.card.x}px,${before.card.y - next.card.y}px) scale(${before.card.w / next.card.w},${before.card.h / next.card.h})` },
        { transform: 'none' },
      ], options);
      for (const name of ['content', 'cta', 'foot']) {
        if (!before[name] || !next[name]) continue;
        const start = { transform: `translate(${before[name].x - next[name].x}px,${before[name].y - next[name].y}px)` };
        const end = { transform: 'none' };
        if (name === 'content') {
          // Clip the new live form to the growing frame, without scaling its
          // glyphs or leaving controls painted outside the white surface.
          const top = Math.max(0, before.card.y - before.content.y);
          const right = Math.max(0, before.content.x + next.content.w - before.card.x - before.card.w);
          const bottom = Math.max(0, before.content.y + next.content.h - before.card.y - before.card.h);
          const left = Math.max(0, before.card.x - before.content.x);
          start.clipPath = `inset(${top}px ${right}px ${bottom}px ${left}px)`;
          end.clipPath = 'inset(0px 0px 0px 0px)';
        }
        animate(e[name], [start, end], options);
      }
      animate(e.main, [{ opacity: structural ? 0 : (Number.isFinite(opacity) ? opacity : 1) }, { opacity: 1 }],
        structural ? { duration: 180, delay: 70, easing: 'cubic-bezier(0,0,.2,1)', fill: 'backwards' } : { duration, easing: EASE });
      frame.onfinish = frame.oncancel = () => { if (!dead && generation === token) settle(); };
    } catch { settle(); }
  }
  const resized = () => { if (!dead && initialized) update(key); };
  const observer = new win.ResizeObserver(resized);
  observer.observe(elements().content); observer.observe(elements().wrap);
  const viewportChanged = () => { if (!sameView()) settle(); };
  const reduce = () => { if (media.matches) settle(); };
  const hidden = () => { if (win.document.visibilityState === 'hidden') settle(); };
  const restored = () => settle();
  win.addEventListener('resize', viewportChanged, { passive: true });
  win.addEventListener('scroll', viewportChanged, { passive: true });
  win.visualViewport?.addEventListener('resize', viewportChanged, { passive: true });
  win.visualViewport?.addEventListener('scroll', viewportChanged, { passive: true });
  media.addEventListener?.('change', reduce);
  win.document.addEventListener('visibilitychange', hidden);
  win.addEventListener('pagehide', restored); win.addEventListener('pageshow', restored);
  win.document.fonts?.addEventListener?.('loadingdone', resized);
  win.document.fonts?.ready?.then(resized, () => {});
  return { update, destroy() {
    dead = true; clear(); observer.disconnect();
    win.removeEventListener('resize', viewportChanged); win.removeEventListener('scroll', viewportChanged);
    win.visualViewport?.removeEventListener('resize', viewportChanged);
    win.visualViewport?.removeEventListener('scroll', viewportChanged);
    media.removeEventListener?.('change', reduce);
    win.document.removeEventListener('visibilitychange', hidden);
    win.removeEventListener('pagehide', restored); win.removeEventListener('pageshow', restored);
    win.document.fonts?.removeEventListener?.('loadingdone', resized);
  } };
}
