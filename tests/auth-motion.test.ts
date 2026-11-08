import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { renderAuthMotionScript } from '../src/authMotion.js';

const key = 'authcard.geometry.v1';
const now = 10_000;
function geometry(overrides: Record<string, unknown> = {}) {
  return { v: 1, w: 400, h: 300, vw: 800, vh: 700, xw: 800, xh: 700, s: 1, t: now - 100, ...overrides };
}
function fixture(options: {
  stored?: string | null; denied?: boolean; navigation?: string | null; reduced?: boolean;
  native?: boolean; unsupported?: boolean; throwAnimation?: boolean; now?: number;
  viewport?: Record<string, number>;
} = {}) {
  const storage = new Map<string, string>();
  if (options.stored !== null) storage.set(key, options.stored ?? JSON.stringify(geometry()));
  const windowEvents = new Map<string, ((event: any) => void)[]>();
  const visualEvents = new Map<string, ((event: any) => void)[]>();
  const mediaEvents = new Map<string, ((event: any) => void)[]>();
  const register = (events: Map<string, any[]>) => (type: string, callback: any) => {
    events.set(type, [...(events.get(type) ?? []), callback]);
  };
  const emit = (events: Map<string, any[]>, type: string, event: any = {}) => {
    for (const callback of events.get(type) ?? []) callback(event);
  };
  const classes = new Set<string>();
  const animations: any[] = [];
  let painted = { width: 400, height: 460 };
  let focusCalls = 0;
  const focus = () => { focusCalls++; };
  const animate = (target: string) => (frames: any, timing: any) => {
    if (options.throwAnimation && target === 'content') throw new Error('unsupported animation');
    const animation = {
      target, frames, timing, onfinish: null as any, oncancel: null as any, cancelled: false,
      cancel() { this.cancelled = true; this.oncancel?.(); },
      finish() { this.onfinish?.(); },
    };
    animations.push(animation);
    return animation;
  };
  const child = { classList: { contains: () => false }, animate: animate('content') };
  const brand = { classList: { contains: (name: string) => name === 'brand' }, animate: animate('brand') };
  const body = {
    style: { width: '' }, children: [brand, child], animate: animate('body'),
    getBoundingClientRect: () => ({ width: 398, height: 458 }), focus,
  };
  const card = {
    querySelector: (selector: string) => { assert.equal(selector, '.cb'); return body; },
    getBoundingClientRect: () => painted,
    classList: { add: (name: string) => classes.add(name), remove: (name: string) => classes.delete(name) },
    animate: options.unsupported ? undefined : animate('shell'), focus,
  };
  const media = { matches: options.reduced ?? false, addEventListener: register(mediaEvents) };
  const visual = { width: 800, height: 700, scale: 1, ...options.viewport,
    addEventListener: register(visualEvents) };
  const context: any = {
    document: {
      querySelector: (selector: string) => { assert.equal(selector, '.card'); return card; },
      // Any authentication/form access outside these two geometric selectors fails the test.
    },
    sessionStorage: {
      getItem(name: string) { if (options.denied) throw new Error('denied'); return storage.get(name) ?? null; },
      removeItem(name: string) { if (options.denied) throw new Error('denied'); storage.delete(name); },
      setItem(name: string, value: string) { if (options.denied) throw new Error('denied'); storage.set(name, value); },
    },
    performance: { getEntriesByType(type: string) {
      assert.equal(type, 'navigation');
      return options.navigation === null ? [] : [{ type: options.navigation ?? 'navigate' }];
    } },
    matchMedia: (query: string) => { assert.equal(query, '(prefers-reduced-motion: reduce)'); return media; },
    Date: { now: () => options.now ?? now }, innerWidth: 800, innerHeight: 700,
    visualViewport: visual, addEventListener: register(windowEvents),
  };
  context.window = context;
  if (options.native) context.onpagereveal = null;
  const markup = renderAuthMotionScript('test-nonce');
  const script = markup.slice(markup.indexOf('>') + 1, markup.lastIndexOf('</script>'));
  vm.runInNewContext(script, context);
  return {
    storage, classes, animations, body, visual, media, context,
    emit: (type: string, event: any = {}) => emit(windowEvents, type, event),
    visualResize: () => emit(visualEvents, 'resize'),
    reduce: () => { media.matches = true; emit(mediaEvents, 'change', { matches: true }); },
    setPainted: (width: number, height: number) => { painted = { width, height }; },
    focusCalls: () => focusCalls,
    eventTypes: [...windowEvents.keys()],
  };
}

function settled(f: ReturnType<typeof fixture>) {
  assert.equal(f.classes.has('morphing'), false);
  assert.equal(f.body.style.width, '');
  assert.ok(f.animations.every(animation => animation.cancelled));
}

test('script is valid browser JavaScript with an escaped nonce and unscaled shell/content frames', () => {
  assert.match(renderAuthMotionScript('x"<&\''), /^<script nonce="x&quot;&lt;&amp;&#39;">/);
  const f = fixture();
  assert.equal(f.storage.has(key), false);
  assert.equal(f.body.style.width, '398px');
  assert.equal(f.classes.has('morphing'), true);
  assert.deepEqual(JSON.parse(JSON.stringify(f.animations.map(a => [a.target, a.frames]))), [
    ['shell', [{ width: '400px', height: '300px' }, { width: '400px', height: '460px' }]],
    ['content', [{ opacity: 0 }, { opacity: 1 }]],
  ]);
  assert.equal(f.animations[0].timing.duration, 250);
  f.animations[0].finish();
  settled(f);
});

test('anonymous state is bounded, consumed once, and rejects stale, future, malformed, or changed viewport values', () => {
  for (const stored of [
    '{', 'null', '[]', JSON.stringify(geometry({ t: now - 3001 })), JSON.stringify(geometry({ t: now + 1 })),
    JSON.stringify(geometry({ h: 1e99 })), JSON.stringify(geometry({ w: -1 })),
    JSON.stringify(geometry({ w: null })), JSON.stringify(geometry({ vw: 799 })),
    JSON.stringify(geometry({ vh: 699 })), JSON.stringify(geometry({ xh: 699 })),
    JSON.stringify(geometry({ s: 1.5 })), JSON.stringify(geometry({ v: 2 })),
    JSON.stringify({ ...geometry(), extra: 'not permitted' }), ' '.repeat(513),
  ]) {
    const f = fixture({ stored });
    assert.equal(f.storage.has(key), false, stored);
    assert.equal(f.animations.length, 0, stored);
    assert.equal(f.body.style.width, '');
  }
  assert.equal(fixture({ stored: JSON.stringify(geometry({ t: now - 3000 })) }).animations.length, 2);
});

test('reload, history, missing navigation evidence, reduced motion, zoom, native support and unsupported APIs skip animation', () => {
  for (const options of [
    { navigation: 'reload' }, { navigation: 'back_forward' }, { navigation: null }, { reduced: true },
    { viewport: { scale: 1.1 } }, { native: true }, { unsupported: true }, { denied: true },
  ]) {
    const f = fixture(options);
    assert.equal(f.animations.length, 0, JSON.stringify(options));
    assert.equal(f.body.style.width, '');
    f.emit('pagehide', { persisted: false }); // Denied storage never stops navigation.
  }
});

test('pagehide saves visible intermediate geometry before cancellation, and no authentication data', () => {
  const f = fixture();
  f.setPainted(399.5, 372.25);
  f.emit('pagehide', { persisted: false });
  assert.deepEqual(JSON.parse(f.storage.get(key)!), geometry({ w: 399.5, h: 372.25, t: now }));
  settled(f);
  assert.deepEqual(f.eventTypes.sort(), ['keydown', 'pagehide', 'pageshow', 'pointerdown', 'resize', 'touchstart', 'wheel']);
  assert.equal(f.focusCalls(), 0);
});

test('outgoing BFCache can seed a fresh navigation; BFCache restore and reduced motion settle immediately', () => {
  const cached = fixture();
  cached.emit('pagehide', { persisted: true });
  assert.equal(cached.storage.has(key), true);
  settled(cached);
  cached.emit('pageshow', { persisted: true });
  assert.equal(cached.storage.has(key), false);
  const restored = fixture();
  restored.storage.set(key, JSON.stringify(geometry()));
  restored.emit('pageshow', { persisted: true });
  assert.equal(restored.storage.has(key), false);
  settled(restored);
  const reduced = fixture();
  reduced.reduce();
  settled(reduced);
  reduced.emit('pagehide', { persisted: false });
  assert.equal(reduced.storage.has(key), false);
});

test('unchanged Firefox viewport notifications preserve motion; real viewport/keyboard/scale changes settle', () => {
  const f = fixture();
  f.emit('resize'); f.visualResize();
  assert.equal(f.classes.has('morphing'), true);
  f.visual.height = 450;
  f.visualResize();
  settled(f);
  const resized = fixture();
  resized.context.innerWidth = 700;
  resized.emit('resize');
  settled(resized);
  const zoomed = fixture();
  zoomed.visual.scale = 1.1;
  zoomed.visualResize();
  settled(zoomed);
});

test('initial autofocus is unaffected while real user interaction can settle without being intercepted', () => {
  const f = fixture();
  f.body.focus();
  f.emit('focusin', { isTrusted: true });
  assert.equal(f.classes.has('morphing'), true);
  assert.equal(f.focusCalls(), 1);
  f.emit('keydown', { isTrusted: false });
  assert.equal(f.classes.has('morphing'), true);
  f.emit('keydown', { isTrusted: true,
    preventDefault() { assert.fail('visual enhancement cannot prevent input'); },
    stopPropagation() { assert.fail('visual enhancement cannot stop input'); },
  });
  settled(f);
});

test('external animation cancellation and partial animation failure always clean all temporary styles', () => {
  const f = fixture();
  f.animations[1].cancel();
  settled(f);
  const interrupted = fixture();
  interrupted.animations[0].cancel();
  settled(interrupted);
  const failed = fixture({ throwAnimation: true });
  settled(failed);
});

test('first navigation can record geometry, but invalid or zoomed outgoing geometry is never stored', () => {
  const first = fixture({ stored: null });
  assert.equal(first.animations.length, 0);
  first.emit('pagehide', { persisted: false });
  assert.deepEqual(JSON.parse(first.storage.get(key)!), geometry({ h: 460, t: now }));
  const invalid = fixture({ stored: null });
  invalid.setPainted(NaN, 460);
  invalid.emit('pagehide', { persisted: false });
  assert.equal(invalid.storage.has(key), false);
  const zoom = fixture({ stored: null, viewport: { scale: 2 } });
  zoom.emit('pagehide', { persisted: false });
  assert.equal(zoom.storage.has(key), false);
});
