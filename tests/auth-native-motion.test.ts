import test from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { renderAuthNativeMotionScript } from '../src/authNativeMotion.js';

const first = { offset: 0, computedOffset: 0, easing: 'linear', composite: 'auto',
  width: '400px', height: '380px', transform: 'matrix(1, 0, 0, 1, 200, 160)', backdropFilter: 'none' };
const last = { offset: 1, computedOffset: 1, easing: 'linear', composite: 'auto',
  width: '360px', height: '460px', transform: 'matrix(1, 0, 0, 1, 220, 120)', backdropFilter: 'none' };
function fixture(options: {
  frames?: any[]; reduced?: boolean; duplicate?: boolean; name?: string; target?: string;
  unavailable?: boolean; rejectSet?: boolean; scrollY?: number; style?: Record<string, string>;
  origin?: string;
  rect?: { width: number; height: number; left: number; top: number };
  visual?: Record<string, number>;
  ancestorStyles?: Record<string, string>[];
  noObserver?: boolean; observeFailure?: boolean;
} = {}) {
  const events = new Map<string, ((event: any) => void)[]>();
  const mediaEvents = new Map<string, ((event: any) => void)[]>();
  const register = (map: typeof events) => (type: string, callback: (event: any) => void) => {
    map.set(type, [...(map.get(type) ?? []), callback]);
  };
  const root = {};
  const original = structuredClone(options.frames ?? [first, last]);
  let current = original;
  let writes = 0;
  const timing = { duration: 250, easing: 'cubic-bezier(.2,0,0,1)', delay: 0 };
  const effect = {
    target: options.target === 'other' ? {} : root,
    pseudoElement: '::view-transition-group(authcard)',
    getKeyframes: () => structuredClone(current),
    setKeyframes(frames: any[]) {
      if (options.rejectSet) throw new TypeError('not supported');
      writes++; current = structuredClone(frames);
    },
    getTiming: () => timing,
  };
  const animation = { effect, playState: 'running',
    animationName: options.name ?? '-ua-view-transition-group-anim-authcard', currentTime: 12.5 };
  const unrelatedEffect = { pseudoElement: '::view-transition-group(authcontent)',
    setKeyframes() { assert.fail('content must never be changed'); },
    getKeyframes() { assert.fail('content must never be inspected'); } };
  const parents = (options.ancestorStyles ?? []).map(style => ({ fixtureStyle: style, parentElement: null as any }));
  parents.forEach((parent, index) => { parent.parentElement = parents[index + 1] ?? null; });
  let rect = options.rect ?? { width: 360, height: 460, left: 220, top: 120 };
  const card = { isConnected: true, parentElement: parents[0] ?? null,
    getBoundingClientRect: () => rect };
  const media = { matches: options.reduced ?? false, addEventListener: register(mediaEvents) };
  const marks: string[] = [];
  const observers: { disconnected: boolean; deliver: () => void; target?: unknown }[] = [];
  class FakeResizeObserver {
    disconnected = false;
    target?: unknown;
    constructor(private callback: () => void) { observers.push(this); }
    observe(target: unknown, observedOptions: { box: string }) {
      assert.equal(target, card); assert.equal(observedOptions.box, 'border-box');
      this.target = target;
      if (options.observeFailure) throw new Error('border-box observation unsupported');
    }
    disconnect() { this.disconnected = true; }
    deliver() { this.callback(); } // Also exercise callbacks already queued before disconnect.
  }
  const context: any = {
    onpagereveal: null, addEventListener: register(events), matchMedia: () => media,
    scrollX: 0, scrollY: options.scrollY ?? 0,
    visualViewport: { scale: 1, offsetLeft: 0, offsetTop: 0, ...options.visual },
    performance: { mark: (name: string) => { marks.push(name); } },
    ResizeObserver: options.noObserver ? undefined : FakeResizeObserver,
    document: { documentElement: root, visibilityState: 'visible',
      querySelector(selector: string) { assert.equal(selector, '.card'); return card; },
      getAnimations: options.unavailable ? undefined : () => [
        { effect: unrelatedEffect }, animation, ...(options.duplicate ? [animation] : []),
      ],
    },
    getComputedStyle: (element: any, pseudo?: string) => pseudo ? { transformOrigin: options.origin ?? '0px 0px' } :
      ({ transform: 'none', translate: 'none', rotate: 'none', scale: 'none', ...(element.fixtureStyle ?? options.style) }),
  };
  context.window = context;
  const markup = renderAuthNativeMotionScript('test-nonce');
  vm.runInNewContext(markup.slice(markup.indexOf('>') + 1, markup.lastIndexOf('</script>')), context);
  const emit = (type: string, event: any = {}) => { for (const callback of events.get(type) ?? []) callback(event); };
  return {
    context, effect, animation, original, emit, marks, observers,
    setRect: (values: Partial<typeof rect>) => { rect = { ...rect, ...values }; },
    current: () => JSON.parse(JSON.stringify(current)), writes: () => writes,
    reveal: async (ready: Promise<void> = Promise.resolve(), finished?: Promise<void>) => {
      emit('pagereveal', { viewTransition: { ready, finished } }); await ready.catch(() => {}); await Promise.resolve();
    },
    reduce: () => { media.matches = true; for (const callback of mediaEvents.get('change') ?? []) callback({ matches: true }); },
  };
}

test('native shell becomes transform-only while preserving timing, progress and unrelated content', async () => {
  assert.match(renderAuthNativeMotionScript('x"<&\''), /^<script nonce="x&quot;&lt;&amp;&#39;">/);
  const f = fixture();
  await f.reveal();
  assert.deepEqual(f.current(), [
    { offset: 0, easing: 'linear', composite: 'replace', transform: `matrix(${400 / 360},0,0,${380 / 460},200,160)` },
  ]);
  assert.equal(f.animation.currentTime, 12.5);
  assert.equal(f.effect.getTiming().duration, 250);
  assert.equal(f.effect.getTiming().easing, 'cubic-bezier(.2,0,0,1)');
  assert.equal(f.writes(), 1);
  assert.deepEqual(f.marks, ['auth-vt-transform']);
});

test('implicit UA final endpoints resolve only from the untransformed final card border box', async () => {
  for (const frames of [[first], [first, { offset: 1, computedOffset: 1, easing: 'ease-out', composite: 'auto' }]]) {
    const f = fixture({ frames });
    await f.reveal();
    assert.equal(f.writes(), 1);
    assert.equal(f.current().length, 1);
    assert.equal(f.current()[0].offset, 0);
    assert.equal(f.current()[0].easing, first.easing);
  }
});

test('observed Chromium UA frame shape retains easing and drops static backdropFilter plus dimensions', async () => {
  // Shape captured by the local real-navigation fixture; independent of production auth data.
  const f = fixture({ rect: { width: 400, height: 402, left: 440, top: 141 }, frames: [
    { ...first, width: '400px', height: '422px', transform: 'matrix(1, 0, 0, 1, 440, 93.5)',
      easing: 'cubic-bezier(0.2, 0, 0, 1)' },
    { ...last, width: '400px', height: '402px', transform: 'matrix(1, 0, 0, 1, 440, 141)',
      easing: 'cubic-bezier(0.2, 0, 0, 1)', composite: 'replace' },
  ] });
  await f.reveal();
  assert.equal(f.writes(), 1);
  assert.deepEqual(f.current(), [
    { offset: 0, easing: 'cubic-bezier(0.2, 0, 0, 1)', composite: 'replace',
      transform: `matrix(1,0,0,${422 / 402},440,93.5)` },
  ]);
});

test('unsupported, ambiguous, malformed or mismatched geometry preserves the original effect', async () => {
  const invalid: Parameters<typeof fixture>[0][] = [
    { unavailable: true }, { noObserver: true }, { reduced: true }, { duplicate: true }, { name: 'author-animation' },
    { target: 'other' }, { scrollY: 10 }, { style: { transform: 'matrix(1,0,0,1,0,0)' } }, { origin: '180px 230px' },
    { frames: [] }, { frames: [first, last, last] },
    { frames: [{ ...first, computedOffset: 0.1 }, last] },
    { frames: [{ ...first, width: 'auto' }, last] },
    { frames: [{ ...first, width: '-2px' }, last] },
    { frames: [{ ...first, transform: 'matrix(2, 0, 0, 1, 200, 200)' }, last] },
    { frames: [{ ...first, transform: 'matrix(1, 0, , 1, 200, 200)' }, last] },
    { frames: [{ ...first, transform: 'matrix3d(1,0,0,0,0,1,0,0,0,0,1,0,200,200,0,1)' }, last] },
    { frames: [{ ...first, opacity: 0 }, last] },
    { frames: [{ ...first, backdropFilter: 'blur(1px)' }, last] },
    { frames: [{ ...first, composite: 'add' }, last] },
    { frames: [first, { offset: 1, computedOffset: 1, width: '360px' }] },
    { frames: [first, { ...last, height: '461px' }] },
    { frames: [last, last] }, { rejectSet: true },
  ];
  for (const options of invalid) {
    const f = fixture(options);
    await f.reveal();
    assert.equal(f.writes(), 0, JSON.stringify(options));
    assert.deepEqual(f.current(), f.original, JSON.stringify(options));
    assert.deepEqual(f.marks, []);
  }
});

test('zoom, visual viewport offsets and transforms anywhere in the ancestor chain skip optimization', async () => {
  for (const options of [
    { visual: { scale: 1.1 } }, { visual: { offsetLeft: 1 } }, { visual: { offsetTop: -1 } },
    { ancestorStyles: [{ transform: 'matrix(1,0,0,1,0,0)' }] },
    { ancestorStyles: [{}, { translate: '1px' }] },
    { ancestorStyles: [{}, { rotate: '1deg' }] },
    { ancestorStyles: [{}, { scale: '1.1' }] },
  ]) {
    const f = fixture(options); await f.reveal();
    assert.equal(f.writes(), 0, JSON.stringify(options));
    assert.deepEqual(f.current(), f.original);
  }
  const plainAncestors = fixture({ ancestorStyles: [{}, {}] });
  await plainAncestors.reveal(); assert.equal(plainAncestors.writes(), 1);
});

test('shell scaling is bounded in both axes, including the accepted boundary ratios', async () => {
  for (const [width, height, accepted] of [
    [270, 380, true], [480, 380, true], [269, 380, false], [481, 380, false],
    [400, 360, true], [400, 640, true], [400, 359, false], [400, 641, false],
  ] as const) {
    const f = fixture({ rect: { width: 360, height: 480, left: 220, top: 120 }, frames: [
      { ...first, width: `${width}px`, height: `${height}px` }, { ...last, height: '480px' },
    ] });
    await f.reveal(); assert.equal(f.writes(), accepted ? 1 : 0, `${width} × ${height}`);
  }
});

test('missing/rejected native transitions and pagehide before ready do not mutate animations', async () => {
  const missing = fixture(); missing.emit('pagereveal'); await Promise.resolve();
  assert.equal(missing.writes(), 0);
  const failed = fixture(); await failed.reveal(Promise.reject(new Error('skipped')));
  assert.equal(failed.writes(), 0);
  let ready!: () => void;
  const waiting = new Promise<void>(resolve => { ready = resolve; });
  const hidden = fixture();
  const pending = hidden.reveal(waiting);
  hidden.emit('pagehide'); ready(); await pending;
  assert.equal(hidden.writes(), 0);
  const invisible = fixture(); invisible.context.document.visibilityState = 'hidden';
  await invisible.reveal(); assert.equal(invisible.writes(), 0);
});

test('reduced motion and page lifecycle restore only the changed native shell', async () => {
  for (const action of ['reduce', 'pagehide']) {
    const f = fixture(); await f.reveal();
    if (action === 'reduce') f.reduce(); else f.emit('pagehide');
    assert.deepEqual(f.current(), [f.original[0]]);
    assert.equal(f.writes(), 2);
    assert.equal(f.observers[0].disconnected, true);
  }
});

test('finished transitions release the saved effect without rewriting it; stale completion cannot clear a new one', async () => {
  let finish!: () => void;
  const finished = new Promise<void>(resolve => { finish = resolve; });
  const f = fixture(); await f.reveal(Promise.resolve(), finished);
  finish(); await finished; await Promise.resolve();
  f.emit('pagehide'); assert.equal(f.writes(), 1);
  assert.equal(f.observers[0].disconnected, true);
  f.setRect({ height: 500 }); f.observers[0].deliver();
  assert.equal(f.writes(), 1);

  let finishOld!: () => void;
  const oldFinished = new Promise<void>(resolve => { finishOld = resolve; });
  const newer = fixture(); await newer.reveal(Promise.resolve(), oldFinished);
  await newer.reveal();
  const beforeReduction = newer.writes();
  finishOld(); await oldFinished; await Promise.resolve();
  newer.reduce();
  assert.equal(newer.writes(), beforeReduction + 1);
  assert.deepEqual(newer.current(), [newer.original[0]]);
});

test('a real card size change restores once; initial and unchanged observer deliveries keep the optimization', async () => {
  for (const dimension of ['width', 'height'] as const) {
    const f = fixture(); await f.reveal();
    const observer = f.observers[0];
    observer.deliver(); assert.equal(f.writes(), 1);
    f.setRect({ [dimension]: dimension === 'width' ? 360.05 : 460.05 });
    observer.deliver(); assert.equal(f.writes(), 1);
    f.setRect({ [dimension]: 500 }); observer.deliver();
    assert.equal(f.writes(), 2);
    assert.deepEqual(f.current(), [f.original[0]]);
    assert.deepEqual(f.marks, ['auth-vt-transform', 'auth-vt-resize-fallback']);
    assert.equal(observer.disconnected, true);
    observer.deliver(); assert.equal(f.writes(), 2);
  }
});

test('old-generation resize callbacks cannot restore a newer transition', async () => {
  const f = fixture(); await f.reveal();
  const oldObserver = f.observers[0];
  await f.reveal();
  assert.equal(oldObserver.disconnected, true);
  const beforeResize = f.writes();
  f.setRect({ height: 500 }); oldObserver.deliver();
  assert.equal(f.writes(), beforeResize);
  f.observers[1].deliver(); assert.equal(f.writes(), beforeResize + 1);
});

test('observer setup and effect assignment failures disconnect observation without changing the native effect', async () => {
  for (const options of [{ observeFailure: true }, { rejectSet: true }]) {
    const f = fixture(options); await f.reveal();
    assert.equal(f.writes(), 0); assert.deepEqual(f.current(), f.original);
    assert.equal(f.observers[0].disconnected, true);
    f.setRect({ height: 500 }); f.observers[0].deliver();
    assert.equal(f.writes(), 0); assert.deepEqual(f.marks, []);
  }
});
