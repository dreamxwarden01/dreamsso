import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Run the actual component with deterministic hooks, element refs, loader timing
// and a synthetic provider. No real browser, script request or human proof.
function fixture(options: { ready?: boolean; active?: boolean; key?: string | null } = {}) {
  let index = 0, serial = 0, element: any;
  const slots: any[] = [], effects: Function[] = [], intervals = new Map<number, Function>();
  const scripts = new Map<string, any>(), appended: any[] = [], renders: any[] = [], removals: string[] = [], resets: string[] = [];
  const tokens: string[] = [], expired: string[] = [], errors: string[] = [];
  const resetRef: { current: any } = { current: null };
  const nodes = new Map<any, any>(), activeDomRefs = new Set<any>();
  const settings = { turnstileSiteKey: options.key === undefined ? 'synthetic-site-key' : options.key };
  let props: any = { active: options.active ?? true, resetRef,
    onToken: (value: string) => tokens.push(value), onExpire: () => expired.push('expired'), onError: () => errors.push('error') };
  const same = (a: any[], b: any[]) => a.length === b.length && a.every((value, n) => Object.is(value, b[n]));
  const react = {
    useRef(value: any) { const position = index++; slots[position] ||= { current: value }; return slots[position]; },
    useCallback(fn: Function, deps: any[]) { const position = index++;
      if (!slots[position] || !same(slots[position].deps, deps)) slots[position] = { value: fn, deps }; return slots[position].value; },
    useEffect(effect: Function, deps: any[]) { const position = index++, previous = slots[position];
      if (!previous || !same(previous.deps, deps)) effects.push(() => {
        previous?.cleanup?.(); slots[position] = { deps, cleanup: effect() };
      }); },
  };
  const jsx = (type: any, props: any) => ({ type, props: props || {} });
  const provider = {
    render(container: any, callbacks: any) { const record = { id: 'widget-' + (renders.length + 1), container, callbacks }; renders.push(record); return record.id; },
    remove(id: string) { removals.push(id); }, reset(id: string) { resets.push(id); },
  };
  const window: any = options.ready ? { turnstile: provider } : {};
  const document = { getElementById: (id: string) => scripts.get(id), createElement: (tag: string) => ({ tag }),
    head: { appendChild(script: any) { scripts.set(script.id, script); appended.push(script); } } };
  const source = fs.readFileSync(new URL('../account/client/src/components/Turnstile.jsx', import.meta.url), 'utf8');
  const compiled = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS,
    target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.ReactJSX } }).outputText;
  const exports: any = {};
  vm.runInNewContext(compiled, { exports, window, document,
    setInterval: (fn: Function, delay: number) => { assert.equal(delay, 100); const id = ++serial; intervals.set(id, fn); return id; },
    clearInterval: (id: number) => intervals.delete(id),
    require: (name: string) => {
      if (name === 'react') return react;
      if (name === 'react/jsx-runtime') return { jsx, jsxs: jsx, Fragment: Symbol('fragment') };
      if (name === '../context/SiteContext.jsx') return { useSite: () => settings };
      throw new Error('unexpected dependency ' + name);
    },
  });
  function commitRefs(node: any, present: Set<any>) {
    if (Array.isArray(node)) { node.forEach(child => commitRefs(child, present)); return; }
    if (!node || typeof node !== 'object') return;
    if (node.props.ref) {
      const ref = node.props.ref;
      if (!activeDomRefs.has(ref)) nodes.set(ref, { tag: node.type, className: node.props.className, instance: ++serial });
      ref.current = nodes.get(ref); present.add(ref);
    }
    commitRefs(node.props.children, present);
  }
  const h = { renders, removals, resets, appended, intervals, tokens, expired, errors, resetRef,
    render(patch: any = {}) {
      props = { ...props, ...patch }; index = 0; element = exports.default(props);
      const present = new Set<any>(); commitRefs(element, present);
      for (const ref of activeDomRefs) if (!present.has(ref)) ref.current = null;
      activeDomRefs.clear(); for (const ref of present) activeDomRefs.add(ref);
      for (const run of effects.splice(0)) run(); return element;
    },
    setKey(key: string | null) { settings.turnstileSiteKey = key; this.render(); },
    providerReady() { window.turnstile = provider; },
    poll() { for (const fn of [...intervals.values()]) fn(); },
    unmount() { for (const slot of slots) slot?.cleanup?.(); for (const ref of activeDomRefs) ref.current = null; activeDomRefs.clear(); },
  };
  return h;
}

test('inactive or unconfigured Turnstile creates no widget, loader or polling work', () => {
  for (const options of [{ active: false }, { active: true, key: null }]) {
    const h = fixture(options); assert.equal(h.render(), null);
    assert.equal(h.appended.length, 0); assert.equal(h.intervals.size, 0); assert.equal(h.renders.length, 0);
    h.resetRef.current?.(); assert.equal(h.resets.length, 0); h.unmount(); assert.equal(h.resetRef.current, null);
  }
});

test('eligible lazy activation inserts one loader and renders only when the provider is ready', () => {
  const h = fixture({ active: false }); h.render(); h.render({ active: true });
  assert.equal(h.appended.length, 1); assert.match(h.appended[0].src, /^https:\/\/challenges\.cloudflare\.com\/turnstile\/v0\/api\.js\?render=explicit$/);
  assert.equal(h.renders.length, 0); assert.equal(h.intervals.size, 1);
  h.providerReady(); h.poll(); assert.equal(h.renders.length, 1); assert.equal(h.intervals.size, 0);
  h.renders[0].callbacks.callback('synthetic-proof'); assert.deepEqual(h.tokens, ['synthetic-proof']); h.unmount();
});

test('lazy-created widget is removed on deactivation and all stale provider callbacks are ignored', () => {
  const h = fixture(); h.render(); h.providerReady(); h.poll(); const old = h.renders[0];
  h.render({ active: false }); assert.deepEqual(h.removals, [old.id]); assert.equal(h.intervals.size, 0);
  old.callbacks.callback('stale-proof'); old.callbacks['expired-callback'](); old.callbacks['error-callback'](); old.callbacks['timeout-callback']();
  assert.deepEqual(h.tokens, []); assert.deepEqual(h.expired, []); assert.deepEqual(h.errors, []); h.unmount();
});

test('immediate provider path also removes its widget and clears external reset ownership on unmount', () => {
  const h = fixture({ ready: true }); h.render(); const old = h.renders[0];
  h.unmount(); assert.deepEqual(h.removals, [old.id]); assert.equal(h.resetRef.current, null);
  old.callbacks.callback('stale-proof'); old.callbacks['error-callback']();
  assert.deepEqual(h.tokens, []); assert.deepEqual(h.errors, []);
});

test('an existing widget uses the latest callbacks without rendering another widget', () => {
  const h = fixture({ ready: true }); h.render(); const old = h.renders[0];
  const latest: string[] = [];
  h.render({ onToken: (value: string) => latest.push(value), onExpire: () => latest.push('expired'), onError: () => latest.push('error') });
  old.callbacks.callback('new-proof'); old.callbacks['expired-callback'](); old.callbacks['error-callback'](); old.callbacks['timeout-callback']();
  assert.equal(h.renders.length, 1); assert.deepEqual(latest, ['new-proof', 'expired', 'error', 'expired']);
  assert.deepEqual(h.tokens, []); assert.deepEqual(h.expired, []); assert.deepEqual(h.errors, []); h.unmount();
});

test('inactive-to-eligible retry creates a fresh widget and cannot revive the previous proof', () => {
  const h = fixture({ ready: true }); h.render(); const old = h.renders[0];
  h.render({ active: false }); h.render({ active: true }); const fresh = h.renders[1];
  assert.notEqual(fresh.id, old.id); old.callbacks.callback('old-proof'); fresh.callbacks.callback('fresh-proof');
  assert.deepEqual(h.tokens, ['fresh-proof']); assert.deepEqual(h.removals, [old.id]); h.unmount();
});

test('changing the site key replaces the widget and invalidates callbacks from the old key', () => {
  const h = fixture({ ready: true }); h.render(); const old = h.renders[0];
  h.setKey('synthetic-new-key'); const fresh = h.renders[1]; assert.equal(fresh.callbacks.sitekey, 'synthetic-new-key');
  old.callbacks.callback('old-proof'); fresh.callbacks.callback('fresh-proof');
  assert.deepEqual(h.tokens, ['fresh-proof']); assert.deepEqual(h.removals, [old.id]); h.unmount();
});

test('external reset targets only the currently eligible widget', () => {
  const h = fixture({ ready: true }); h.render(); h.resetRef.current(); assert.deepEqual(h.resets, ['widget-1']);
  h.render({ active: false }); h.resetRef.current(); assert.deepEqual(h.resets, ['widget-1']);
  h.render({ active: true }); h.resetRef.current(); assert.deepEqual(h.resets, ['widget-1', 'widget-2']); h.unmount();
});

test('unmount before the lazy provider is ready cancels polling and fences an already queued loader callback', () => {
  const h = fixture(); h.render(); const queued = [...h.intervals.values()][0]; assert.ok(queued);
  h.unmount(); assert.equal(h.intervals.size, 0); h.providerReady(); queued(); assert.equal(h.renders.length, 0);
});

test('retry before script readiness shares one loader while old polling callbacks stay invalid', () => {
  const h = fixture(); h.render(); const queued = [...h.intervals.values()][0];
  h.render({ active: false }); h.render({ active: true }); assert.equal(h.appended.length, 1); assert.equal(h.intervals.size, 1);
  h.providerReady(); queued(); assert.equal(h.renders.length, 0); h.poll(); assert.equal(h.renders.length, 1); h.unmount();
});
