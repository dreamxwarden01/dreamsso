import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const root = new URL('../', import.meta.url);
function sourceModule(file: string, dependencies: Record<string, any>, globals: Record<string, any> = {}) {
  const source = fs.readFileSync(new URL(file, root), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  const exports = {};
  vm.runInNewContext(output, { exports, require: (name: string) => {
    assert.ok(Object.hasOwn(dependencies, name), 'unexpected import: ' + name); return dependencies[name];
  }, console: { error() {} }, Date, Intl, ...globals }, { filename: file });
  return exports as any;
}
function deferred() { let resolve!: (value: any) => void, reject!: (error: any) => void;
  return { promise: new Promise((yes, no) => { resolve = yes; reject = no; }), resolve, reject }; }
const now = 1800000000000;
const sendBody = (requestId: string | undefined, patch: Record<string, any> = {}) => ({ result: 'sent', request_id: requestId,
  mail: { state: 'sent', at: new Date(now).toISOString(), error_code: null }, expires_at: new Date(now + 3600000).toISOString(), resend_backoff: 60, ...patch });
const invitation = (patch = {}) => ({ code: 'ABCD1234EFGH', label: 'Course access', status: 'unused',
  role: { id: 'fixture-role', name: 'Member' }, created_at: new Date(now - 3600000).toISOString(),
  expires_at: new Date(now + 3600000).toISOString(), bound_email: null, mail: { state: 'none', at: null }, ...patch });

// Execute the actual React page and its actual invitation/feedback helpers with
// deterministic hook scheduling and browser/API dependencies. No replica of the
// page state machine, external DOM, live settings, network or credentials.
function clientFixture(page: 'start' | 'complete' = 'start', options: Record<string, any> = {}) {
  let time = now, dirty = true, index = 0, tree: any, nextTimer = 0, sequence = 0, tokenResets = 0, siteRefreshes = 0, stateUpdates = 0;
  const slots: any[] = [], effects: Function[] = [], timers = new Map<number, any>(), calls: any[] = [], redirects: string[] = [];
  const storage = options.storage || new Map();
  const finishCallbacks: { phase: string; callback: Function }[] = [];
  let params = new URLSearchParams(options.query ?? (page === 'start' ? 'code=ABCD1234EFGH' : 'email=alex%40example.test&token=synthetic-proof'));
  const settings = { siteName: 'Example', registrationEnabled: true, invitationRequired: true, turnstileSiteKey: null, ...options.site };
  const react = {
    useState(initial: any) { const slot = index++; if (!slots[slot]) slots[slot] = { value: typeof initial === 'function' ? initial() : initial };
      return [slots[slot].value, (next: any) => { const value = typeof next === 'function' ? next(slots[slot].value) : next;
        if (!Object.is(value, slots[slot].value)) { slots[slot].value = value; dirty = true; stateUpdates++; } }]; },
    useRef(initial: any) { const slot = index++; if (!slots[slot]) slots[slot] = { current: initial }; return slots[slot]; },
    useEffect(effect: Function, deps: any[]) { const slot = index++, previous = slots[slot];
      if (!previous || deps.some((value, n) => !Object.is(value, previous.deps[n]))) {
        effects.push(() => { previous?.cleanup?.(); slots[slot] = { deps, cleanup: effect() }; });
      } },
  };
  const jsx = (type: any, props: any) => ({ type, props: props || {} });
  const runtime = { jsx, jsxs: jsx, Fragment: Symbol('fragment') };
  const clock = new Proxy(Date, { get(target, key) { return key === 'now' ? () => time : Reflect.get(target, key); },
    construct(target, args) { return Reflect.construct(target, args.length ? args : [time]); } });
  const globals = { Date: clock, setTimeout: (fn: Function, ms: number) => { const id = ++nextTimer; timers.set(id, { fn, at: time + ms }); return id; },
    clearTimeout: (id: number) => timers.delete(id),
    setInterval: (fn: Function, ms: number) => { const id = ++nextTimer; timers.set(id, { fn, at: time + ms, interval: ms }); return id; },
    clearInterval: (id: number) => timers.delete(id),
    sessionStorage: { getItem: (key: string) => storage.get(key) || null, setItem: (key: string, value: string) => storage.set(key, value), removeItem: (key: string) => { storage.delete(key); } },
    crypto: { randomUUID: () => `00000000-0000-4000-8000-${String((options.uuidOffset || 0) + ++sequence).padStart(12, '0')}` },
    window: { location: { replace: (value: string) => redirects.push(value) } },
  };
  const helpers = sourceModule('account/client/src/components/registration/invitation.js', {}, globals);
  const Icon = () => null;
  const ui = sourceModule('account/client/src/components/registration/RecipientUi.jsx', {
    react, 'react/jsx-runtime': runtime, '../Icon.jsx': { __esModule: true, default: Icon }, './invitation.js': helpers, './recipient.css': {},
  }, globals);
  // Observe the page's actual delayed continuations without replacing either
  // their implementation or the real feedback hook/timer. Tests can deliver a
  // captured continuation after a ceremony switch, independently of cancellation.
  const actualUseFeedback = ui.useRecipientFeedback;
  const observedUi = { ...ui, useRecipientFeedback: (...args: any[]) => {
    const feedback = actualUseFeedback(...args);
    return { ...feedback, finish: (phase: string, callback: Function) => {
      finishCallbacks.push({ phase, callback }); return feedback.finish(phase, callback);
    } };
  } };
  const defaults: any = {
    registerInvitation: async () => ({ invitation: invitation() }),
    // No receipt is assumed by default: a code/UUID alone cannot acknowledge a send.
    registerRequestStatus: async () => { throw { status: 404, code: 'request_not_found' }; },
    registerStart: async (_email: string, _code: string, _proof: string, requestId: string) => sendBody(requestId),
    registerValidate: async () => ({ email: 'alex@example.test', bound_email: 'alex@example.test', expires_at: new Date(time + 3600000).toISOString(),
      invitation: invitation({ bound_email: 'alex@example.test' }) }),
    registerCheckUsername: async () => ({ available: true }), registerComplete: async () => ({ complete_url: '/welcome?ticket=synthetic-ticket' }),
  };
  const api = Object.fromEntries(Object.keys(defaults).map(name => [name, async (...args: any[]) => {
    calls.push({ name, args }); return (options.api?.[name] || defaults[name])(...args);
  }]));
  const passwordRules = sourceModule('account/client/src/components/PasswordRules.jsx', { 'react/jsx-runtime': runtime }, globals);
  const Page = sourceModule('account/client/src/pages/' + (page === 'start' ? 'RegisterStartPage.jsx' : 'RegisterCompletePage.jsx'), {
    react, 'react/jsx-runtime': runtime, 'react-router-dom': { useSearchParams: () => [params] },
    '../context/SiteContext.jsx': { useSite: () => ({ ...settings, refreshSite() { siteRefreshes++; } }) },
    '../components/AuthCard.jsx': { __esModule: true, default: (props: any) => jsx('auth-card', { ...props, children: [props.title, props.sub, props.children, props.cta] }) },
    '../components/Turnstile.jsx': { __esModule: true, default: (props: any) => {
      if (!settings.turnstileSiteKey || props.active === false) return null;
      if (props.resetRef) props.resetRef.current = () => { tokenResets++; };
      return jsx('turnstile', props);
    } },
    '../components/Icon.jsx': { __esModule: true, default: Icon },
    '../components/PasswordRules.jsx': passwordRules,
    '../api.js': api, '../components/registration/invitation.js': helpers, '../components/registration/RecipientUi.jsx': observedUi,
  }, globals).default;
  function expand(node: any): any {
    if (Array.isArray(node)) return node.map(expand);
    if (!node || typeof node !== 'object') return node;
    if (typeof node.type === 'function') return expand(node.type(node.props));
    return { ...node, props: { ...node.props, children: expand(node.props.children) } };
  }
  function walk(node: any, predicate: (value: any) => boolean): any[] {
    if (Array.isArray(node)) return node.flatMap(child => walk(child, predicate));
    if (!node || typeof node !== 'object') return [];
    return [...(predicate(node) ? [node] : []), ...walk(node.props?.children, predicate)];
  }
  const fixture = {
    calls, redirects, storage, helpers, uuidCount: () => sequence, tokenResetCount: () => tokenResets,
    refreshCount: () => siteRefreshes, stateUpdateCount: () => stateUpdates, finishCallbacks,
    async flush() {
      for (let n = 0; n < 30; n++) {
        if (dirty) { dirty = false; index = 0; tree = Page(); for (const run of effects.splice(0)) run(); }
        await new Promise(resolve => setImmediate(resolve));
        if (!dirty && !effects.length) return;
      }
      throw new Error('render did not settle');
    },
    nodes: (predicate: (node: any) => boolean) => walk(expand(tree), predicate),
    field(id: string) { const node = this.nodes(node => node.props.id === id)[0]; assert.ok(node, 'missing field ' + id); return node; },
    // Delivers onChange, not a native paste. Browser maxLength is checked separately.
    async input(id: string, value: string) { this.field(id).props.onChange({ target: { value } }); await this.flush(); },
    async blur(id: string) { const handler = this.field(id).props.onBlur; assert.equal(typeof handler, 'function', id + ' blur handler'); handler(); await this.flush(); },
    prove(token = 'synthetic-human-proof') { const widget = this.nodes(node => node.type === 'turnstile')[0]; assert.ok(widget, 'human widget must be eligible'); widget.props.onToken(token); },
    actionButton() { const button = this.nodes(node => node.type === 'button' && node.props.className?.includes('recipient-button'))[0]; assert.ok(button); return button; },
    openBanners() { return this.nodes(node => node.props.className === 'recipient-feedback' && node.props['data-open'] === true); },
    form() { const node = this.nodes(node => node.type === 'form')[0]; assert.ok(node, 'missing form'); return node; },
    async submit() { const pending = this.form().props.onSubmit({ preventDefault() {} }); await this.flush(); return pending; },
    text() { const collect = (node: any): string => Array.isArray(node) ? node.map(collect).join(' ') : !node ? '' : typeof node === 'object' ? collect(node.props?.children) : String(node);
      return collect(expand(tree)); },
    async advance(ms: number) { const end = time + ms;
      for (;;) { const due = [...timers].filter(([, timer]) => timer.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
        if (!due) break; const [id, timer] = due; time = timer.at; if (timer.interval) timer.at += timer.interval; else timers.delete(id);
        timer.fn(); await this.flush(); }
      time = end; await this.flush();
    },
    async setQuery(value: string) { params = new URLSearchParams(value); dirty = true; await this.flush(); },
    unmount() { for (const slot of slots) slot?.cleanup?.(); timers.clear(); },
  };
  return fixture;
}

function assertNoDetailCalls(h: { calls: any[] }) { assert.ok(h.calls.every(call => call.name === 'registerStart'), 'sender made a preview/status query'); }

test('plain txn signup first screen contains email, required invitation code and human verification together', async () => {
  const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key', ssoUrl: 'https://sso.example.test' } });
  await h.flush(); assert.equal(h.calls.length, 0);
  assert.equal(h.field('reg-email').props.readOnly, false); assert.equal(h.field('reg-code').props.value, '');
  assert.equal(h.field('reg-code').props.required, true); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  assert.doesNotMatch(h.text(), /Use your invitation|see the access it offers/);
  assert.ok(h.nodes(node => node.type === 'a' && node.props.href === 'https://sso.example.test/login?txn=synthetic-login-txn').length);
  h.unmount();
});

test('shared URL only prefills the code in that same form, with no initial invitation read', async () => {
  const h = clientFixture('start', { query: 'code=abcd1234efgh&txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' } });
  await h.flush(); assert.equal(h.calls.length, 0); assert.equal(h.field('reg-code').props.value, 'ABCD1234EFGH');
  assert.equal(h.field('reg-email').props.value, ''); assert.equal(h.field('reg-email').props.readOnly, false);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); h.unmount();
});

test('manual code is submitted with email and human proof directly, without any preflight', async () => {
  const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.input('reg-code', 'abcd1234efgh');
  await h.submit(); assert.equal(h.calls.length, 0);
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']);
  assert.equal(h.calls[0].args[0], 'alex@example.test'); assert.equal(h.calls[0].args[1], 'ABCD1234EFGH');
  assert.equal(h.calls[0].args[2], 'synthetic-human-proof'); assert.ok(h.calls[0].args[3]); h.unmount();
});

for (const status of ['used', 'expired', 'revoked', 'unavailable']) for (const withMetadata of [false, true]) {
  test('first-form ' + status + ' code is an editable inline issue without a read or banner' + (withMetadata ? ' (bound metadata)' : ''), async () => {
    const h = clientFixture('start', { api: { registerStart: async () => { throw { status: 409, code: 'invitation_' + status,
      ...(withMetadata ? { data: { invitation: invitation({ status, bound_email: 'alex@example.test' }) } } : {}),
    }; } } });
    await h.flush(); assert.equal(h.calls.length, 0); await h.input('reg-email', 'alex@example.test'); await h.submit();
    assert.equal(h.nodes(node => node.type === 'form').length, 1); assert.deepEqual(h.calls.map(call => call.name), ['registerStart']);
    const message = h.field('reg-code-error').props.children;
    assert.match(message, status === 'used' ? /used/i : status === 'expired' ? /expired/i : status === 'revoked' ? /withdrawn|revoked/i : /available|offered|changed|eligible/i);
    assert.equal(h.field('reg-code').props['aria-invalid'], true); assert.equal(h.field('reg-code').props['aria-describedby'], 'reg-code-error');
    assert.equal(h.field('reg-code').props.readOnly, false); assert.equal(h.openBanners().length, 0); h.unmount();
  });
}

for (const [raw, normalized] of [['', ''], ['A', 'A'], ['ABCD1234EFG', 'ABCD1234EFG'], ['abc-12!', 'ABC12']]) {
  test('required malformed code is blocked locally without starting human verification: ' + (raw || 'empty'), async () => {
    const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' } });
    await h.flush(); await h.input('reg-email', 'alex@example.test'); if (raw) await h.input('reg-code', raw);
    assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
    assert.equal(h.field('reg-code').props.value, normalized); assert.equal(h.actionButton().props.disabled, true);
    // Invoke the actual form handler directly: disabled-button DOM behavior is
    // insufficient protection against Enter/programmatic submit paths.
    await h.submit(); await h.advance(2500);
    assert.deepEqual(h.calls, []); assert.equal(h.uuidCount(), 0); assert.equal(h.storage.size, 0); assert.equal(h.tokenResetCount(), 0);
    await h.input('reg-code', 'ABCD1234EFGH'); h.prove('synthetic-fresh-human-proof'); await h.flush(); assert.equal(h.actionButton().props.disabled, false);
    await h.submit(); assert.equal(h.calls[0].name, 'registerStart'); assert.equal(h.calls[0].args[2], 'synthetic-fresh-human-proof');
    assert.equal(h.uuidCount(), 1); h.unmount();
  });
}

test('code blur marks invalid syntax inline; typing clears only the mark until the next blur', async () => {
  const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  assert.equal(h.field('reg-code').props['aria-invalid'], false);
  await h.blur('reg-code'); assert.equal(h.field('reg-code').props['aria-invalid'], true);
  assert.equal(h.field('reg-code').props['aria-describedby'], 'reg-code-error');
  assert.match(h.field('reg-code-error').props.children, /required/i); assert.equal(h.openBanners().length, 0);
  await h.input('reg-code', 'SHORT'); assert.equal(h.field('reg-code').props['aria-invalid'], false);
  assert.equal(h.field('reg-code-error').props.children, null); assert.equal(h.actionButton().props.disabled, true);
  await h.blur('reg-code'); assert.equal(h.field('reg-code').props['aria-invalid'], true);
  assert.match(h.field('reg-code-error').props.children, /12.character/i); assert.equal(h.openBanners().length, 0);
  await h.input('reg-code', 'abcd-1234 efgh'); assert.equal(h.field('reg-code').props.value, 'ABCD1234EFGH');
  assert.equal(h.field('reg-code').props['aria-invalid'], false); h.prove(); await h.flush(); assert.equal(h.actionButton().props.disabled, false);
  assert.equal(h.calls.length, 0); assert.equal(h.uuidCount(), 0); assert.equal(h.tokenResetCount(), 0); h.unmount();
});

for (const error of [
  { status: 422, data: { errors: { code: 'invalid_code' } } },
  { status: 422, code: 'invalid_invitation' },
]) test('well-formed unknown code has one inline server error, retained on blur until edited: ' + (error.code || 'errors.code'), async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => { throw error; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush();
  assert.equal(h.actionButton().props.disabled, false); await h.submit();
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); assert.equal(h.calls[0].args[1], 'ABCD1234EFGH');
  const message = h.field('reg-code-error').props.children;
  assert.match(message, error.code ? /was not found/ : /is invalid/);
  assert.equal(h.field('reg-code').props['aria-invalid'], true); assert.equal(h.field('reg-code').props['aria-describedby'], 'reg-code-error');
  assert.equal(h.field('reg-code-error').props.role, 'alert'); assert.equal(h.openBanners().length, 0);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  assert.equal(h.actionButton().props.disabled, true); await h.blur('reg-code');
  assert.equal(h.field('reg-code-error').props.children, message); await h.submit(); assert.equal(h.calls.length, 1);
  await h.input('reg-code', 'ZXCV5678BNMQ'); assert.equal(h.field('reg-code').props['aria-invalid'], false);
  h.prove('synthetic-next-human-proof'); await h.flush(); assert.equal(h.actionButton().props.disabled, false); assert.equal(h.openBanners().length, 0); h.unmount();
});

test('a definite code error can be edited immediately without waiting for feedback', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => { throw { status: 422, code: 'invalid_invitation' }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.field('reg-code').props.readOnly, false);
  assert.equal(h.field('reg-code').props['aria-invalid'], true); await h.input('reg-code', 'SHORT');
  assert.equal(h.field('reg-code').props['aria-invalid'], false); assert.equal(h.field('reg-code-error').props.children, null);
  assert.equal(h.openBanners().length, 0);
  await h.blur('reg-code'); assert.equal(h.field('reg-code').props['aria-invalid'], true);
  assert.match(h.field('reg-code-error').props.children, /12.character/i); assert.equal(h.calls.length, 1); h.unmount();
});

test('email blur and editing expose one inline error without opening a duplicate banner', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' } });
  await h.flush(); await h.input('reg-email', 'not-an-email');
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  assert.equal(h.actionButton().props.disabled, true); assert.equal(h.field('reg-email').props['aria-invalid'], false);
  await h.blur('reg-email'); assert.equal(h.field('reg-email').props['aria-invalid'], true);
  assert.equal(h.field('reg-email').props['aria-describedby'], 'reg-email-error');
  assert.match(h.field('reg-email-error').props.children, /valid email address/); assert.equal(h.openBanners().length, 0);
  await h.input('reg-email', 'still-invalid'); assert.equal(h.field('reg-email').props['aria-invalid'], false);
  assert.equal(h.actionButton().props.disabled, true); await h.blur('reg-email');
  assert.equal(h.field('reg-email').props['aria-invalid'], true); assert.equal(h.openBanners().length, 0);
  assert.equal(h.calls.length, 0); assert.equal(h.uuidCount(), 0); assert.equal(h.tokenResetCount(), 0); h.unmount();
});

for (const error of [
  { status: 422, data: { errors: { email: 'email_taken' } } },
  { status: 422, code: 'email_taken' },
  { status: 422, data: { errors: { email: 'invalid_email' } } },
  { status: 422, code: 'invalid_email' },
]) test('recipient email server error is inline only: ' + (error.code ? 'error=' + error.code : 'errors.email=' + error.data?.errors.email), async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => { throw error; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  const message = h.field('reg-email-error').props.children;
  assert.match(message, (error.code || error.data?.errors.email) === 'email_taken' ? /already registered/ : /valid email address/);
  assert.equal(h.field('reg-email').props['aria-invalid'], true); assert.equal(h.field('reg-email').props['aria-describedby'], 'reg-email-error');
  assert.equal(h.field('reg-email-error').props.role, 'alert'); assert.equal(h.openBanners().length, 0);
  assert.equal(h.field('reg-email').props.value, 'alex@example.test'); assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); h.unmount();
});

for (const initialState of ['sent', 'queued']) for (const rejection of [
  { status: 403, code: 'email_mismatch', field: 'email' },
  { status: 422, code: 'email_taken', field: 'email' },
  { status: 422, code: 'invalid_invitation', field: 'code' },
]) test('a ' + rejection.code + ' rejection after ' + initialState + ' restores the editable field without queries', async () => {
  let requests = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (++requests === 1) return sendBody(args[3], { result: initialState === 'sent' ? 'sent' : 'pending', mail: { state: initialState }, resend_backoff: 60 });
    throw { status: rejection.status, code: rejection.code, data: { ...sendBody(args[3], { mail: { state: 'failed' } }),
      bound_email: 'hidden@example.test', invitation: invitation({ bound_email: 'hidden@example.test' }) } };
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove(); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 0); await h.advance(initialState === 'sent' ? 60000 : 5000);
  h.prove('retry-proof'); await h.flush(); await h.actionButton().props.onClick(); await h.flush();
  assert.equal(h.nodes(node => node.type === 'form').length, 1);
  assert.equal(h.field('reg-email').props.value, 'alex@example.test'); assert.equal(h.field('reg-email').props.readOnly, false); assert.equal(h.field('reg-code').props.readOnly, false);
  assert.equal(h.field('reg-' + rejection.field).props['aria-invalid'], true); assert.ok(h.field('reg-' + rejection.field + '-error').props.children);
  assert.equal(h.openBanners().length, 0); assert.doesNotMatch(h.text(), /hidden@example.test/); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  assert.equal(h.calls.length, 2); if (initialState === 'queued') assert.equal(h.calls[0].args[3], h.calls[1].args[3]);
  assertNoDetailCalls(h); h.unmount();
});

for (const error of [
  { status: 0, code: 'timeout' }, { status: 403, code: 'turnstile_failed' },
  { status: 429, code: 'rate_limited', data: { can_retry: true, retry_after: 60 } },
  { status: 503, code: 'registration_unavailable' }, { status: 503, code: 'invitation_unavailable' },
]) test('overall request failure retains its banner: ' + error.code, async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => { throw error; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.openBanners().length, 1); assert.equal(h.field('reg-code').props['aria-invalid'], false);
  assert.equal(h.field('reg-email').props['aria-invalid'], false); assert.equal(h.calls.filter(call => call.name === 'registerStart').length, 1); h.unmount();
});

test('a failed server human check does not trigger invitation lookup or consume the form fields', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' },
    api: { registerStart: async () => { throw { status: 403, code: 'turnstile_failed' }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-expired-human-proof'); await h.flush(); await h.submit();
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); assert.equal(h.field('reg-email').props.value, 'alex@example.test');
  assert.equal(h.field('reg-code').props.value, 'ABCD1234EFGH'); assert.equal(h.field('reg-code').props.readOnly, false); assert.match(h.text(), /Human verification failed/); h.unmount();
});

for (const mismatch of ['email_mismatch', 'email_bound']) for (const fieldEnvelope of [false, true]) {
  test('first-form mismatch preserves the entered address without queries or metadata disclosure: ' + mismatch + (fieldEnvelope ? ' field' : ' top-level'), async () => {
    const hidden = 'hidden-recipient@example.test', note = 'synthetic-private-note', role = 'synthetic-private-role';
    const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => { throw {
      status: 403, ...(fieldEnvelope ? {} : { code: mismatch }),
      data: { ...(fieldEnvelope ? { errors: { email: mismatch } } : {}), email: hidden, bound_email: hidden,
        invitation: invitation({ bound_email: hidden, label: note, role: { id: role, name: role }, mail: { state: 'sent' } }) },
    }; } } });
    await h.flush(); assert.equal(h.calls.length, 0); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
    await h.input('reg-email', 'entered@example.test');
    h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
    assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); assert.equal(h.calls[0].args[0], 'entered@example.test');
    assert.equal(h.field('reg-email').props.value, 'entered@example.test'); assert.equal(h.field('reg-email').props.readOnly, false);
    assert.equal(h.field('reg-email').props['aria-invalid'], true); assert.match(h.field('reg-email-error').props.children, /email address.*invitation|invitation.*email address/i);
    assert.equal(h.nodes(node => node.props.id === 'recipient-email').length, 0); assert.equal(h.openBanners().length, 0);
    const rendered = JSON.stringify(h.nodes(() => true));
    for (const value of [hidden, note, role]) assert.ok(!rendered.includes(value), 'rejection metadata was rendered');
    assert.equal(h.nodes(node => node.type === 'turnstile').length, 0, 'known field rejection is not an eligible retry');
    await h.input('reg-email', 'another-owned@example.test');
    assert.equal(h.nodes(node => node.type === 'turnstile').length, 1); assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); h.unmount();
  });
}

for (const query of ['txn=synthetic-login-txn', 'code=ABCD1234EFGH&txn=synthetic-login-txn']) test('invitation feature off ignores code and keeps email plus human verification: ' + query.split('&')[0], async () => {
  const h = clientFixture('start', { query, site: { invitationRequired: false, turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => ({ sent: true, resend_backoff: 60 }) } });
  await h.flush(); assert.equal(h.calls.length, 0); assert.equal(h.nodes(node => node.props.id === 'reg-code').length, 0);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); assert.doesNotMatch(h.text(), /Use an invitation code/);
  await h.input('reg-email', 'alex@example.test'); h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.match(h.text(), /Check your email/); assert.equal(h.calls[0].args[1], undefined); assert.equal(h.calls[0].args[3], undefined);
  assert.equal(h.calls.filter(call => call.name === 'registerInvitation').length, 0); h.unmount();
});

for (const error of [
  { status: 422, data: { errors: { code: 'invalid_code' } } },
  { status: 422, code: 'invalid_invitation' },
]) test('stale invitation-OFF settings expose the server code error and refresh settings: ' + (error.code || 'errors.code'), async () => {
  const h = clientFixture('start', { query: 'code=ABCD1234EFGH&txn=synthetic-login-txn',
    site: { invitationRequired: false, turnstileSiteKey: 'synthetic-site-key' },
    api: { registerStart: async () => { throw error; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.props.id === 'reg-code').length, 0); assert.equal(h.openBanners().length, 1);
  assert.match(h.text(), /invitation code/i); assert.equal(h.refreshCount(), 1); assert.equal(h.uuidCount(), 0);
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']);
  assert.equal(h.calls[0].args[1], undefined); assert.equal(h.calls[0].args[3], undefined);
  assert.equal(h.field('reg-email').props.value, 'alex@example.test'); h.unmount();
});

test('definite free-registration mail failure leaves its email editable', async () => {
  const h = clientFixture('start', { query: '', site: { invitationRequired: false }, api: { registerStart: async () => { throw { status: 503, code: 'send_failed' }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.field('reg-email').props.readOnly, false); assert.match(h.text(), /could not send the email/); h.unmount();
});

test('provider acceptance moves directly from pending form to result without a success dwell or metadata disclosure', async () => {
  const send = deferred();
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: () => send.promise } });
  await h.flush(); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  await h.input('reg-email', 'entered@example.test'); h.prove('proof-once'); await h.flush();
  const pending = h.form().props.onSubmit({ preventDefault() {} }); await h.flush();
  assert.equal(h.field('reg-email').props.readOnly, true); assert.equal(h.field('reg-code').props.readOnly, true);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); assert.equal(h.calls[0].args[2], 'proof-once');
  const id = h.calls[0].args[3];
  send.resolve(sendBody(id, { email: 'hidden@example.test', bound_email: 'hidden@example.test', invitation: invitation({ bound_email: 'hidden@example.test', label: 'private-note' }) }));
  await pending; await h.flush();
  assert.equal(h.nodes(node => node.type === 'form').length, 0, 'result must not wait two seconds');
  assert.match(h.text(), /entered@example.test/); assert.doesNotMatch(h.text(), /hidden@example.test|private-note/);
  assert.equal(h.finishCallbacks.length, 0); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  await h.advance(59999); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  await h.advance(1); assert.equal(h.nodes(node => node.type === 'turnstile').length, 1);
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); h.unmount();
});

test('a submitted proof is unavailable while pending and must be replaced after a definite human-check failure', async () => {
  const send = deferred(); let requests = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (++requests === 1) return send.promise; return sendBody(args[3]);
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove('first-proof'); await h.flush();
  const pending = h.form().props.onSubmit({ preventDefault() {} }); await h.flush();
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); await h.submit(); assert.equal(h.calls.length, 1);
  send.reject({ status: 403, code: 'turnstile_failed' }); await pending; await h.flush();
  assert.equal(h.field('reg-email').props.readOnly, false); assert.equal(h.nodes(node => node.type === 'turnstile').length, 1);
  assert.equal(h.actionButton().props.disabled, true); await h.submit(); assert.equal(h.calls.length, 1);
  h.prove('fresh-proof'); await h.flush(); await h.submit();
  assert.deepEqual(h.calls.map(call => call.args[2]), ['first-proof', 'fresh-proof']); assertNoDetailCalls(h); h.unmount();
});

test('initial rate rejection keeps values editable but removes the widget until cooldown ends', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async () => { throw {
    status: 429, code: 'rate_limited', data: { retry_after: 5, can_retry: true },
  }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove(); await h.flush(); await h.submit();
  assert.equal(h.field('reg-email').props.readOnly, false); assert.equal(h.field('reg-code').props.readOnly, false);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); await h.submit(); assert.equal(h.calls.length, 1);
  await h.advance(4999); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  await h.advance(1); assert.equal(h.nodes(node => node.type === 'turnstile').length, 1);
  assert.equal(h.actionButton().props.disabled, true); assertNoDetailCalls(h); h.unmount();
});

for (const state of ['queued', 'sending']) test('rare pending response uses a five-second same-receipt retry despite server normal backoff: ' + state, async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) =>
    sendBody(args[3], { result: 'pending', mail: { state }, resend_backoff: 60 }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove('pending-first'); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 0); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  const id = h.calls[0].args[3]; await h.actionButton().props.onClick(); await h.flush(); assert.equal(h.calls.length, 1);
  await h.advance(5000); h.prove('pending-retry'); await h.flush(); await h.actionButton().props.onClick(); await h.flush();
  assert.equal(h.calls.length, 2); assert.equal(h.calls[1].args[3], id);
  assert.equal(h.calls[1].args[0], 'alex@example.test'); assert.equal(h.calls[1].args[1], 'ABCD1234EFGH');
  await h.advance(10000); assert.equal(h.calls.length, 2); assertNoDetailCalls(h); h.unmount();
});

for (const retryError of [
  { status: 403, code: 'turnstile_failed' },
  { status: 429, code: 'rate_limited', data: { retry_after: 5 } },
]) test('an uncertain transport retry retains its UUID and locked values across ' + retryError.code, async () => {
  let requests = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (++requests === 1) throw { status: 0, code: 'timeout' }; if (requests === 2) throw retryError; return sendBody(args[3]);
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove('transport-proof'); await h.flush(); await h.submit();
  assert.equal(h.field('reg-email').props.readOnly, true); assert.equal(h.field('reg-code').props.readOnly, true);
  await h.input('reg-email', 'must-not-change@example.test'); assert.equal(h.field('reg-email').props.value, 'alex@example.test');
  const id = h.calls[0].args[3]; h.prove('retry-proof'); await h.flush(); await h.submit();
  assert.equal(h.field('reg-email').props.readOnly, true); assert.equal(h.field('reg-code').props.readOnly, true);
  if (retryError.status === 429) { assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); await h.advance(5000); }
  h.prove('final-proof'); await h.flush(); await h.submit();
  assert.equal(h.calls.length, 3); assert.ok(h.calls.every(call => call.args[3] === id));
  assert.deepEqual(h.calls.map(call => call.args[2]), ['transport-proof', 'retry-proof', 'final-proof']);
  assert.equal(h.nodes(node => node.type === 'form').length, 0); assertNoDetailCalls(h); h.unmount();
});

for (const outcome of ['unknown', 'failed']) test('a settled ' + outcome + ' receipt permits a new UUID only on deliberate resend after cooldown', async () => {
  let requests = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (++requests > 1) return sendBody(args[3]);
    const data = sendBody(args[3], { result: outcome, mail: { state: outcome }, resend_backoff: 5 });
    if (outcome === 'failed') throw { status: 502, code: 'send_failed', data }; return data;
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove('first-proof'); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 0); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  const firstId = h.calls[0].args[3]; await h.actionButton().props.onClick(); await h.flush(); assert.equal(h.calls.length, 1);
  await h.advance(5000); h.prove('resend-proof'); await h.flush(); await h.actionButton().props.onClick(); await h.flush();
  assert.equal(h.calls.length, 2); assert.notEqual(h.calls[1].args[3], firstId); assertNoDetailCalls(h); h.unmount();
});

for (const asError of [false, true]) test('a response carrying somebody else’s receipt cannot settle this send' + (asError ? ' (failure)' : ''), async () => {
  let requests = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (++requests > 1) return sendBody(args[3]);
    const data = sendBody('00000000-0000-4000-8000-000000009999', { mail: { state: asError ? 'failed' : 'sent' } });
    if (asError) throw { status: 502, code: 'send_failed', data }; return data;
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove(); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 1); assert.equal(h.field('reg-email').props.readOnly, true);
  const id = h.calls[0].args[3]; h.prove('retry'); await h.flush(); await h.submit();
  assert.equal(h.calls[1].args[3], id); assertNoDetailCalls(h); h.unmount();
});

test('email configuration failure blocks repeated widgets and sends after the cooldown', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => { throw {
    status: 503, code: 'email_not_configured', data: sendBody(args[3], { result: 'failed', mail: { state: 'failed' }, resend_backoff: 5 }),
  }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove(); await h.flush(); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 0); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0);
  await h.advance(121000); assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); assert.equal(h.actionButton().props.disabled, true);
  await h.actionButton().props.onClick(); await h.flush(); assert.equal(h.calls.length, 1); assert.match(h.text(), /administrator|admin|set up/i); h.unmount();
});

for (const error of [
  { status: 400, code: 'already_authenticated' },
  { status: 422, code: 'invalid_request_id' },
  { status: 409, code: 'request_conflict' },
]) for (const priorUncertain of [false, true]) test('nonretryable ' + error.code + ' blocks proof/sends and preserves prior uncertainty=' + priorUncertain, async () => {
  let attempts = 0;
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async () => {
    if (priorUncertain && ++attempts === 1) throw { status: 0, code: 'timeout' }; throw error;
  } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); h.prove(); await h.flush(); await h.submit();
  if (priorUncertain) { h.prove('retry-proof'); await h.flush(); await h.submit(); }
  assert.equal(h.field('reg-email').props.readOnly, priorUncertain); assert.equal(h.field('reg-code').props.readOnly, priorUncertain);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); assert.equal(h.actionButton().props.disabled, true);
  assert.match(h.text(), error.code === 'already_authenticated' ? /already signed in|sign out/i : /new tab|can.t be retried/i);
  const calls = h.calls.length; await h.advance(121000); await h.submit();
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 0); assert.equal(h.calls.length, calls); assertNoDetailCalls(h); h.unmount();
});

test('retiring a failed receipt removes only its matching cached identity, not a competing replacement', () => {
  const h = clientFixture(), code = 'ABCD1234EFGH', email = 'alex@example.test';
  const original = h.helpers.registrationRequestId(code, email), otherAddress = h.helpers.registrationRequestId(code, 'other@example.test');
  const replacement = h.helpers.registrationRequestId(code, email, true); assert.notEqual(original, replacement);
  h.helpers.retireRegistrationRequest(code, email, original);
  assert.equal(h.helpers.registrationRequestId(code, email), replacement);
  h.helpers.retireRegistrationRequest(code, email.toUpperCase(), replacement);
  assert.notEqual(h.helpers.registrationRequestId(code, email), replacement);
  assert.equal(h.helpers.registrationRequestId(code, 'other@example.test'), otherAddress); h.unmount();
});

test('a configuration-failed receipt is retired so reload after repair can create a fresh request', async () => {
  const storage = new Map();
  const first = clientFixture('start', { storage, site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => { throw {
    status: 503, code: 'email_not_configured', data: sendBody(args[3], { result: 'failed', mail: { state: 'failed' }, resend_backoff: 5 }),
  }; } } });
  await first.flush(); await first.input('reg-email', 'alex@example.test'); first.prove(); await first.flush(); await first.submit();
  const oldId = first.calls[0].args[3]; assert.ok(oldId); assert.ok(![...storage.values()].includes(oldId)); first.unmount();
  const repaired = clientFixture('start', { storage, uuidOffset: 1000, site: { turnstileSiteKey: 'synthetic-key' } });
  await repaired.flush(); await repaired.input('reg-email', 'alex@example.test'); repaired.prove('fresh-after-repair'); await repaired.flush(); await repaired.submit();
  assert.equal(repaired.calls.length, 1); assert.notEqual(repaired.calls[0].args[3], oldId);
  assert.equal(repaired.nodes(node => node.type === 'form').length, 0); assertNoDetailCalls(repaired); repaired.unmount();
});

for (const state of ['transport-unknown', 'queued', 'sending', 'unknown', 'sent']) test('unsettled/nonfailed ' + state + ' receipt remains cached across reload', async () => {
  const storage = new Map();
  const first = clientFixture('start', { storage, site: { turnstileSiteKey: 'synthetic-key' }, api: { registerStart: async (...args: any[]) => {
    if (state === 'transport-unknown') throw { status: 0, code: 'network' };
    return sendBody(args[3], { result: state === 'queued' || state === 'sending' ? 'pending' : state, mail: { state }, resend_backoff: 60 });
  } } });
  await first.flush(); await first.input('reg-email', 'alex@example.test'); first.prove(); await first.flush(); await first.submit();
  const id = first.calls[0].args[3]; assert.ok([...storage.values()].includes(id)); first.unmount();
  const reloaded = clientFixture('start', { storage, uuidOffset: 1000 }); await reloaded.flush();
  assert.equal(reloaded.helpers.registrationRequestId('ABCD1234EFGH', 'alex@example.test'), id); assert.equal(reloaded.uuidCount(), 0);
  assertNoDetailCalls(first); assert.equal(reloaded.calls.length, 0); reloaded.unmount();
});

test('expired sent result uses its known private expiry without an unavailable deadline or metadata footer', async () => {
  const expiry = new Date(now + 1000).toISOString();
  const h = clientFixture('start', { api: { registerStart: async (...args: any[]) => sendBody(args[3], { expires_at: expiry }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit(); await h.advance(1000);
  assert.match(h.text(), /has expired/i); assert.ok(h.text().includes(h.helpers.formatInvitationTime(expiry)));
  assert.doesNotMatch(h.text(), /Deadline unavailable/i); assert.equal(h.nodes(node => node.props.className === 'recipient-meta').length, 0); h.unmount();
});

for (const outcome of ['success', 'failure']) test('a late ' + outcome + ' send response cannot overwrite a new ceremony or an unmounted page', async () => {
  for (const unmount of [false, true]) {
    const send = deferred(); const h = clientFixture('start', { api: { registerStart: () => send.promise } });
    await h.flush(); await h.input('reg-email', 'alex@example.test'); const pending = h.form().props.onSubmit({ preventDefault() {} }); await h.flush();
    const id = h.calls[0].args[3]; if (unmount) h.unmount(); else await h.setQuery('code=ZXCV5678BNMQ');
    const before = h.stateUpdateCount(); if (outcome === 'success') send.resolve(sendBody(id)); else send.reject({ status: 403, code: 'email_mismatch' });
    await pending; if (unmount) assert.equal(h.stateUpdateCount(), before); else {
      await h.flush(); assert.equal(h.field('reg-code').props.value, 'ZXCV5678BNMQ'); assert.equal(h.field('reg-email').props.value, '');
      assert.equal(h.nodes(node => node.type === 'form').length, 1); assert.equal(h.field('reg-email').props['aria-invalid'], false); h.unmount();
    }
    assertNoDetailCalls(h);
  }
});

test('two immediate form submits share the one in-flight operation', async () => {
  const send = deferred(); const h = clientFixture('start', { api: { registerStart: () => send.promise } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); const form = h.form();
  const first = form.props.onSubmit({ preventDefault() {} }), second = form.props.onSubmit({ preventDefault() {} });
  await h.flush(); assert.equal(h.calls.length, 1); send.resolve(sendBody(h.calls[0].args[3]));
  await Promise.all([first, second]); await h.flush(); assert.equal(h.nodes(node => node.type === 'form').length, 0); h.unmount();
});

test('registration link validates without Turnstile and final submit preserves password fields and the welcome ticket hop', async () => {
  const h = clientFixture('complete'); await h.flush();
  assert.deepEqual(h.calls.map(call => call.name), ['registerValidate']); assert.equal(h.field('recipient-email').props.readOnly, true);
  await h.input('reg-username', 'alex_demo'); await h.input('reg-name', 'Alex Demo'); await h.input('reg-pw', 'Synthetic1!'); await h.input('reg-cf', 'Synthetic1!');
  await h.submit(); const call = h.calls.find(call => call.name === 'registerComplete');
  assert.equal(call.args[0].email, 'alex@example.test'); assert.equal(call.args[0].token, 'synthetic-proof');
  assert.equal(call.args[0].password, 'Synthetic1!'); assert.equal(call.args[0].confirm_password, 'Synthetic1!');
  assert.equal(h.redirects.length, 0); await h.advance(1999); assert.equal(h.redirects.length, 0);
  await h.advance(1); assert.deepEqual(h.redirects, ['/welcome?ticket=synthetic-ticket']); h.unmount();
});

test('stale username availability responses cannot reject a newer username', async () => {
  const check = deferred(); const h = clientFixture('complete', { api: { registerCheckUsername: () => check.promise } });
  await h.flush(); await h.input('reg-username', 'old_name'); h.field('reg-username').props.onBlur();
  await h.input('reg-username', 'new_name'); check.resolve({ available: false }); await h.flush();
  assert.doesNotMatch(h.text(), /already taken/); h.unmount();
});

for (const status of ['used', 'expired', 'revoked', 'unavailable']) test('emailed proof retains the full ' + status + ' terminal notice', async () => {
  const h = clientFixture('complete', { api: { registerValidate: async () => { throw { status: 409, code: 'invitation_' + status,
    data: { invitation: invitation({ status, bound_email: 'alex@example.test' }) } }; } } });
  await h.flush(); assert.equal(h.nodes(node => node.type === 'form').length, 0);
  assert.deepEqual(h.calls.map(call => call.name), ['registerValidate']);
  assert.match(h.text(), status === 'used' ? /already been used/ : status === 'expired' ? /has expired/ : status === 'revoked' ? /was withdrawn/ : /no longer available/); h.unmount();
});

test('transport failure while checking a mail proof is retryable, not mislabeled expired', async () => {
  const h = clientFixture('complete', { api: { registerValidate: async () => { throw { code: 'timeout', status: 0 }; } } });
  await h.flush(); assert.match(h.text(), /Unable to check/); assert.doesNotMatch(h.text(), /has expired/); assert.match(h.text(), /Try again/); h.unmount();
});

test('exact deadline and unknown metadata fail closed in the actual shared helper', () => {
  const h = clientFixture();
  assert.equal(h.helpers.invitationStatus(invitation(), now + 3600000), 'expired');
  assert.equal(h.helpers.invitationStatus(invitation({ expires_at: 'bad' }), now), 'unavailable');
  assert.equal(h.helpers.invitationStatus(invitation({ status: 'mystery' }), now), 'unavailable');
  const value = h.helpers.formatInvitationTime(new Date(2026, 10, 18, 9, 4).toISOString());
  assert.match(value, /^2026\/11\/18 09:04 AM .+$/);
});

test('final account submit requires its own current human proof when configured', async () => {
  const h = clientFixture('complete', { site: { turnstileSiteKey: 'synthetic-key' } });
  await h.flush(); await h.input('reg-username', 'alex_demo'); await h.input('reg-name', 'Alex Demo');
  await h.input('reg-pw', 'Synthetic1!'); await h.input('reg-cf', 'Synthetic1!'); await h.submit();
  assert.equal(h.calls.filter(call => call.name === 'registerComplete').length, 0);
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-final-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.calls.find(call => call.name === 'registerComplete').args[0].turnstile_token, 'synthetic-final-human-proof'); h.unmount();
});

test('a completed account is not relabeled expired during the two-second success feedback', async () => {
  const h = clientFixture('complete', { api: { registerValidate: async () => ({ email: 'alex@example.test', bound_email: 'alex@example.test',
    expires_at: new Date(now + 1000).toISOString(), invitation: invitation({ bound_email: 'alex@example.test', expires_at: new Date(now + 1000).toISOString() }) }) } });
  await h.flush(); await h.input('reg-username', 'alex_demo'); await h.input('reg-name', 'Alex Demo');
  await h.input('reg-pw', 'Synthetic1!'); await h.input('reg-cf', 'Synthetic1!'); await h.submit();
  await h.advance(1000); assert.doesNotMatch(h.text(), /has expired/); await h.advance(1000);
  assert.deepEqual(h.redirects, ['/welcome?ticket=synthetic-ticket']); h.unmount();
});

test('failed final validation preserves all signup fields and a persistent below-button error', async () => {
  const h = clientFixture('complete', { api: { registerComplete: async () => { throw { status: 422, data: { errors: { username: 'username_taken' } } }; } } });
  await h.flush(); await h.input('reg-username', 'alex_demo'); await h.input('reg-name', 'Alex Demo');
  await h.input('reg-pw', 'Synthetic1!'); await h.input('reg-cf', 'Synthetic1!'); await h.submit(); await h.advance(2000);
  assert.equal(h.field('reg-pw').props.value, 'Synthetic1!'); assert.equal(h.field('reg-name').props.value, 'Alex Demo');
  assert.match(h.text(), /already taken/); assert.match(h.text(), /Check the highlighted fields/); assert.equal(h.redirects.length, 0); h.unmount();
});

function bffFixture(options: Record<string, any> = {}) {
  const routes = new Map(), calls: any[] = [];
  sourceModule('account/server/src/routes/register.ts', {
    express: { Router: () => ({ post: (path: string, handler: Function) => routes.set(path, handler) }) },
    '../session.js': { getSession: async () => { calls.push(['session']); return null; } },
    './auth.js': { SESSION_COOKIE: 'acct_sid' },
    './reset.js': {
      enforceTurnstileGate: async () => { calls.push(['turnstile']); return options.human !== false; },
      s2sPost: async (path: string, body: any) => { calls.push([path, body]); return new Response(JSON.stringify(options.upstream || sendBody(undefined)), { status: options.status || 200, headers: { 'content-type': 'application/json' } }); },
      mirror: async (res: any, response: Response) => res.status(response.status).json(await response.json()),
    },
  });
  return { calls, hasRoute: (path: string) => routes.has(path), async request(path: string, body: any) {
    const res = { code: 200, body: null as any, headers: {} as any,
      status(code: number) { this.code = code; return this; }, json(value: any) { this.body = value; return this; },
      set(name: string, value: string) { this.headers[name] = value; return this; } };
    await routes.get(path)({ body, cookies: {} }, res); return res;
  } };
}

test('retired code preview returns no data and receipt-status route is absent', async () => {
  const h = bffFixture({ upstream: { bound_email: 'hidden@example.test' } });
  const res = await h.request('/api/register/invitation', { code: 'ABCD1234EFGH', email: 'alex@example.test', request_id: '00000000-0000-4000-8000-000000000001' });
  assert.equal(res.code, 404); assert.deepEqual(h.calls, []); assert.ok(!JSON.stringify(res.body).includes('hidden@example.test'));
  assert.equal(h.hasRoute('/api/register/status'), false);
});

test('mail send keeps Turnstile first and forwards only the request UUID plus approved fields', async () => {
  const h = bffFixture(); await h.request('/api/register/start', { email: 'alex@example.test', code: 'ABCD1234EFGH',
    request_id: '00000000-0000-4000-8000-000000000001', role: 'injected-role', bound_email: 'injected@example.test' });
  assert.deepEqual(h.calls.map(call => call[0]), ['turnstile', 'session', '/internal/register/start']);
  assert.equal(h.calls[2][1].request_id, '00000000-0000-4000-8000-000000000001');
  assert.equal(h.calls[2][1].role, undefined); assert.equal(h.calls[2][1].bound_email, undefined);
  const denied = bffFixture({ human: false }); await denied.request('/api/register/start', {}); assert.deepEqual(denied.calls, [['turnstile']]);
});

test('proof validation is ungated and final account creation remains human-gated', async () => {
  const h = bffFixture(); await h.request('/api/register/validate', { email: 'alex@example.test', token: 'synthetic-proof', password: 'ignored' });
  assert.deepEqual(h.calls.map(call => call[0]), ['/internal/register/validate']); assert.equal(h.calls[0][1].password, undefined);
  const denied = bffFixture({ human: false }); await denied.request('/api/register/complete', {}); assert.deepEqual(denied.calls, [['turnstile']]);
});

test('BFF defers code and email policy to SSO after the human gate, including malformed supplied values', async () => {
  const h = bffFixture();
  await h.request('/api/register/start', { email: 'not-an-email', code: 'not-a-code' });
  assert.deepEqual(h.calls.map(call => call[0]), ['turnstile', 'session', '/internal/register/start']);
  assert.equal(h.calls[2][1].email, 'not-an-email');
  assert.equal(h.calls[2][1].code, 'NOT-A-CODE');
  const denied = bffFixture({ human: false });
  await denied.request('/api/register/start', { email: 'not-an-email', code: 'not-a-code' });
  assert.deepEqual(denied.calls, [['turnstile']]);
});
for (const status of [200, 202, 502, 503]) test('BFF projects a real JSON provider outcome without recipient metadata: ' + status, async () => {
  const id = '00000000-0000-4000-8000-000000000001';
  const mail = { state: status === 200 ? 'sent' : status === 202 ? 'sending' : 'failed', at: new Date(now).toISOString(), error_code: null };
  const error = status === 503 ? 'email_not_configured' : 'send_failed';
  const payload = sendBody(id, { result: status === 200 ? 'sent' : status === 202 ? 'pending' : 'failed', mail,
    ...(status >= 400 ? { error } : {}), email: 'hidden@example.test', bound_email: 'hidden@example.test', invitation: invitation({ bound_email: 'hidden@example.test' }) });
  const h = bffFixture({ status, upstream: payload }); const res = await h.request('/api/register/start', { email: 'alex@example.test', code: 'ABCD1234EFGH', request_id: id });
  assert.equal(res.code, status); assert.deepEqual(JSON.parse(JSON.stringify(res.body)), {
    request_id: id, expires_at: payload.expires_at, resend_backoff: 60, mail,
    ...(status >= 400 ? { error } : { result: payload.result }), ...(status === 200 ? { sent: true } : {}),
  });
  assert.ok(!JSON.stringify(res.body).includes('hidden@example.test'));
});

test('actual client API exposes only the send action and performs no detail/status request', async () => {
  const calls: any[] = [], id = '00000000-0000-4000-8000-000000000001';
  const api = sourceModule('account/client/src/api.js', {}, { AbortSignal, fetch: async (path: string, options: any) => {
    calls.push([path, JSON.parse(options.body)]); return new Response(JSON.stringify(sendBody(id)), { headers: { 'content-type': 'application/json' } });
  } });
  await api.registerStart('alex@example.test', 'ABCD1234EFGH', 'synthetic-proof', id);
  assert.equal(api.registerRequestStatus, undefined); assert.equal(api.registerInvitation, undefined);
  assert.deepEqual(calls, [['/api/register/start', { email: 'alex@example.test', code: 'ABCD1234EFGH', request_id: id, turnstile_token: 'synthetic-proof' }]]);
});
