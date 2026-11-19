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
const invitation = (patch = {}) => ({ code: 'ABCD1234EFGH', label: 'Course access', status: 'unused',
  role: { id: 'fixture-role', name: 'Member' }, created_at: new Date(now - 3600000).toISOString(),
  expires_at: new Date(now + 3600000).toISOString(), bound_email: null, mail: { state: 'none', at: null }, ...patch });

// Execute the actual React page and its actual invitation/feedback helpers with
// deterministic hook scheduling and browser/API dependencies. No replica of the
// page state machine, external DOM, live settings, network or credentials.
function clientFixture(page: 'start' | 'complete' = 'start', options: Record<string, any> = {}) {
  let time = now, dirty = true, index = 0, tree: any, nextTimer = 0, sequence = 0;
  const slots: any[] = [], effects: Function[] = [], timers = new Map<number, any>(), calls: any[] = [], redirects: string[] = [];
  const storage = options.storage || new Map();
  let params = new URLSearchParams(options.query ?? (page === 'start' ? 'code=ABCD1234EFGH' : 'email=alex%40example.test&token=synthetic-proof'));
  const settings = { siteName: 'Example', registrationEnabled: true, invitationRequired: true, turnstileSiteKey: null, ...options.site };
  const react = {
    useState(initial: any) { const slot = index++; if (!slots[slot]) slots[slot] = { value: typeof initial === 'function' ? initial() : initial };
      return [slots[slot].value, (next: any) => { const value = typeof next === 'function' ? next(slots[slot].value) : next;
        if (!Object.is(value, slots[slot].value)) { slots[slot].value = value; dirty = true; } }]; },
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
    sessionStorage: { getItem: (key: string) => storage.get(key) || null, setItem: (key: string, value: string) => storage.set(key, value) },
    crypto: { randomUUID: () => `00000000-0000-4000-8000-${String(++sequence).padStart(12, '0')}` },
    window: { location: { replace: (value: string) => redirects.push(value) } },
  };
  const helpers = sourceModule('account/client/src/components/registration/invitation.js', {}, globals);
  const Icon = () => null;
  const ui = sourceModule('account/client/src/components/registration/RecipientUi.jsx', {
    react, 'react/jsx-runtime': runtime, '../Icon.jsx': { __esModule: true, default: Icon }, './invitation.js': helpers, './recipient.css': {},
  }, globals);
  const defaults: any = {
    registerInvitation: async () => ({ invitation: invitation() }),
    registerStart: async () => ({ queued: true, sent: false, email: 'alex@example.test', bound_email: 'alex@example.test', resend_backoff: 60,
      invitation: invitation({ bound_email: 'alex@example.test', mail: { state: 'queued', at: new Date(time).toISOString() } }) }),
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
    '../context/SiteContext.jsx': { useSite: () => ({ ...settings, refreshSite() {} }) },
    '../components/AuthCard.jsx': { __esModule: true, default: (props: any) => jsx('auth-card', { ...props, children: [props.title, props.sub, props.children, props.cta] }) },
    '../components/Turnstile.jsx': { __esModule: true, default: (props: any) => settings.turnstileSiteKey ? jsx('turnstile', props) : null },
    '../components/Icon.jsx': { __esModule: true, default: Icon },
    '../components/PasswordRules.jsx': passwordRules,
    '../api.js': api, '../components/registration/invitation.js': helpers, '../components/registration/RecipientUi.jsx': ui,
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
    calls, redirects, storage, helpers,
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
    async input(id: string, value: string) { this.field(id).props.onChange({ target: { value } }); await this.flush(); },
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

test('plain txn signup first screen contains email, required invitation code and human verification together', async () => {
  const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key', ssoUrl: 'https://sso.example.test' } });
  await h.flush(); assert.equal(h.calls.length, 0);
  assert.equal(h.field('reg-email').props.readOnly, false); assert.equal(h.field('reg-code').props.value, '');
  assert.equal(h.field('reg-code').props.required, true); assert.equal(h.nodes(node => node.type === 'turnstile').length, 1);
  assert.doesNotMatch(h.text(), /Use your invitation|see the access it offers/);
  assert.ok(h.nodes(node => node.type === 'a' && node.props.href === 'https://sso.example.test/login?txn=synthetic-login-txn').length);
  h.unmount();
});

test('shared URL only prefills the code in that same form, with no initial invitation read', async () => {
  const h = clientFixture('start', { query: 'code=abcd1234efgh&txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' } });
  await h.flush(); assert.equal(h.calls.length, 0); assert.equal(h.field('reg-code').props.value, 'ABCD1234EFGH');
  assert.equal(h.field('reg-email').props.value, ''); assert.equal(h.field('reg-email').props.readOnly, false);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 1); h.unmount();
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

for (const status of ['used', 'expired', 'revoked', 'unavailable']) test('send endpoint terminal state ' + status + ' is preserved after human-gated submission', async () => {
  const h = clientFixture('start', { api: { registerStart: async () => { throw { status: 409, code: 'invitation_' + status, data: { invitation: invitation({ status }) } }; } } });
  await h.flush(); assert.equal(h.calls.length, 0); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.nodes(node => node.type === 'form').length, 0); assert.equal(h.calls.length, 1);
  assert.match(h.text(), status === 'used' ? /already been used/ : status === 'expired' ? /has expired/ : status === 'revoked' ? /was withdrawn/ : /no longer available/); h.unmount();
});

for (const code of ['', 'BADBADBADBAD']) test('required code is checked by the send endpoint after human verification: ' + (code || 'missing'), async () => {
  const h = clientFixture('start', { query: 'txn=synthetic-login-txn', site: { turnstileSiteKey: 'synthetic-site-key' },
    api: { registerStart: async () => { throw code ? { status: 422, code: 'invalid_invitation' } : { status: 422, data: { errors: { code: 'invalid_code' } } }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); if (code) await h.input('reg-code', code);
  await h.submit(); assert.equal(h.calls.length, 0);
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); assert.equal(h.calls[0].args[1], code || undefined);
  assert.equal(h.calls[0].args[2], 'synthetic-human-proof'); await h.advance(2000);
  assert.equal(h.field('reg-email').props.value, 'alex@example.test'); assert.equal(h.field('reg-code').props.readOnly, false);
  assert.match(h.text(), code ? /invalid or cannot be used/ : /invitation code is required/); h.unmount();
});

test('a failed server human check does not trigger invitation lookup or consume the form fields', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-site-key' },
    api: { registerStart: async () => { throw { status: 403, code: 'turnstile_failed' }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-expired-human-proof'); await h.flush(); await h.submit(); await h.advance(2000);
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart']); assert.equal(h.field('reg-email').props.value, 'alex@example.test');
  assert.equal(h.field('reg-code').props.value, 'ABCD1234EFGH'); assert.equal(h.field('reg-code').props.readOnly, false); assert.match(h.text(), /Human verification failed/); h.unmount();
});

test('a human-gated binding mismatch can read and lock the authoritative invited address afterward', async () => {
  const h = clientFixture('start', { api: { registerStart: async () => { throw { status: 403, code: 'email_mismatch' }; },
    registerInvitation: async () => ({ invitation: invitation({ bound_email: 'bound@example.test' }) }) } });
  await h.flush(); assert.equal(h.calls.length, 0); await h.input('reg-email', 'wrong@example.test'); await h.submit();
  assert.deepEqual(h.calls.map(call => call.name), ['registerStart', 'registerInvitation']);
  assert.equal(h.field('recipient-email').props.value, 'bound@example.test'); assert.equal(h.field('recipient-email').props.readOnly, true);
  assert.match(h.text(), /recipient cannot be changed/); h.unmount();
});

test('queue acknowledgement is honest, send feedback holds two seconds, polling ends on provider acceptance', async () => {
  const h = clientFixture('start', { api: { registerInvitation: async () => ({ invitation: invitation({
    bound_email: 'alex@example.test', mail: { state: 'sent', at: new Date(now).toISOString() },
  }) }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.nodes(node => node.props['data-phase'] === 'done').length, 1);
  await h.advance(1999); assert.doesNotMatch(h.text(), /Email queued/);
  await h.advance(1); assert.match(h.text(), /Email queued/); assert.match(h.text(), /does not mean the email was delivered/);
  await h.advance(2000); assert.match(h.text(), /mail provider accepted/); const count = h.calls.length;
  await h.advance(6000); assert.equal(h.calls.length, count); h.unmount();
});

test('uncertain send keeps its email locked and retries the exact same UUID', async () => {
  let sends = 0;
  const h = clientFixture('start', { api: { registerStart: async () => { if (++sends <= 2) throw { code: 'timeout', status: 0 }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.field('reg-email').props.readOnly, true); assert.match(h.text(), /could not be confirmed/);
  await h.advance(2000); await h.submit();
  const sendsMade = h.calls.filter(call => call.name === 'registerStart'); assert.equal(sendsMade.length, 2);
  assert.equal(sendsMade[0].args[3], sendsMade[1].args[3]); assert.ok(sendsMade[0].args[3]); h.unmount();
});

test('definite queued acknowledgement followed by explicit resend uses a new UUID after cooldown', async () => {
  const next = invitation({ bound_email: 'alex@example.test', mail: { state: 'sent', at: new Date(now).toISOString() } });
  const h = clientFixture('start', { api: { registerStart: async () => ({ queued: true, sent: false, resend_backoff: 1, invitation: next }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit(); await h.advance(2000);
  await h.nodes(node => node.type === 'button' && node.props.className?.includes('recipient-button'))[0].props.onClick(); await h.flush();
  const sends = h.calls.filter(call => call.name === 'registerStart'); assert.equal(sends.length, 2); assert.notEqual(sends[0].args[3], sends[1].args[3]); h.unmount();
});

for (const query of ['txn=synthetic-login-txn', 'code=ABCD1234EFGH&txn=synthetic-login-txn']) test('invitation feature off ignores code and keeps email plus human verification: ' + query.split('&')[0], async () => {
  const h = clientFixture('start', { query, site: { invitationRequired: false, turnstileSiteKey: 'synthetic-site-key' }, api: { registerStart: async () => ({ sent: true, resend_backoff: 60 }) } });
  await h.flush(); assert.equal(h.calls.length, 0); assert.equal(h.nodes(node => node.props.id === 'reg-code').length, 0);
  assert.equal(h.nodes(node => node.type === 'turnstile').length, 1); assert.doesNotMatch(h.text(), /Use an invitation code/);
  await h.input('reg-email', 'alex@example.test'); h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit(); await h.advance(2000);
  assert.match(h.text(), /Check your email/); assert.match(h.text(), /30 minutes/); assert.equal(h.calls[0].args[1], undefined); assert.equal(h.calls[0].args[3], undefined);
  assert.equal(h.calls.filter(call => call.name === 'registerInvitation').length, 0); h.unmount();
});

test('definite free-registration mail failure leaves its email editable', async () => {
  const h = clientFixture('start', { query: '', site: { invitationRequired: false }, api: { registerStart: async () => { throw { status: 503, code: 'send_failed' }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit(); await h.advance(2000);
  assert.equal(h.field('reg-email').props.readOnly, false); assert.match(h.text(), /could not send the email/); h.unmount();
});

test('queued status polling pauses after two minutes without an infinite busy button', async () => {
  const h = clientFixture('start', { api: { registerInvitation: async () => ({ invitation: invitation({ bound_email: 'alex@example.test', mail: { state: 'queued' } }) }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit(); await h.advance(2000);
  await h.advance(122000); assert.match(h.text(), /still queued/);
  assert.equal(h.nodes(node => node.props['aria-busy'] === true).length, 0); const count = h.calls.length;
  await h.advance(10000); assert.equal(h.calls.length, count); assert.match(h.text(), /Check status/); h.unmount();
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

test('a replayed request with definitive failed delivery can be explicitly resent with a new UUID', async () => {
  const h = clientFixture('start', { api: { registerStart: async () => ({ queued: false, sent: false, resend_backoff: 1,
    invitation: invitation({ bound_email: 'alex@example.test', mail: { state: 'failed' } }) }) } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit(); await h.advance(2000);
  assert.match(h.text(), /Email not sent/); assert.equal(h.nodes(node => node.props['data-phase'] === 'busy').length, 0);
  await h.nodes(node => node.type === 'button' && node.props.className?.includes('recipient-button'))[0].props.onClick(); await h.flush();
  const sends = h.calls.filter(call => call.name === 'registerStart'); assert.equal(sends.length, 2);
  assert.notEqual(sends[0].args[3], sends[1].args[3]); h.unmount();
});

test('human verification is absent from previews and required only before sending or completing', async () => {
  const h = clientFixture('start', { site: { turnstileSiteKey: 'synthetic-key' } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.calls.filter(call => call.name === 'registerStart').length, 0);
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.calls.filter(call => call.name === 'registerStart')[0].args[2], 'synthetic-human-proof'); h.unmount();
});

test('final account submit requires its own current human proof when configured', async () => {
  const h = clientFixture('complete', { site: { turnstileSiteKey: 'synthetic-key' } });
  await h.flush(); await h.input('reg-username', 'alex_demo'); await h.input('reg-name', 'Alex Demo');
  await h.input('reg-pw', 'Synthetic1!'); await h.input('reg-cf', 'Synthetic1!'); await h.submit();
  assert.equal(h.calls.filter(call => call.name === 'registerComplete').length, 0);
  h.nodes(node => node.type === 'turnstile')[0].props.onToken('synthetic-final-human-proof'); await h.flush(); await h.submit();
  assert.equal(h.calls.find(call => call.name === 'registerComplete').args[0].turnstile_token, 'synthetic-final-human-proof'); h.unmount();
});

test('two immediate submits cannot enqueue twice before the component rerenders', async () => {
  const send = deferred(); const h = clientFixture('start', { api: { registerStart: () => send.promise } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  const form = h.form(), first = form.props.onSubmit({ preventDefault() {} }), second = form.props.onSubmit({ preventDefault() {} });
  await h.flush(); assert.equal(h.calls.filter(call => call.name === 'registerStart').length, 1);
  send.resolve({ queued: true, sent: false, invitation: invitation({ bound_email: 'alex@example.test', mail: { state: 'queued' } }) });
  await Promise.all([first, second]); await h.flush(); h.unmount();
});

test('authoritative mail failure keeps the recipient bound and shows an honest failure below the button', async () => {
  const h = clientFixture('start', { api: { registerStart: async () => { throw { status: 503, code: 'mail_failed',
    data: { invitation: invitation({ bound_email: 'alex@example.test', mail: { state: 'failed' } }) } }; } } });
  await h.flush(); await h.input('reg-email', 'alex@example.test'); await h.submit();
  assert.equal(h.field('recipient-email').props.value, 'alex@example.test'); assert.equal(h.field('recipient-email').props.readOnly, true);
  await h.advance(2000); assert.match(h.text(), /Email not sent/); assert.match(h.text(), /same address/);
  assert.doesNotMatch(h.text(), /mail provider accepted/); assert.equal(h.nodes(node => node.props.role === 'alert').length, 1); h.unmount();
});

test('a changed invitation link fences a late send response and resets old busy state', async () => {
  const send = deferred(); const h = clientFixture('start', { api: { registerStart: () => send.promise } });
  await h.flush(); await h.input('reg-email', 'alex@example.test');
  const pending = h.form().props.onSubmit({ preventDefault() {} }); await h.flush();
  await h.setQuery('code=ZXCV5678BNMQ');
  send.resolve({ queued: true, sent: false, invitation: invitation({ bound_email: 'old@example.test', mail: { state: 'queued' } }) });
  await pending; await h.flush(); assert.equal(h.nodes(node => node.props['aria-busy'] === true).length, 0);
  assert.equal(h.field('reg-email').props.value, ''); assert.doesNotMatch(h.text(), /old@example.test/); h.unmount();
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
      s2sPost: async (path: string, body: any) => { calls.push([path, body]); return options.upstream || { invitation: invitation() }; },
      mirror: async (res: any, body: any) => res.json(body),
    },
  });
  return { calls, async request(path: string, body: any) {
    const res = { code: 200, body: null as any, headers: {} as any,
      status(code: number) { this.code = code; return this; }, json(value: any) { this.body = value; return this; },
      set(name: string, value: string) { this.headers[name] = value; return this; } };
    await routes.get(path)({ body, cookies: {} }, res); return res;
  } };
}

test('actual BFF preview is code-only signed upstream read with no Turnstile or session effect', async () => {
  const h = bffFixture(); const res = await h.request('/api/register/invitation', { code: ' abcd 1234 efgh ', email: 'ignored@example.test', token: 'ignored-proof' });
  assert.equal(res.headers['Cache-Control'], 'no-store'); assert.equal(res.code, 200);
  assert.equal(h.calls.length, 1); assert.equal(h.calls[0][0], '/internal/register/invitation');
  assert.equal(JSON.stringify(h.calls[0][1]), JSON.stringify({ code: 'ABCD1234EFGH' }));
});

test('actual BFF rejects malformed preview without any upstream/human call', async () => {
  const h = bffFixture(); assert.equal((await h.request('/api/register/invitation', { code: 'bad' })).code, 422); assert.equal(h.calls.length, 0);
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
