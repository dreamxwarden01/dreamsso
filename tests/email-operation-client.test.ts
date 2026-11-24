import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

const root = new URL('../', import.meta.url);
const state = (patch = {}) => ({ email: 'old@example.test', email_verified: false, username: 'member', revision: '7', pending: null, ...patch });
const pending = { request_id: '11111111-1111-4111-8111-111111111111', kind: 'change', new_email: 'new@example.test', last_sent: 1800000000, expires_at: '2027-01-15T09:00:00Z' };
function deferred() { let resolve!: (value: any) => void, reject!: (error: any) => void;
  return { promise: new Promise((yes, no) => { resolve = yes; reject = no; }), resolve, reject }; }
function sourceModule(file: string, dependencies: Record<string, any>, globals = {}, extra = '') {
  const source = readFileSync(new URL(file, root), 'utf8') + extra;
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022,
    jsx: ts.JsxEmit.ReactJSX, esModuleInterop: true } }).outputText;
  const exports: any = {};
  vm.runInNewContext(js, { exports, require: (name: string) => { assert.ok(Object.hasOwn(dependencies, name), name); return dependencies[name]; },
    AbortSignal, AbortController, console: { error() {} }, ...globals });
  return exports;
}

// Actual source components with deterministic hooks and synthetic dependencies.
// Private component exports exist only in the transpiled test module.
function clientFixture(component = 'ChangeModal', options: any = {}) {
  let index = 0, dirty = true, tree: any, serial = 0, updates = 0;
  let params = new URLSearchParams(options.query ?? 'token=synthetic-email-proof');
  const slots: any[] = [], effects: Function[] = [], calls: any[] = [], notices: any[] = [], done: string[] = [];
  const same = (a: any[], b: any[]) => a.length === b.length && a.every((v, n) => Object.is(v, b[n]));
  const react = {
    useState(initial: any) { const n = index++; slots[n] ??= { value: typeof initial === 'function' ? initial() : initial };
      return [slots[n].value, (next: any) => { const value = typeof next === 'function' ? next(slots[n].value) : next;
        if (!Object.is(value, slots[n].value)) { slots[n].value = value; dirty = true; updates++; } }]; },
    useRef(value: any) { const n = index++; return slots[n] ??= { current: value }; },
    useCallback(fn: Function, deps: any[]) { const n = index++; if (!slots[n] || !same(slots[n].deps, deps)) slots[n] = { value: fn, deps }; return slots[n].value; },
    useEffect(effect: Function, deps: any[]) { const n = index++, previous = slots[n]; if (!previous || !same(previous.deps, deps)) effects.push(() => {
      previous?.cleanup?.(); slots[n] = { deps, cleanup: effect() }; }); },
    useId: () => 'synthetic-dialog',
    useLayoutEffect: () => {},
    cloneElement: (node: any, props: any) => ({ ...node, props: { ...node.props, ...props } }),
  };
  const jsx = (type: any, props: any) => ({ type, props: props || {} });
  const runtime = { jsx, jsxs: jsx, Fragment: 'fragment' };
  const defaults: any = { emailChangeCheck: async () => null, emailChangeStart: async (body: any) => ({ sent: true, new_email: body.new_email }),
    emailChangeGet: async () => state(), getStepupStatus: async () => ({ mode: 'email-change' }), getSecurity: async () => ({}),
    emailChangeResend: async () => ({}), emailChangeCancel: async () => null, emailVerifySend: async () => ({ sent: true }),
    usernameChangeCheck: async () => null, usernameChange: async () => ({ username: 'new-name' }), avatarUrl: (v: any) => v,
    verifyEmail: async () => ({ ok: true, kind: 'change' }) };
  const api = Object.fromEntries(Object.keys(defaults).map(name => [name, async (...args: any[]) => {
    calls.push({ name, args: JSON.parse(JSON.stringify(args)) }); return (options.api?.[name] || defaults[name])(...args);
  }]));
  let closed = 0, changed = 0;
  const reload = async () => { calls.push({ name: 'reload', args: [] }); return options.reload ? options.reload() : state(); };
  let props: any = { kind: 'email', st: state(), reload, onClose: () => { closed++; }, onChanged: () => { changed++; }, onDone: (msg: string) => done.push(msg), ...options.props };
  const dependencies: any = { react, 'react/jsx-runtime': runtime, 'react-router-dom': { NavLink: 'nav-link', useSearchParams: () => [params] },
    '../context/AuthContext.jsx': { useAuth: () => ({ can: () => true, user: { profile: {} }, reload: async () => {} }) },
    '../api.js': api, '../components/Icon.jsx': { default: 'icon' }, '../components/Modal.jsx': { default: 'modal' },
    '../components/StepUpModal.jsx': { default: 'step-up' }, '../components/Toast.jsx': { toast: { success: (msg: string) => notices.push({ kind: 'success', msg }), error: (msg: string) => notices.push({ kind: 'error', msg }) } },
    '../components/Avatar.jsx': { initials: () => 'AB' }, '../components/AvatarModal.jsx': { default: 'avatar-modal' }, '../components/AuthCard.jsx': { default: 'auth-card' } };
  // JSX default imports use ES-module identity just as the bundled components.
  for (const value of Object.values(dependencies) as any[]) if (value.default) value.__esModule = true;
  let sourceFile = 'account/client/src/pages/ProfilePage.jsx', extra = '\nexport { ChangeModal, EmailRow };';
  if (component === 'VerifyEmailPage') { sourceFile = 'account/client/src/pages/VerifyEmailPage.jsx'; extra = ''; }
  if (component === 'CreateInvitationDialog') {
    sourceFile = 'account/client/src/pages/org/invitations/InvitationDialogs.jsx'; extra = '';
    Object.assign(dependencies, { './InvitationIcon.jsx': { __esModule: true, default: 'invitation-icon' },
      './InvitationControls.jsx': { CopyInvitationButton: 'copy-button', InvitationButton: 'invitation-button', InvitationModal: 'invitation-modal', InvitationPicker: 'invitation-picker',
        useInvitationFeedback: () => ({ phase: 'idle', begin: () => true, reset() {}, finish() {} }), useInvitationTime: () => ({ close() {} }) },
      './invitationModel.js': { formatInvitationTime: () => 'synthetic deadline', invitationError: () => 'Generic invitation error', invitationLink: () => '', limitInvitationNote: (s: string) => s, VALIDITY: [] },
      './invitationApi.js': { loadInvitationRoles: async () => ({ roles: [{ slug: 'member', label: 'Member', editable: true }], default_role: 'member' }), loadInvitation: async () => ({}) },
      './invitationDraft.js': { DEFAULT_INVITATION_FORM: { email: '', note: '', delivery: 'email', role_slug: 'member', validity_hours: 72 }, clearInvitationDraft() {}, writeInvitationDraft: () => true } });
    props = { actor: 'synthetic-actor', initialForm: { email: 'new@example.test' }, onCreate: options.onCreate, onClose() {} };
  }
  const module = sourceModule(sourceFile, dependencies, { crypto: { randomUUID: () => `00000000-0000-4000-8000-${String(++serial).padStart(12, '0')}` }, sessionStorage: {} }, extra);
  const Component = ['ProfilePage', 'VerifyEmailPage'].includes(component) ? module.default : module[component];
  function walk(node: any, predicate: Function): any[] {
    if (Array.isArray(node)) return node.flatMap(v => walk(v, predicate));
    if (!node || typeof node !== 'object') return [];
    return [...(predicate(node) ? [node] : []), ...walk(node.props.children, predicate)];
  }
  const text = (node: any): string => Array.isArray(node) ? node.map(text).join(' ') : node && typeof node === 'object' ? text(node.props.children) : node == null || node === false ? '' : String(node);
  return { calls, notices, done, uuidCount: () => serial, closed: () => closed, changed: () => changed, updateCount: () => updates,
    async flush() { for (let n = 0; n < 30; n++) { if (dirty) { dirty = false; index = 0; tree = Component(props); effects.splice(0).forEach(run => run()); }
      await new Promise(resolve => setImmediate(resolve)); if (!dirty && !effects.length) return; } throw new Error('render did not settle'); },
    nodes(predicate: Function) { return walk(tree, predicate); }, text: () => text(tree),
    button(label: string) { const button = walk(tree, (n: any) => n.type === 'button' && text(n).trim() === label)[0]; assert.ok(button, label); return button; },
    async input(value: string) { const input = walk(tree, (n: any) => n.type === 'input')[0]; assert.ok(input); input.props.onChange({ target: { value } }); await this.flush(); },
    async click(label: string) { await this.button(label).props.onClick(); await this.flush(); },
    async render(patch: any) { props = { ...props, ...patch }; dirty = true; await this.flush(); },
    async setQuery(query: string) { params = new URLSearchParams(query); dirty = true; await this.flush(); },
    unmount() { slots.forEach(slot => slot?.cleanup?.()); },
  };
}

test('email start binds the displayed revision and preserves its UUID through step-up and uncertain HTTP retry', async () => {
  let attempts = 0;
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async (body: any) => {
    if (++attempts === 1) throw { code: 'step_up_required' };
    if (attempts === 2) throw { code: 'network_error' };
    return { sent: true, new_email: body.new_email };
  } } });
  await h.flush(); await h.input('NEW@example.test'); await h.click('Continue');
  const challenge = h.nodes((n: any) => n.type === 'step-up')[0]; assert.ok(challenge);
  await challenge.props.onSuccess(); await h.flush(); await h.click('Verify');
  const sends = h.calls.filter(c => c.name === 'emailChangeStart'); assert.equal(sends.length, 3);
  assert.deepEqual(sends[0].args[0], { new_email: 'new@example.test', expected_revision: '7', request_id: '00000000-0000-4000-8000-000000000001' });
  assert.ok(sends.every(c => JSON.stringify(c.args) === JSON.stringify(sends[0].args))); assert.equal(h.uuidCount(), 1); assert.equal(h.done.length, 1); h.unmount();
});

test('editing a previously attempted target fetches current state before allocating a fresh UUID', async () => {
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async () => { throw { code: 'network_error' }; } } });
  await h.flush(); await h.input('first@example.test'); await h.click('Continue'); await h.click('Back');
  await h.input('second@example.test'); await h.click('Continue');
  const sends = h.calls.filter(c => c.name === 'emailChangeStart'); assert.equal(sends.length, 2);
  assert.notEqual(sends[0].args[0].request_id, sends[1].args[0].request_id); assert.equal(sends[1].args[0].expected_revision, '7');
  assert.deepEqual(h.calls.map(c => c.name), ['emailChangeCheck', 'emailChangeStart', 'reload', 'reload', 'emailChangeCheck', 'emailChangeStart', 'reload']); h.unmount();
});

test('a changed revision while editing refreshes the displayed state instead of overwriting an unseen operation', async () => {
  const h = clientFixture('ChangeModal', { reload: async () => state({ revision: '8', pending }), api: { emailChangeStart: async () => { throw { code: 'network_error' }; } } });
  await h.flush(); await h.input('first@example.test'); await h.click('Continue'); await h.click('Back'); await h.input('second@example.test'); await h.click('Continue');
  assert.equal(h.changed(), 1); assert.equal(h.uuidCount(), 1); assert.equal(h.calls.filter(c => c.name === 'emailChangeStart').length, 1); h.unmount();
});

for (const code of ['email_change_changed', 'no_pending']) test('start ' + code + ' refreshes state and exits the stale ceremony', async () => {
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async () => { throw { status: code === 'no_pending' ? 404 : 409, code }; } } });
  await h.flush(); await h.input('new@example.test'); await h.click('Continue');
  assert.equal(h.changed(), 1); assert.equal(h.calls.at(-1).name, 'reload'); assert.doesNotMatch(h.text(), /Couldn't complete/); h.unmount();
});

test('a final start-time email collision returns to the existing input with its inline error', async () => {
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async () => { throw { status: 409, code: 'email_taken', data: { errors: { email: 'email_taken' } } }; } } });
  await h.flush(); await h.input('new@example.test'); await h.click('Continue');
  assert.match(h.text(), /already registered/); assert.equal(h.nodes((n: any) => n.type === 'input')[0].props.value, 'new@example.test');
  assert.equal(h.nodes((n: any) => n.props.className === 'err').length, 0); assert.ok(h.button('Continue')); h.unmount();
});

for (const kind of ['change', 'confirm']) for (const action of ['Resend', 'Cancel']) test(kind + ' ' + action + ' targets the rendered pending ID, never a replacement', async () => {
  const wait = deferred(); const name = action === 'Resend' ? 'emailChangeResend' : 'emailChangeCancel';
  const h = clientFixture('EmailRow', { props: { st: state({ pending: { ...pending, kind } }) }, api: { [name]: () => wait.promise } });
  await h.flush(); const old = h.nodes((n: any) => n.type === 'a' && n.props.href === '#' + action.toLowerCase())[0];
  old.props.onClick({ preventDefault() {} }); await h.flush();
  await h.render({ st: state({ revision: '8', pending: { ...pending, request_id: '22222222-2222-4222-8222-222222222222', kind } }) });
  assert.equal(h.calls[0].args[0], pending.request_id); wait.reject({ code: 'email_change_changed', status: 409 }); await h.flush();
  assert.equal(h.calls.filter(c => c.name === name).length, 1); assert.equal(h.calls.at(-1).name, 'reload');
  assert.match(h.notices.at(-1).msg, /changed|expired/); h.unmount();
});

test('confirm-current preserves the same displayed revision and UUID after uncertain transport', async () => {
  let count = 0; const h = clientFixture('EmailRow', { api: { emailVerifySend: async () => { if (++count === 1) throw { code: 'network_error' }; return { sent: true }; } } });
  await h.flush(); await h.click('Verify'); await h.click('Verify');
  const sends = h.calls.filter(c => c.name === 'emailVerifySend'); assert.equal(sends.length, 2); assert.deepEqual(sends[0].args, sends[1].args);
  assert.equal(sends[0].args[0].expected_revision, '7'); assert.equal(h.uuidCount(), 1); assert.equal(h.calls.at(-1).name, 'reload'); h.unmount();
});

test('a legacy/missing pending ID causes refresh without a resend or cancellation mutation', async () => {
  const h = clientFixture('EmailRow', { props: { st: state({ pending: { ...pending, request_id: undefined } }) } });
  await h.flush(); h.nodes((n: any) => n.type === 'a' && n.props.href === '#cancel')[0].props.onClick({ preventDefault() {} }); await h.flush();
  assert.deepEqual(h.calls.map(c => c.name), ['reload']); assert.equal(h.notices.length, 1); h.unmount();
});

test('late start responses cannot update an unmounted change ceremony', async () => {
  const wait = deferred(); const h = clientFixture('ChangeModal', { api: { emailChangeStart: () => wait.promise } });
  await h.flush(); await h.input('new@example.test'); const attempt = h.button('Continue').props.onClick(); await h.flush(); h.unmount(); const before = h.updateCount();
  wait.resolve({ sent: true, new_email: 'new@example.test' }); await attempt; await h.flush();
  assert.equal(h.updateCount(), before); assert.deepEqual(h.done, []);
});

test('a cancelled step-up cannot later restart an old email attempt', async () => {
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async () => { throw { code: 'step_up_required' }; } } });
  await h.flush(); await h.input('new@example.test'); await h.click('Continue');
  const challenge = h.nodes((n: any) => n.type === 'step-up')[0]; challenge.props.onCancel(); await h.flush();
  challenge.props.onSuccess(); await h.flush();
  assert.equal(h.calls.filter(c => c.name === 'emailChangeStart').length, 1); assert.equal(h.uuidCount(), 1); h.unmount();
});

test('expired pending actions refresh without claiming a cancellation succeeded', async () => {
  const h = clientFixture('EmailRow', { props: { st: state({ pending }) }, api: { emailChangeCancel: async () => { throw { code: 'no_pending', status: 404 }; } } });
  await h.flush(); h.nodes((n: any) => n.type === 'a' && n.props.href === '#cancel')[0].props.onClick({ preventDefault() {} }); await h.flush();
  assert.equal(h.calls.at(-1).name, 'reload'); assert.deepEqual(h.notices.map(n => n.kind), ['error']); assert.match(h.notices[0].msg, /expired/); h.unmount();
});

test('profile account reload keeps the newest coherent snapshot and ignores a late earlier GET', async () => {
  const old = deferred(), recent = deferred(); let reads = 0;
  const h = clientFixture('ProfilePage', { api: { emailChangeGet: () => ++reads === 1 ? old.promise : recent.promise } });
  await h.flush(); const row = h.nodes((n: any) => n.type?.name === 'EmailRow')[0]; assert.ok(row);
  const refresh = row.props.reload(); recent.resolve(state({ revision: '8', pending })); await refresh; await h.flush();
  old.resolve(state({ revision: '7' })); await h.flush();
  assert.equal(h.nodes((n: any) => n.type?.name === 'EmailRow')[0].props.st.revision, '8'); h.unmount();
});

for (const error of [{ status: 503, code: 'send_failed' }, { status: 503, code: 'send_unconfirmed' },
  { status: 503, code: 'email_change_unavailable' }, { status: 0, code: 'request_timeout', uncertain: true }]) {
  test('possible committed operation after ' + error.code + ' refreshes state without replacing the attempt or reporting Sent', async () => {
    const fresh = state({ revision: '8', pending });
    const h = clientFixture('ChangeModal', { reload: async () => fresh, api: { emailChangeStart: async () => { throw error; } } });
    await h.flush(); await h.input('new@example.test'); await h.click('Continue');
    assert.equal(h.calls.at(-1).name, 'reload'); assert.equal(h.done.length, 0); assert.equal(h.changed(), 0);
    // The parent may now display a newer operation. The open ceremony still
    // retries its own original tuple; it must never borrow that operation's ID.
    await h.render({ st: fresh }); await h.click('Verify');
    const sends = h.calls.filter(c => c.name === 'emailChangeStart'); assert.equal(sends.length, 2); assert.deepEqual(sends[0].args, sends[1].args);
    assert.equal(sends[1].args[0].expected_revision, '7'); assert.notEqual(sends[1].args[0].request_id, pending.request_id);
    assert.equal(h.uuidCount(), 1); assert.equal(h.done.length, 0); h.unmount();
  });
}

test('closing the email-change modal reloads current state so a failed send can expose pending controls', async () => {
  const fresh = state({ revision: '8', pending }); const h = clientFixture('EmailRow', { reload: async () => fresh });
  await h.flush(); await h.click('Edit'); const modal = h.nodes((n: any) => n.type?.name === 'ChangeModal')[0]; assert.ok(modal);
  modal.props.onClose(); await h.flush(); assert.deepEqual(h.calls.map(c => c.name), ['reload']);
  await h.render({ st: fresh }); assert.match(h.text(), /Pending verification/);
  assert.ok(h.nodes((n: any) => n.type === 'a' && n.props.href === '#cancel').length); h.unmount();
});

test('a failed read-only account refresh preserves the last coherent state and pending operation', async () => {
  const initial = state({ pending }); let count = 0;
  const h = clientFixture('ProfilePage', { api: { emailChangeGet: async () => { if (++count === 1) return initial; throw { status: 503, code: 'email_change_unavailable' }; } } });
  await h.flush(); const row = h.nodes((n: any) => n.type?.name === 'EmailRow')[0]; assert.ok(row);
  assert.equal(await row.props.reload(), null); await h.flush();
  assert.deepEqual(h.nodes((n: any) => n.type?.name === 'EmailRow')[0].props.st, initial); h.unmount();
});

for (const error of [{ code: 'network', status: 0 }, { code: 'timeout', status: 0 }, { code: 'server_error', status: 500 },
  { code: 'upstream_unreachable', status: 502 }, { code: 'temporarily_unavailable', status: 503 }, { code: 'rate_limited', status: 429 },
  { code: 'upstream_timeout' }, { code: 'upstream_unreachable' }]) {
  test('verification temporary ' + error.code + ' status=' + (error.status ?? 'none') + ' offers a retry with exactly the same URL token', async () => {
    let count = 0;
    const h = clientFixture('VerifyEmailPage', { api: { verifyEmail: async () => { if (++count === 1) throw error; return { ok: true, kind: 'change', replayed: true }; } } });
    await h.flush(); assert.equal(h.nodes((n: any) => n.type === 'auth-card')[0].props.title, 'Verification unavailable');
    assert.ok(h.button('Retry')); assert.doesNotMatch(h.text(), /expired|Email updated/);
    await h.click('Retry'); assert.match(h.text(), /Email updated/); assert.equal(h.calls.length, 2);
    assert.deepEqual(h.calls.map(c => c.args), [['synthetic-email-proof'], ['synthetic-email-proof']]); assert.equal(h.uuidCount(), 0); h.unmount();
  });
}

for (const [error, title] of [[{ status: 422, code: 'invalid_token' }, 'Link expired'], [{ status: 409, code: 'email_taken' }, 'Address already in use']] as const) {
  test('authoritative verification ' + error.code + ' keeps its existing terminal UI', async () => {
    const h = clientFixture('VerifyEmailPage', { api: { verifyEmail: async () => { throw error; } } });
    await h.flush(); assert.equal(h.nodes((n: any) => n.type === 'auth-card')[0].props.title, title);
    assert.equal(h.nodes((n: any) => n.type === 'button').length, 0); assert.equal(h.calls.length, 1); h.unmount();
  });
}

test('verification retry preserves the confirm-current success and cannot apply a late earlier token response', async () => {
  const old = deferred();
  const h = clientFixture('VerifyEmailPage', { api: { verifyEmail: async (token: string) => token === 'synthetic-email-proof' ? old.promise : { ok: true, kind: 'confirm', replayed: true } } });
  await h.flush(); await h.setQuery('token=synthetic-replacement-proof'); assert.match(h.text(), /Email verified/);
  old.reject({ status: 503, code: 'temporarily_unavailable' }); await h.flush(); assert.match(h.text(), /Email verified/);
  assert.equal(h.nodes((n: any) => n.type === 'button').length, 0); h.unmount();
});

test('a pending current-address verification does not claim the verification email was sent', async () => {
  const h = clientFixture('EmailRow', { props: { st: state({ pending: { ...pending, kind: 'confirm' } }) } });
  await h.flush(); assert.match(h.text(), /Verification pending/); assert.doesNotMatch(h.text(), /Verification email sent/);
  for (const action of ['#resend', '#cancel']) assert.equal(h.nodes((n: any) => n.type === 'a' && n.props.href === action).length, 1);
  assert.equal(h.calls.length, 0); h.unmount();
});

test('a late verification failure does not update an unmounted page', async () => {
  const wait = deferred(); const h = clientFixture('VerifyEmailPage', { api: { verifyEmail: () => wait.promise } });
  await h.flush(); h.unmount(); const before = h.updateCount(); wait.reject({ status: 503, code: 'temporarily_unavailable' }); await h.flush();
  assert.equal(h.updateCount(), before);
});

test('send_unconfirmed start retains its attempt and never claims the email was sent', async () => {
  const h = clientFixture('ChangeModal', { api: { emailChangeStart: async () => { throw { status: 503, code: 'send_unconfirmed' }; } } });
  await h.flush(); await h.input('new@example.test'); await h.click('Continue');
  assert.match(h.text(), /couldn’t confirm whether the email was sent.*Check your inbox/); assert.deepEqual(h.done, []);
  await h.click('Verify'); const sends = h.calls.filter(c => c.name === 'emailChangeStart');
  assert.deepEqual(sends[0].args, sends[1].args); assert.equal(h.uuidCount(), 1); h.unmount();
});

for (const resend of [false, true]) test('send_unconfirmed ' + (resend ? 'resend' : 'confirm-current') + ' keeps the same operation identity and warns to check the inbox', async () => {
  const name = resend ? 'emailChangeResend' : 'emailVerifySend';
  const h = clientFixture('EmailRow', { props: { st: state(resend ? { pending } : {}) }, api: { [name]: async () => { throw { status: 503, code: 'send_unconfirmed' }; } } });
  await h.flush();
  const attempt = async () => { if (resend) h.nodes((n: any) => n.type === 'a' && n.props.href === '#resend')[0].props.onClick({ preventDefault() {} }); else await h.click('Verify'); await h.flush(); };
  await attempt(); await attempt(); const sends = h.calls.filter(c => c.name === name);
  assert.equal(sends.length, 2); assert.deepEqual(sends[0].args, sends[1].args); assert.ok(h.notices.every(n => n.kind === 'error'));
  assert.match(h.notices[0].msg, /couldn’t confirm whether the email was sent.*Check your inbox/); h.unmount();
});

for (const error of [{ code: 'email_taken' }, { data: { errors: { email: 'email_taken' } } }]) test('admin invitation registered-address rejection uses the existing inline email field', async () => {
  const h = clientFixture('CreateInvitationDialog', { onCreate: async () => { throw error; } }); await h.flush();
  await h.nodes((n: any) => n.type === 'form')[0].props.onSubmit({ preventDefault() {} }); await h.flush();
  const input = h.nodes((n: any) => n.type === 'input' && n.props.type === 'email')[0];
  assert.equal(input.props['aria-invalid'], true); assert.match(h.text(), /already registered/);
  assert.equal(h.nodes((n: any) => n.props.role === 'alert').length, 0); await h.input('other@example.test');
  assert.equal(h.nodes((n: any) => n.type === 'input' && n.props.type === 'email')[0].props['aria-invalid'], false); h.unmount();
});

test('actual API wrappers carry guarded start, confirm, resend and DELETE bodies', async () => {
  const calls: any[] = []; const api = sourceModule('account/client/src/api.js', {}, { fetch: async (path: string, init: any) => {
    calls.push({ path, method: init.method, body: JSON.parse(init.body) }); return new Response(null, { status: 204 }); } });
  const tuple = { new_email: 'new@example.test', request_id: pending.request_id, expected_revision: '7' };
  await api.emailChangeStart(tuple); await api.emailVerifySend({ request_id: tuple.request_id, expected_revision: tuple.expected_revision });
  await api.emailChangeResend(tuple.request_id); await api.emailChangeCancel(tuple.request_id);
  assert.deepEqual(calls, [ { path: '/api/email-change/start', method: 'POST', body: tuple },
    { path: '/api/email/verify/send', method: 'POST', body: { request_id: tuple.request_id, expected_revision: '7' } },
    { path: '/api/email-change/resend', method: 'POST', body: { request_id: tuple.request_id } },
    { path: '/api/email-change', method: 'DELETE', body: { request_id: tuple.request_id } } ]);
});

test('actual BFF route callbacks whitelist operation identities and do not substitute the browser SID', async () => {
  const text = readFileSync(new URL('account/server/src/routes/api.ts', root), 'utf8');
  const source = ts.createSourceFile('api.ts', text, ts.ScriptTarget.Latest, true);
  const wanted = new Set(['POST /api/email-change/start', 'POST /api/email-change/resend', 'DELETE /api/email-change', 'POST /api/email/verify/send']);
  const callbacks: string[] = [];
  for (const node of source.statements) {
    if (!ts.isExpressionStatement(node) || !ts.isCallExpression(node.expression)) continue;
    const call = node.expression;
    if (!ts.isPropertyAccessExpression(call.expression) || call.expression.expression.getText(source) !== 'apiRouter' || !call.arguments.length || !ts.isStringLiteral(call.arguments[0])) continue;
    const route = call.expression.name.text.toUpperCase() + ' ' + call.arguments[0].text;
    if (wanted.has(route)) callbacks.push(JSON.stringify(route) + ':' + call.arguments.at(-1)!.getText(source));
  }
  assert.equal(callbacks.length, 4); const forwards: any[] = [], context: any = { callbacks: {}, forwardOrg: (...args: any[]) => forwards.push(args.slice(2)) };
  vm.runInNewContext(ts.transpileModule('globalThis.callbacks={' + callbacks.join(',') + '};', { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText, context);
  const body = { new_email: 'new@example.test', request_id: pending.request_id, expected_revision: '7', sid: 'forged', sub: 'forged', token: 'forged', kind: 'confirm' };
  for (const callback of Object.values(context.callbacks) as Function[]) await callback({ body }, {});
  const normalized = JSON.parse(JSON.stringify(forwards));
  assert.deepEqual(normalized, [ ['POST', '/account/email-change/start', { new_email: body.new_email, request_id: body.request_id, expected_revision: '7' }],
    ['POST', '/account/email-change/resend', { request_id: body.request_id }], ['DELETE', '/account/email-change', { request_id: body.request_id }],
    ['POST', '/account/email/verify/send', { request_id: body.request_id, expected_revision: '7' }] ]);
});
