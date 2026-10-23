import test from 'node:test';
import assert from 'node:assert/strict';
import { DRAFT_KEY, DRAFT_TTL, DRAFT_MAX, publicJwks, writeClientDraft, readClientDraft, restoreClientDraft, clearClientDraft, clientDraftAuthUncertain, settleClientDraft, rebaseClientDraftForm, observeClientDraftSettlement } from './clientDraft.js';
const initial = { client_id: '', name: '', hostname: '', redirect_paths: [''], events_path: '', key_mode: 'uri', jwks_path: '', jwks_text: '', allowed_scopes: ['openid', 'profile', 'email'], is_first_party: true, entry_policy: 'opt_in' };
const populated = { ...initial, client_id: 'app', name: 'App', hostname: 'app.example', redirect_paths: ['/callback'], jwks_path: '/jwks' };
function fixture() {
  const data = new Map();
  const storage = { getItem: (k) => data.get(k) ?? null, setItem: (k, v) => data.set(k, v), removeItem: (k) => data.delete(k) };
  const opts = { owner: 'subject-a', route: 'new', base: initial, form: populated, now: 1000 };
  const write = (extra = {}) => writeClientDraft({ ...opts, ...extra }, storage);
  const read = (extra = {}) => readClientDraft({ ...opts, ...extra }, storage);
  return { data, storage, opts, write, read };
}
test('tab draft binds stable account and route; an account change drops it', () => {
  const f = fixture(); f.write();
  assert.equal(f.read({ route: 'client:app' }), null);
  assert.equal(f.data.has(DRAFT_KEY), true);
  assert.equal(f.read({ owner: 'subject-b' }), null);
  assert.equal(f.data.has(DRAFT_KEY), false);
});
test('expired, future, corrupt, oversize and invalid-schema drafts are removed', () => {
  const f = fixture();
  f.write(); assert.equal(f.read({ now: 1000 + DRAFT_TTL }), null);
  f.write(); assert.equal(f.read({ now: 999 }), null);
  for (const raw of ['{', 'x'.repeat(DRAFT_MAX + 1), JSON.stringify({ version: 2 }), JSON.stringify({ ...f.opts, version: 1, savedAt: 1000, changes: { token: 'secret' }, omitted: [], uncertain: false })]) {
    f.data.set(DRAFT_KEY, raw); assert.equal(f.read(), null); assert.equal(f.data.has(DRAFT_KEY), false);
  }
});
test('public JWKS is preserved; private, symmetric, unknown, invalid and credential fields never reach storage', () => {
  const pub = { keys: [{ kty: 'OKP', crv: 'Ed25519', x: 'abc123', kid: 'public-id', alg: 'EdDSA' }] };
  assert.equal(publicJwks(JSON.stringify(pub)), JSON.stringify(pub, null, 2));
  for (const key of [{ ...pub.keys[0], d: 'private-secret' }, { kty: 'oct', k: 'symmetric-secret' }, { ...pub.keys[0], extra: 'unknown-secret' }, { kty: 'RSA', n: 'n' }]) {
    const f = fixture(); const res = f.write({ form: { ...populated, key_mode: 'inline', jwks_text: JSON.stringify({ keys: [key] }) } });
    assert.ok(res.omitted.includes('jwks_text'));
    assert.doesNotMatch(f.data.get(DRAFT_KEY), /private-secret|symmetric-secret|unknown-secret/);
  }
  const f = fixture(); f.write({ form: { ...populated, key_mode: 'inline', jwks_text: JSON.stringify(pub) } });
  assert.equal(f.read().changes.jwks_text, JSON.stringify(pub, null, 2));
});
test('URL credentials and query/fragment secrets are omitted without rewriting entered values', () => {
  for (const value of ['https://user:secret@app.example/callback', '/callback?token=secret', '/callback#secret', '//user:secret@app.example/callback', '/callback%3Ftoken=secret']) {
    const f = fixture(); const form = { ...populated, redirect_paths: [value] };
    assert.ok(f.write({ form }).omitted.includes('redirect_paths'));
    assert.equal(form.redirect_paths[0], value);
    assert.doesNotMatch(f.data.get(DRAFT_KEY), /secret/);
  }
  const f = fixture(); f.write({ form: { ...populated, redirect_paths: ['https://app.example/callback'] } });
  assert.deepEqual(f.read().changes.redirect_paths, ['https://app.example/callback']);
});
test('restoration merges only dirty fields over current server state and retains an uncertain result', () => {
  const f = fixture(); f.write({ route: 'client:app', base: populated, form: { ...populated, name: 'Unsaved' }, uncertain: true });
  const draft = f.read({ route: 'client:app' });
  const current = { ...populated, allowed_scopes: ['openid'], is_first_party: false };
  const result = restoreClientDraft(draft, current);
  assert.equal(result.form.name, 'Unsaved'); assert.deepEqual(result.form.allowed_scopes, ['openid']);
  assert.equal(result.form.is_first_party, false); assert.equal(result.uncertain, true);
  assert.deepEqual(result.restored, ['name']);
  // Pure restoration cannot perform a request, navigate, or submit.
  assert.equal(Object.hasOwn(result, 'submit'), false);
});
test('changed server fields, URL host dependencies, disabled and deleted registrations do not resurrect draft settings', () => {
  const f = fixture(); f.write({ route: 'client:app', base: populated, form: { ...populated, name: 'Unsaved', redirect_paths: ['/new'], is_first_party: false } });
  const draft = f.read({ route: 'client:app' });
  const current = { ...populated, name: 'Server edit', hostname: 'changed.example', is_first_party: false };
  const result = restoreClientDraft(draft, current);
  assert.equal(result.form.name, 'Server edit'); assert.deepEqual(result.form.redirect_paths, ['/callback']);
  assert.deepEqual(result.conflicts, ['name', 'redirect_paths', 'is_first_party']);
  const disabled = restoreClientDraft(draft, current, { disabled: true });
  assert.deepEqual(disabled.form, current); assert.equal(disabled.discarded, true);
  clearClientDraft('subject-a', 'client:app', f.storage); assert.equal(f.read({ route: 'client:app' }), null);
});
test('confirmed success or explicit discard clears only its draft; no storage exception blocks caller', () => {
  const f = fixture(); f.write();
  clearClientDraft('other', 'new', f.storage); assert.ok(f.read());
  clearClientDraft('subject-a', 'new', f.storage); assert.equal(f.read(), null);
  const fail = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('quota'); } };
  assert.equal(writeClientDraft(f.opts, fail).saved, false);
  assert.equal(readClientDraft(f.opts, fail), null);
  assert.equal(clearClientDraft('subject-a', 'new', fail), false);
});

test('key edits based on an external JWKS source require re-entry rather than replacing a changed source', () => {
  const f = fixture();
  f.write({ route: 'client:app', base: populated, form: { ...populated, key_mode: 'inline' }, externalJwksUri: 'https://external.example/jwks' });
  const draft = f.read({ route: 'client:app' });
  assert.deepEqual(draft.omitted, ['key_mode']);
  assert.deepEqual(draft.changes, {});
  assert.equal(restoreClientDraft(draft, populated).form.key_mode, 'uri');
});

test('even the in-flight marker is retained when the form itself has no dirty edits', () => {
  const f = fixture(); f.write({ form: initial, uncertain: true });
  assert.equal(f.read().uncertain, true);
  assert.deepEqual(f.read().changes, {});
});


test('omitted fields remain required across two bounces until that actual field is re-entered', () => {
  const f = fixture();
  f.write({ form: { ...populated, key_mode: 'inline', jwks_text: '{"keys":[{"kty":"oct","k":"private-secret"}]}' } });
  const first = f.read();
  const recovered = restoreClientDraft(first, initial, { isNew: true });
  assert.deepEqual(recovered.omitted, ['jwks_text']);
  f.write({ form: recovered.form, omitted: recovered.omitted, createdAt: first.savedAt, now: 2000 });
  const second = f.read({ now: 2000 });
  assert.deepEqual(second.omitted, ['jwks_text']);
  assert.equal(second.savedAt, 1000);
  assert.deepEqual(restoreClientDraft(second, initial, { isNew: true }).omitted, ['jwks_text']);
  const pub = '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"public"}]}';
  f.write({ form: { ...recovered.form, jwks_text: pub }, omitted: [], createdAt: first.savedAt, now: 3000 });
  assert.deepEqual(f.read({ now: 3000 }).omitted, []);
});

test('repeated writes cannot extend the original draft lifetime and failure results identify unavailable recovery', () => {
  const f = fixture();
  const first = f.write();
  const next = f.write({ now: 1000 + DRAFT_TTL - 1, createdAt: first.savedAt });
  assert.equal(next.savedAt, 1000);
  assert.equal(f.write({ now: 1000 + DRAFT_TTL, createdAt: first.savedAt }).reason, 'expired');
  assert.equal(f.data.has(DRAFT_KEY), false);
  const unavailable = writeClientDraft(f.opts, { getItem() { throw new Error('denied'); } });
  assert.equal(unavailable.saved, false); assert.equal(unavailable.reason, 'unavailable');
});

test('known rejection of this RP mutation clears only its uncertainty; background auth failures preserve prior unknown outcomes', () => {
  for (const reason of ['unauthenticated', 'step_up_required']) {
    assert.equal(clientDraftAuthUncertain(true, { reason, mutating: true, path: '/clients' }, '/clients'), false);
    assert.equal(clientDraftAuthUncertain(true, { reason, mutating: false, path: '/clients' }, '/clients'), true);
    assert.equal(clientDraftAuthUncertain(true, { reason, mutating: true, path: '/settings' }, '/clients'), true);
  }
  assert.equal(clientDraftAuthUncertain(true, undefined, '/clients'), true);
});


test('an omission-only edit draft survives repeated bounces with no other dirty fields', () => {
  const f = fixture();
  const base = { ...populated, key_mode: 'inline', jwks_text: '{"keys":[{"kty":"OKP","crv":"Ed25519","x":"public"}]}' };
  f.write({ route: 'client:app', base, form: { ...base, jwks_text: '{"keys":[{"kty":"oct","k":"private-secret"}]}' } });
  const recovered = restoreClientDraft(f.read({ route: 'client:app' }), base);
  assert.deepEqual(recovered.restored, []);
  f.write({ route: 'client:app', base, form: recovered.form, omitted: recovered.omitted, now: 2000 });
  const second = f.read({ route: 'client:app', now: 2000 });
  assert.ok(second); assert.deepEqual(second.omitted, ['jwks_text']);
  assert.deepEqual(second.changes, {});
});


test('late definitive settlements affect only their pending snapshot after navigation', () => {
  const f = fixture();
  const operationId = 'operation-a';
  f.write({ uncertain: true, operationId, priorUnknown: false });
  assert.equal(settleClientDraft({ ...f.opts, operationId, success: true }, f.storage), true);
  assert.equal(f.read(), null);
  f.write({ uncertain: true, operationId, priorUnknown: false });
  assert.equal(settleClientDraft({ ...f.opts, operationId, uncertain: false }, f.storage), true);
  assert.equal(f.read().uncertain, false);
  assert.equal(f.read().operationId, null);
  // Navigating away and back, then editing, publishes a new draft snapshot.
  f.write({ uncertain: true, operationId, priorUnknown: false });
  f.write({ form: { ...populated, name: 'New work' }, operationId: null });
  assert.equal(settleClientDraft({ ...f.opts, operationId, success: true }, f.storage), false);
  assert.equal(f.read().changes.name, 'New work');
  assert.equal(settleClientDraft({ ...f.opts, operationId, uncertain: true }, f.storage), false);
  assert.equal(f.read().uncertain, false);
  f.write({ owner: 'subject-b', uncertain: true, operationId: 'operation-b' });
  assert.equal(settleClientDraft({ ...f.opts, operationId, success: true }, f.storage), false);
  assert.ok(f.read({ owner: 'subject-b' }));
});

test('a rejected retry preserves a prior unknown result through auth bounce, settlement, and another reload', () => {
  const f = fixture();
  for (const reason of ['unauthenticated', 'step_up_required']) {
    const uncertainty = clientDraftAuthUncertain(true, { reason, mutating: true, path: '/clients' }, '/clients', true);
    assert.equal(uncertainty, true);
    f.write({ uncertain: uncertainty, operationId: 'retry-operation', priorUnknown: true });
    settleClientDraft({ ...f.opts, operationId: 'retry-operation', uncertain: false }, f.storage);
    const draft = f.read();
    assert.equal(draft.uncertain, true); assert.equal(draft.priorUnknown, true);
    assert.equal(restoreClientDraft(draft, initial, { isNew: true }).uncertain, true);
  }
  f.write({ uncertain: true, operationId: 'retry-operation', priorUnknown: true });
  settleClientDraft({ ...f.opts, operationId: 'retry-operation', success: true }, f.storage);
  assert.equal(f.read(), null);
});

test('a disabled discard drops omitted requirements and permits a fresh creation time', () => {
  const f = fixture();
  f.write({ route: 'client:app', omitted: ['jwks_text'], uncertain: true });
  const discarded = restoreClientDraft(f.read({ route: 'client:app' }), populated, { disabled: true });
  assert.equal(discarded.uncertain, false); assert.deepEqual(discarded.omitted, []);
  assert.equal(discarded.createdAt, undefined);
  clearClientDraft('subject-a', 'client:app', f.storage);
  const fresh = f.write({ route: 'client:app', base: populated, form: { ...populated, name: 'New edit' }, now: 5000 });
  assert.equal(fresh.savedAt, 5000); assert.deepEqual(f.read({ route: 'client:app', now: 5000 }).omitted, []);
});

test('canonical refresh adopts untouched normalized fields and preserves only newer edits', () => {
  const submitted = { ...populated, hostname: 'APP.EXAMPLE', redirect_paths: ['/callback', ''], jwks_text: 'old snapshot' };
  const canonical = { ...populated, allowed_scopes: ['email', 'profile', 'openid'], jwks_text: 'new snapshot' };
  const newer = { ...submitted, name: 'Newer name', entry_policy: 'baseline' };
  const rebased = rebaseClientDraftForm(newer, submitted, canonical);
  assert.deepEqual(rebased, { ...canonical, name: 'Newer name', entry_policy: 'baseline' });
  const f = fixture();
  f.write({ route: 'client:app', base: canonical, form: rebased });
  assert.deepEqual(f.read({ route: 'client:app' }).changes, { name: 'Newer name', entry_policy: 'baseline' });
});

test('a safely omitted key dependency requires re-entry rather than claiming the server changed', () => {
  const f = fixture();
  const base = { ...populated, jwks_text: '{"keys":[{"kty":"RSA","n":"public","e":"AQAB","x5c":["certificate"]}]}' };
  f.write({ route: 'client:app', base, form: { ...base, jwks_path: '/replacement' } });
  const result = restoreClientDraft(f.read({ route: 'client:app' }), base);
  assert.deepEqual(result.restored, []); assert.deepEqual(result.conflicts, []);
  assert.deepEqual(result.omitted, ['jwks_path']);
});

test('explicit discard removes corrupt and malformed draft entries when storage works', () => {
  const f = fixture();
  for (const raw of ['{', 'null', '{"version":999}']) {
    f.data.set(DRAFT_KEY, raw);
    assert.equal(clearClientDraft('subject-a', 'new', f.storage), true);
    assert.equal(f.data.has(DRAFT_KEY), false);
  }
});


test('late success notifies an untouched returned view so its later pagehide cannot resurrect the settled draft', () => {
  const f = fixture();
  f.write({ uncertain: true, operationId: 'pending-return', priorUnknown: false });
  const restored = f.read();
  let returnedRef = { form: restoreClientDraft(restored, initial, { isNew: true }).form, base: initial,
    uncertain: true, priorUnknown: restored.priorUnknown, operationId: null, restoredOperationId: restored.operationId };
  let repersistenceDisabled = false, visibleUncertain = true;
  const off = observeClientDraftSettlement({ ...f.opts, operationId: restored.operationId }, (event) => {
    if (returnedRef?.restoredOperationId !== event.operationId) return;
    visibleUncertain = event.uncertain;
    if (event.success) { returnedRef = null; repersistenceDisabled = true; }
  });
  try {
    assert.equal(settleClientDraft({ ...f.opts, operationId: 'pending-return', success: true }, f.storage), true);
    assert.equal(visibleUncertain, false);
    assert.equal(repersistenceDisabled, true);
    // The returned form's pagehide handler uses this same ref/disabled gate.
    if (returnedRef && !repersistenceDisabled) f.write(returnedRef);
    assert.equal(f.read(), null);
  } finally { off(); }
});

test('a real edit after returning removes settlement provenance and survives the old completion', () => {
  const f = fixture();
  f.write({ uncertain: true, operationId: 'pending-return', priorUnknown: false });
  let notifications = 0;
  const off = observeClientDraftSettlement({ ...f.opts, operationId: 'pending-return' }, () => { notifications++; });
  // The field edit unsubscribes before publishing its own snapshot.
  off();
  const edited = { ...populated, name: 'New work after return' };
  f.write({ form: edited, uncertain: true, priorUnknown: true, operationId: null });
  assert.equal(settleClientDraft({ ...f.opts, operationId: 'pending-return', success: true }, f.storage), false);
  assert.equal(notifications, 0);
  assert.equal(f.read().changes.name, 'New work after return');
});

test('returned-view rejection notifications clear only the settled request uncertainty and match exact identity', () => {
  const f = fixture();
  for (const priorUnknown of [false, true]) {
    f.write({ uncertain: true, operationId: 'pending-return', priorUnknown });
    const seen = [];
    const off = observeClientDraftSettlement({ ...f.opts, operationId: 'pending-return' }, (event) => seen.push(event));
    const unrelated = observeClientDraftSettlement({ ...f.opts, owner: 'subject-b', operationId: 'pending-return' }, () => assert.fail('other account notified'));
    try {
      settleClientDraft({ ...f.opts, operationId: 'pending-return', uncertain: false }, f.storage);
      assert.equal(seen.length, 1); assert.equal(seen[0].uncertain, priorUnknown);
      assert.equal(f.read().uncertain, priorUnknown);
    } finally { off(); unrelated(); }
  }
});


test('returned pending old-request auth rejection retains its operation for CAS notification without inventing a prior unknown', () => {
  const f = fixture();
  for (const reason of ['unauthenticated', 'step_up_required']) {
    f.write({ uncertain: true, operationId: 'pending-old-auth', priorUnknown: false });
    const draft = f.read();
    const recovered = restoreClientDraft(draft, initial, { isNew: true });
    assert.equal(recovered.uncertain, true); assert.equal(recovered.priorUnknown, false);
    let returnedRef = { form: recovered.form, base: initial, uncertain: recovered.uncertain,
      priorUnknown: recovered.priorUnknown, operationId: null, restoredOperationId: draft.operationId };
    const events = [];
    const off = observeClientDraftSettlement({ ...f.opts, operationId: draft.operationId }, (event) => {
      if (returnedRef.restoredOperationId !== event.operationId) return;
      events.push(event);
      returnedRef = { ...returnedRef, restoredOperationId: null, uncertain: event.uncertain, priorUnknown: event.uncertain };
    });
    try {
      // The returned view's pre-navigation listener handles the OLD request's 401/403.
      returnedRef.uncertain = clientDraftAuthUncertain(returnedRef.uncertain,
        { reason, mutating: true, path: '/clients' }, '/clients', returnedRef.priorUnknown);
      f.write({ ...returnedRef, operationId: returnedRef.operationId ?? returnedRef.restoredOperationId });
      assert.equal(f.read().operationId, draft.operationId);
      assert.equal(f.read().uncertain, false);
      assert.equal(settleClientDraft({ ...f.opts, operationId: draft.operationId, uncertain: false }, f.storage), true);
      assert.equal(events.length, 1); assert.equal(returnedRef.uncertain, false);
      assert.equal(returnedRef.priorUnknown, false);
      f.write(returnedRef); // later pagehide remains a known rejected, editable draft.
      assert.equal(f.read().uncertain, false); assert.equal(f.read().operationId, null);
    } finally { off(); }
  }
});
