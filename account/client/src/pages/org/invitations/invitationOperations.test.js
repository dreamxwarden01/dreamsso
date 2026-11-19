import test from 'node:test';
import assert from 'node:assert/strict';
import { clearInvitationDraft, DEFAULT_INVITATION_FORM, invitationDraftKey, readInvitationDraft, writeInvitationDraft } from './invitationDraft.js';
import { operationKey, requestForOperation, settleOperation } from './invitationOperations.js';
import { invitationMutationFromDto } from './invitationModel.js';
const uuid = '11111111-1111-4111-8111-111111111111', other = '22222222-2222-4222-8222-222222222222';
const store = () => { const values = new Map(); return { values, getItem: (k) => values.get(k) ?? null, setItem: (k, v) => values.set(k, v), removeItem: (k) => values.delete(k) }; };

test('retry UUID survives uncertain/auth interruptions and changes only for new payload/actor/action/context', () => {
  const storage = store(), key = operationKey('actor', 'create', null);
  assert.equal(requestForOperation(storage, key, 'hash-one', 1000, () => uuid), uuid);
  assert.equal(requestForOperation(storage, key, 'hash-one', 2000, () => { throw Error('must reuse'); }), uuid);
  assert.equal(requestForOperation(storage, key, 'hash-two', 2000, () => other), other);
  assert.equal(requestForOperation(storage, operationKey('another-actor', 'create', null), 'hash-two', 2000, () => uuid), uuid);
  assert.notEqual(operationKey('actor', 'resend', 'record'), operationKey('actor', 'revoke', 'record'));
  assert.equal(requestForOperation(storage, key, 'hash-two', 2000 + 86400000, () => uuid), uuid);
  assert.throws(() => requestForOperation({ ...storage, setItem: () => {} }, 'unpersisted', 'hash', 1, () => uuid), /request_storage_unavailable/);
});
test('known outcome clears only its request; uncertain and auth-bounce receipts remain for explicit retry', (t) => {
  const storage = store(), previous = Object.getOwnPropertyDescriptor(globalThis, 'sessionStorage'); Object.defineProperty(globalThis, 'sessionStorage', { configurable: true, value: storage });
  t.after(() => previous ? Object.defineProperty(globalThis, 'sessionStorage', previous) : delete globalThis.sessionStorage);
  const operation = { key: operationKey('actor', 'create', null) };
  for (const error of [{ status: 503 }, { code: 'network_error' }, new Error('unauthenticated'), { code: 'step_up_required', status: 403 }]) {
    storage.setItem(operation.key, 'pending'); settleOperation(operation, error); assert.equal(storage.getItem(operation.key), 'pending');
  }
  settleOperation(operation, { status: 429, code: 'rate_limited' }); assert.equal(storage.getItem(operation.key), null);
  storage.setItem(operation.key, 'pending');
  try { invitationMutationFromDto(null); assert.fail('missing body must fail'); } catch (error) { settleOperation(operation, error); }
  assert.equal(storage.getItem(operation.key), 'pending', 'unconfirmed 2xx keeps the same explicit retry ID');
  storage.setItem(operation.key, 'pending'); settleOperation(operation); assert.equal(storage.getItem(operation.key), null);
});
test('bounded actor-scoped draft restores only approved form fields without autosubmission data', () => {
  const storage = store(), form = { ...DEFAULT_INVITATION_FORM, delivery: 'link', email: 'fiction@example.invalid', role_slug: 'member', note: 'Fictional note', password: 'private', proof: 'private' };
  assert.equal(writeInvitationDraft(storage, 'actor', form, 1000), true);
  const restored = readInvitationDraft(storage, 'actor', 2000); assert.equal(restored.email, form.email); assert.equal(restored.role_slug, 'member');
  assert.doesNotMatch(JSON.stringify(restored), /password|proof|private/); assert.equal(readInvitationDraft(storage, 'another-actor', 2000), null);
  writeInvitationDraft(storage, 'actor', { ...form, note: 'Changed' }, 3000);
  assert.equal(JSON.parse(storage.getItem(invitationDraftKey('actor'))).at, 1000, 'edits do not extend the original lifetime');
  assert.equal(readInvitationDraft(storage, 'actor', 1000 + 86400000), null);
});
test('corrupt, foreign, future, oversized and expired drafts are removed; explicit cancel/success clears', () => {
  const storage = store(), key = invitationDraftKey('actor');
  for (const bad of ['bad', 'x'.repeat(4097), JSON.stringify({ version: 1, owner: 'other', at: 1000, form: DEFAULT_INVITATION_FORM }), JSON.stringify({ version: 1, owner: 'actor', at: 3000, form: DEFAULT_INVITATION_FORM })]) {
    storage.setItem(key, bad); assert.equal(readInvitationDraft(storage, 'actor', 2000), null); assert.equal(storage.getItem(key), null);
  }
  writeInvitationDraft(storage, 'actor', DEFAULT_INVITATION_FORM, 1000); clearInvitationDraft(storage, 'actor'); assert.equal(storage.getItem(key), null);
  assert.equal(writeInvitationDraft({ ...storage, setItem() { throw Error('blocked'); } }, 'actor', DEFAULT_INVITATION_FORM, 1000), false);
});
test('drafts preserve 60 astral note characters but reject the 61st code point', () => {
  const storage = store(), note = '😀'.repeat(60), form = { ...DEFAULT_INVITATION_FORM, note };
  assert.equal(writeInvitationDraft(storage, 'actor', form, 1000), true); assert.equal(readInvitationDraft(storage, 'actor', 2000).note, note);
  assert.equal(writeInvitationDraft(storage, 'actor', { ...form, note: note + '😀' }, 2000), false);
  assert.equal(readInvitationDraft(storage, 'actor', 2000).note, note);
});
