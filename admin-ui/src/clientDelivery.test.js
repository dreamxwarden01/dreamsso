import test from 'node:test';
import assert from 'node:assert/strict';
import { clearRecovery, deliveryOutcome, deliverySummary, pendingRecovery, recoveryMessage, recoveryRequest, recoverySummary, retainRecovery } from './clientDelivery.js';

const uuid = '11111111-1111-4111-8111-111111111111';
const other = '22222222-2222-4222-8222-222222222222';
const data = () => ({ state: 'ready', counts: { pending: 2, paused: 0, dead: 1, delivered: 7 },
  last_outcome: { code: 'http_rejected', at: '2026-11-18T12:00:00.000Z' }, can_recover: true });
function storage() {
  const values = new Map();
  return { values, getItem: (key) => values.get(key) ?? null,
    setItem: (key, value) => values.set(key, value), removeItem: (key) => values.delete(key) };
}

test('delivery summary copies aggregate metadata only, and rejects misleading state/counts', () => {
  const value = { ...data(), payload: { sub: 'private', token: 'private' } };
  value.counts.subjects = ['private']; value.last_outcome.body = 'private';
  assert.deepEqual(deliverySummary(value), data());
  assert.deepEqual(deliverySummary({ ...data(), last_outcome: { code: 'private_message', at: null } }).last_outcome,
    { code: 'unknown_error', at: null });
  for (const bad of [-1, 0.5, '2', Infinity, Number.MAX_SAFE_INTEGER + 1])
    assert.equal(deliverySummary({ ...data(), counts: { ...data().counts, pending: bad } }), null);
  assert.equal(deliverySummary({ ...data(), state: 'paused' }), null);
  assert.equal(deliverySummary({ ...data(), counts: { ...data().counts, paused: 2 } }), null);
  assert.equal(deliverySummary({ ...data(), last_outcome: { code: 'delivered', at: 'yesterday' } }), null);
  assert.equal(deliverySummary({ ...data(), last_outcome: undefined }), null);
  for (const state of ['paused', 'unconfigured']) assert.ok(deliverySummary({ ...data(), state, can_recover: false,
    counts: { pending: 0, paused: 2, dead: 1, delivered: 7 } }));
});

test('recovery counts are bounded metadata and copy distinguishes queued work from remaining failures', () => {
  const result = { logout_requeued: 2, role_snapshots: 3, role_superseded: 9, other_retained: 1 };
  assert.deepEqual(recoverySummary({ ...result, events: ['private'] }), result);
  assert.equal(recoverySummary({ ...result, other_retained: '1' }), null);
  assert.match(recoveryMessage(result), /^This recovery request queued /); assert.match(recoveryMessage(result), /1 failed notification still needs attention/);
  assert.doesNotMatch(recoveryMessage(result), /delivered|9/);
  assert.equal(recoveryMessage({ ...result, logout_requeued: 0, role_snapshots: 0, other_retained: 0 }), 'This recovery request completed without additional access notices.');
  assert.equal(deliveryOutcome('toString'), 'A delivery outcome needs attention.');
  assert.equal(deliveryOutcome('recovered'), 'Access resynchronization queued.');
});

test('request identity survives remount/sign-in and explicit retry, scoped to actor and client', () => {
  const store = storage();
  assert.equal(pendingRecovery(store, 'actor', 'client', 1000), null);
  assert.equal(recoveryRequest(store, 'actor', 'client', 1000, () => uuid), uuid);
  assert.equal(recoveryRequest(store, 'actor', 'client', 2000, () => { throw Error('must reuse'); }), uuid);
  assert.equal(pendingRecovery(store, 'actor', 'client', 2000), uuid);
  assert.equal(pendingRecovery(store, 'another-actor', 'client', 2000), null);
  assert.equal(pendingRecovery(store, 'actor', 'another-client', 2000), null);
  assert.equal(recoveryRequest(store, 'another-actor', 'client', 2000, () => other), other);
  clearRecovery(store, 'actor', 'client');
  assert.equal(pendingRecovery(store, 'actor', 'client', 2000), null);
  assert.equal(pendingRecovery(store, 'another-actor', 'client', 2000), other);
});

test('request records expire after 24 hours; malformed/future records and failed persistence cannot authorize a POST', () => {
  const store = storage(); recoveryRequest(store, 'actor', 'client', 1000, () => uuid);
  assert.equal(pendingRecovery(store, 'actor', 'client', 1000 + 86400000 - 1), uuid);
  assert.equal(pendingRecovery(store, 'actor', 'client', 1000 + 86400000), null);
  assert.equal(recoveryRequest(store, 'actor', 'client', 1000 + 86400000, () => other), other);
  const key = [...store.values.keys()][0];
  for (const invalid of ['bad', JSON.stringify({ requestId: 'bad', createdAt: 1000 }),
    JSON.stringify({ requestId: uuid, createdAt: 3000 }), 'x'.repeat(2049)]) {
    store.setItem(key, invalid); assert.equal(pendingRecovery(store, 'actor', 'client', 2000), null);
  }
  assert.throws(() => recoveryRequest({ ...store, setItem: () => {} }, 'actor', 'client', 1000, () => uuid), /recovery_storage_unavailable/);
  assert.throws(() => recoveryRequest({ ...store, setItem: () => { throw Error('storage blocked'); } }, 'actor', 'client', 1000, () => uuid), /storage blocked/);
});

test('uncertain failures and auth bounces retain the request; definite action rejections can clear it', () => {
  for (const error of [{ status: 401, code: 'unauthenticated' }, { status: 403, code: 'step_up_required' },
    { status: 0, code: 'network_error', uncertain: true }, { status: 200, code: 'invalid_response', uncertain: true },
    { status: 503, uncertain: true }]) assert.equal(retainRecovery(error), true);
  for (const status of [403, 404, 409, 422, 429]) assert.equal(retainRecovery({ status, code: 'rejected' }), false);
});
