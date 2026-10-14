import assert from 'node:assert/strict';
import test from 'node:test';
import { normalizeRoleCatalog, catalogDigest, inboxDigest, catalogOrder, validateIncomingEvents,
  assertEnvelopeCurrent, EventError, type CatalogSyncState } from '../src/backchannel/rolesSync.js';

const EPOCH = '11111111-1111-4111-8111-111111111111';
const EVENT = '22222222-2222-4222-8222-222222222222';
const raw = { roles: [{ role_id: 0, name: 'Owner', level: 0 }, { role_id: 2, name: 'Member', level: 10 }] };
const error = (code: string, status = 400) => (value: unknown) => value instanceof EventError && value.code === code && value.status === status;
const legacy = (catalog = normalizeRoleCatalog(raw)): CatalogSyncState => ({ catalog_mode: 'legacy', catalog_epoch: null,
  catalog_revision: null, catalog_digest: catalogDigest(catalog), last_sync_iat: '100' });

test('catalog default preserves numeric zero and explicit denial without coercion', () => {
  assert.equal(normalizeRoleCatalog(raw).default_role, null);
  for (const value of [null, 999]) assert.equal(normalizeRoleCatalog({ ...raw, default_role: value }).default_role, null);
  for (const value of [undefined, false, '', '0', [], {}, 0.5, 2147483648, -2147483649]) {
    assert.throws(() => normalizeRoleCatalog({ ...raw, default_role: value }), error('invalid_default_role'));
  }
  assert.equal(normalizeRoleCatalog({ ...raw, default_role: 0 }).default_role, 0);
  assert.equal(normalizeRoleCatalog({ ...raw, default_role: 2 }).default_role, 2);
});

test('role rows require typed int32 values and unique IDs', () => {
  for (const key of ['role_id', 'level']) for (const value of [null, false, '', '0', [], {}, 0.5, NaN, Infinity, 2147483648, -2147483649]) {
    assert.throws(() => normalizeRoleCatalog({ roles: [{ role_id: 0, name: 'R', level: 0, [key]: value }] }), error('invalid_role_row'));
  }
  for (const value of [-2147483648, 2147483647]) assert.equal(normalizeRoleCatalog({ roles: [{ role_id: value, name: 'R', level: value }] }).roles[0].role_id, value);
  assert.throws(() => normalizeRoleCatalog({ roles: [...raw.roles, raw.roles[0]] }), error('duplicate_role_id'));
  assert.throws(() => normalizeRoleCatalog({ roles: [{ role_id: 1, name: 'R', level: 1, is_system: 'true' }] }), error('invalid_role_row'));
  assert.throws(() => normalizeRoleCatalog({ roles: Array(501).fill(raw.roles[0]) }), error('invalid_roles'));
});

test('catalog lineage requires a paired UUID and canonical positive bigint string', () => {
  for (const value of [0, 1, '0', '01', '-1', '+1', '1.0', '9223372036854775808', '1e2', null, undefined]) {
    assert.throws(() => normalizeRoleCatalog({ ...raw, catalog_epoch: EPOCH, catalog_revision: value }), error('invalid_catalog_version'));
  }
  assert.throws(() => normalizeRoleCatalog({ ...raw, catalog_epoch: EPOCH }), error('invalid_catalog_version'));
  assert.throws(() => normalizeRoleCatalog({ ...raw, catalog_revision: '1' }), error('invalid_catalog_version'));
  assert.throws(() => normalizeRoleCatalog({ ...raw, catalog_epoch: 'bad', catalog_revision: '1' }), error('invalid_catalog_version'));
  assert.equal(normalizeRoleCatalog({ ...raw, catalog_epoch: EPOCH, catalog_revision: '9223372036854775807' }).catalog_revision, '9223372036854775807');
});

test('normalized catalog identity is order-independent and excludes version; inbox includes version', () => {
  const a = normalizeRoleCatalog({ ...raw, site_name: ' Site ', catalog_epoch: EPOCH, catalog_revision: '1' });
  const b = normalizeRoleCatalog({ roles: [...raw.roles].reverse(), site_name: 'Site', default_role: null, catalog_epoch: EPOCH, catalog_revision: '2' });
  assert.deepEqual(catalogDigest(a), catalogDigest(b));
  assert.notDeepEqual(inboxDigest({ id: EVENT, type: 'roles.sync', payload: a, catalog: a }), inboxDigest({ id: EVENT, type: 'roles.sync', payload: b, catalog: b }));
  assert.notDeepEqual(catalogDigest(a), catalogDigest({ ...a, default_role: 0 }));
  assert.notDeepEqual(catalogDigest(a), catalogDigest({ ...a, site_name: 'Other' }));
});

test('legacy same-second conflict is retryable, equal state idempotent, older state stale', () => {
  const catalog = normalizeRoleCatalog(raw), state = legacy(catalog);
  assert.equal(catalogOrder(state, catalog, 100, true), 'same');
  const different = normalizeRoleCatalog({ ...raw, default_role: 0 });
  assert.throws(() => catalogOrder(state, different, 100, true), error('catalog_order_ambiguous', 409));
  assert.equal(catalogOrder(state, different, 99, true), 'stale');
  assert.equal(catalogOrder(state, different, 101, true), 'apply');
  assert.equal(catalogOrder({ ...state, catalog_digest: null }, different, 100, false), 'apply');
});

test('revision ordering is independent of envelope signing time, rejects downgrade and foreign epoch', () => {
  const catalog = normalizeRoleCatalog({ ...raw, catalog_epoch: EPOCH, catalog_revision: '20' });
  const state: CatalogSyncState = { ...legacy(catalog), catalog_mode: 'revisioned', catalog_epoch: EPOCH, catalog_revision: '20' };
  assert.equal(catalogOrder(state, { ...catalog, catalog_revision: '19' }, 999, true), 'stale');
  assert.equal(catalogOrder(state, catalog, 999, true), 'same');
  assert.equal(catalogOrder(state, { ...catalog, catalog_revision: '21' }, 1, true), 'apply');
  assert.throws(() => catalogOrder(state, { ...catalog, default_role: 0 }, 101, true), error('catalog_revision_conflict', 409));
  assert.throws(() => catalogOrder(state, normalizeRoleCatalog(raw), 999, true), error('catalog_revision_required', 409));
  assert.throws(() => catalogOrder(state, { ...catalog, catalog_epoch: EVENT }, 999, true), error('catalog_epoch_conflict', 409));
  assert.equal(catalogOrder(legacy(), catalog, 1, true), 'apply');
});

test('entire event batch is validated before it can mutate state', () => {
  assert.throws(() => validateIncomingEvents([{ id: EVENT, type: 'roles.sync', payload: raw }, null]), error('invalid_event_id'));
  assert.throws(() => validateIncomingEvents([{ id: 'a'.repeat(36), type: 'roles.sync', payload: raw }]), error('invalid_event_id'));
  assert.throws(() => validateIncomingEvents([{ id: EVENT, type: '', payload: {} }]), error('invalid_event_type'));
  assert.throws(() => validateIncomingEvents(Array(101).fill({ id: EVENT, type: 'future', payload: {} })), error('invalid_events'));
  assert.equal(validateIncomingEvents([{ id: EVENT.toUpperCase(), type: 'future', payload: { arbitrary: true } }])[0].id, EVENT);
});

test('age and expiry are rechecked after a transaction waits for its lock', () => {
  assertEnvelopeCurrent({ iat: 1000, exp: 1120 }, 1010_000);
  assert.throws(() => assertEnvelopeCurrent({ iat: 1000, exp: 1120 }, 1130_000), error('invalid_token', 401));
  assert.throws(() => assertEnvelopeCurrent({ iat: 1000, exp: 2000 }, 1311_000), error('invalid_token', 401));
  assert.throws(() => assertEnvelopeCurrent({ iat: 1021, exp: 1120 }, 1010_000), error('invalid_token', 401));
  assert.throws(() => assertEnvelopeCurrent({ iat: 1000.5, exp: 1120 }, 1010_000), error('invalid_token', 401));
});

test('catalog text preserves complete Unicode characters and rejects database-invalid text', () => {
  const name = 'a'.repeat(99) + '😀' + 'tail';
  const normalized = normalizeRoleCatalog({ roles: [{ role_id: 0, level: 0, name }], site_name: name });
  assert.equal(normalized.roles[0].name, 'a'.repeat(99) + '😀');
  assert.equal(normalized.site_name, 'a'.repeat(99) + '😀');
  for (const name of ['bad\0text', '\ud800', '\udfff']) {
    assert.throws(() => normalizeRoleCatalog({ roles: [{ role_id: 0, level: 0, name }] }), error('invalid_role_row'));
    assert.throws(() => normalizeRoleCatalog({ ...raw, site_name: name }), error('invalid_site_name'));
  }
});

test('unknown future payloads cannot overflow canonicalization recursion', () => {
  let payload: unknown = null;
  for (let i = 0; i < 70; i++) payload = [payload];
  assert.throws(() => validateIncomingEvents([{ id: EVENT, type: 'future.event', payload }]), error('invalid_event_payload'));
});
