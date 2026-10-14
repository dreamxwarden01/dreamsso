import assert from 'node:assert/strict';
import test from 'node:test';
import {
  backoffMs, boundedBatch, createLegacyImporter, deliverDestination, drainDestination, eventBytes,
  insertEvents, insertLegacyEvent, parseLegacyEvent, EVENT_BYTES_MAX, LEGACY_MEMBER_BYTES_MAX, MAX_ATTEMPTS,
  type DeliveryStore, type DestinationClaim, type EventQuery, type LegacyRedis,
  type PendingRow, type Settlement, type WireEvent,
} from '../src/events/outboxStore.js';

const ID = '11111111-1111-4111-8111-111111111111';
const ID2 = '22222222-2222-4222-8222-222222222222';
const SUBJECT = '33333333-3333-4333-8333-333333333333';
const row = (id = ID, payload: Record<string, unknown> = { sub: SUBJECT, role_id: null }): PendingRow =>
  ({ id, type: 'account.roles_change', payload, attempts: 0, due: true });

class FakeStore implements DeliveryStore {
  current: DestinationClaim = { clientId: 'rp', token: 'owner', uri: 'https://rp.example.invalid/backchannel/events',
    disabled: false, failures: 0, events: [row()] };
  renews = true;
  settled: { ids: readonly string[]; outcome: Settlement }[] = [];
  settleError = false;
  async destinations() { return ['rp']; }
  async claim() { return structuredClone(this.current); }
  async renew() { return this.renews; }
  async settle(claim: DestinationClaim, ids: readonly string[], outcome: Settlement) {
    if (this.settleError) throw new Error('synthetic settlement loss');
    if (claim.token !== this.current.token) return false;
    this.settled.push({ ids, outcome });
    return true;
  }
}

test('byte budget uses UTF-8 and preserves FIFO across count, size and delayed boundaries', () => {
  assert.equal(boundedBatch(Array.from({ length: 101 }, () => row())).length, 100);
  const multibyte = row(ID, { text: '界'.repeat(12_000) });
  const batch = boundedBatch([multibyte, multibyte, row(ID2)]);
  assert.equal(batch.length, 1);assert.ok(eventBytes(batch) <= EVENT_BYTES_MAX);
  assert.equal(boundedBatch([{ ...row(), due: false }, row(ID2)]).length, 0);
  assert.deepEqual(boundedBatch([row(), { ...row(ID2), due: false }, row()]).map(x => x.id), [ID]);
});

test('a poison head exhausts only its own retry budget after the first rejected batch', async () => {
  class PoisonStore extends FakeStore {
    dead: string[] = [];delivered: string[] = [];
    override async settle(claim: DestinationClaim, ids: readonly string[], outcome: Settlement) {
      const accepted = await super.settle(claim, ids, outcome);if (!accepted) return false;
      for (const event of this.current.events.filter(event => ids.includes(event.id))) {
        if (outcome.kind === 'retry') event.attempts += 1;
        if (outcome.kind === 'delivered') this.delivered.push(event.id);
        if (outcome.kind === 'dead' || event.attempts >= MAX_ATTEMPTS) this.dead.push(event.id);
      }
      this.current.events = this.current.events.filter(event => !this.dead.includes(event.id) && !this.delivered.includes(event.id));
      this.current.failures = outcome.kind === 'retry' ? this.current.failures + 1 : 0;
      return true;
    }
  }
  const store = new PoisonStore();store.current.events = [row(ID, { poison: true }), row(ID2, { valid: true })];
  const sent: WireEvent[][] = [];let current: readonly WireEvent[] = [];
  const deps = { store, random: () => 0,
    async sign(_client: string, events: readonly WireEvent[]) { current = events;sent.push(structuredClone([...events]));return 'signed'; },
    async send() { return current.some(event => event.id === ID) ? 400 : 204; } };
  await deliverDestination(deps, 'rp');assert.deepEqual(sent[0].map(event => event.id), [ID, ID2]);
  for (let attempt = 1; attempt < MAX_ATTEMPTS; attempt++) await deliverDestination(deps, 'rp');
  assert.deepEqual(store.dead, [ID]);assert.equal(store.current.events[0].id, ID2);assert.equal(store.current.events[0].attempts, 1);
  assert.ok(sent.slice(1).every(batch => batch.length === 1 && batch[0].id === ID));
  await deliverDestination(deps, 'rp');assert.deepEqual(store.delivered, [ID2]);assert.deepEqual(store.dead, [ID]);
  assert.deepEqual(sent.at(-1), [{ id: ID2, type: 'account.roles_change', payload: { valid: true } }]);
  assert.equal((store.settled[MAX_ATTEMPTS - 1].outcome as {delayMs:number}).delayMs, 3_600_000);
});

test('delivery retry preserves exact IDs and payloads while signing a fresh envelope', async () => {
  const store = new FakeStore(), snapshots: WireEvent[][] = [], tokens: string[] = [];
  let attempt = 0;
  const deps = { store, random: () => 0,
    async sign(_client: string, events: readonly WireEvent[]) { snapshots.push(structuredClone([...events]));return `new-envelope-${++attempt}`; },
    async send(_uri: string, token: string) { tokens.push(token);return attempt === 1 ? 503 : 204; } };
  await deliverDestination(deps, 'rp');await deliverDestination(deps, 'rp');
  assert.deepEqual(snapshots[0], snapshots[1]);assert.notEqual(tokens[0], tokens[1]);
  assert.deepEqual(store.settled[0], { ids: [ID], outcome: { kind: 'retry', code: 'http_rejected', delayMs: 60_000 } });
  assert.equal(store.settled[1].outcome.kind, 'delivered');
});

test('ACK then uncertain settlement leaves the immutable event retryable', async () => {
  const store = new FakeStore(), sent: WireEvent[][] = [];
  const deps = { store, async sign(_client: string, events: readonly WireEvent[]) { sent.push([...events]);return 'signed'; }, async send() { return 204; } };
  store.settleError = true;
  await assert.rejects(deliverDestination(deps, 'rp'), /synthetic settlement loss/);
  store.settleError = false;await deliverDestination(deps, 'rp');
  assert.deepEqual(sent[0], sent[1]);assert.equal(store.settled.length, 1);
});

test('only the receiver 204 acknowledgment settles delivery; 200 HTML and other 2xx responses retry', async () => {
  for (const response of [new Response('<html>edge challenge</html>', { status: 200, headers: { 'content-type': 'text/html' } }),
    new Response(null, { status: 201 }), new Response(null, { status: 202 }), new Response(null, { status: 206 })]) {
    const store = new FakeStore();
    await deliverDestination({ store, random: () => 0, async sign() { return 'signed'; }, async send() { return response.status; } }, 'rp');
    assert.deepEqual(store.settled[0].outcome, { kind: 'retry', code: 'http_rejected', delayMs: 60_000 });
  }
});

test('lost lease before HTTP prevents sending; a late HTTP result cannot settle new ownership', async () => {
  const store = new FakeStore();let sends = 0;const reports: string[] = [];
  store.renews = false;
  const deps = { store, async sign() { return 'signed'; }, async send() { sends++;store.current.token = 'new-owner';return 204; }, report: (code: string) => reports.push(code) };
  await deliverDestination(deps, 'rp');assert.equal(sends, 0);
  store.renews = true;await deliverDestination(deps, 'rp');
  assert.equal(sends, 1);assert.equal(store.settled.length, 0);assert.deepEqual(reports, ['lease_lost']);
});

test('successful isolated retries drain immediately in FIFO order with an eight-claim cap', async () => {
  const store = new FakeStore();
  const queue = Array.from({ length: 10 }, (_, n) => ({ ...row(`00000000-0000-4000-8000-${String(n).padStart(12, '0')}`), attempts: 1 }));
  const expected = queue.map(e => e.id), sent: string[] = [];
  store.claim = async () => ({ ...store.current, events: structuredClone(queue) });
  store.settle = async (_claim, ids, outcome) => {
    assert.equal(outcome.kind, 'delivered');assert.deepEqual(ids, [queue[0].id]);queue.shift();return true;
  };
  await drainDestination({ store, async sign(_client, events) { sent.push(events[0].id);return 'signed'; }, async send() { return 204; } }, 'rp');
  assert.deepEqual(sent, expected.slice(0, 8));assert.deepEqual(queue.map(e => e.id), expected.slice(8));
});

test('immediate draining stops at the first rejection or lease loss, without another attempt', async () => {
  for (const failure of ['http', 'lease'] as const) {
    const store = new FakeStore();let claims = 0, sends = 0;
    store.claim = async () => { claims++;return structuredClone(store.current); };
    store.renew = async () => failure !== 'lease' || claims < 3;
    await drainDestination({ store, random: () => 0, async sign() { return 'signed'; },
      async send() { sends++;return failure === 'http' && sends === 3 ? 503 : 204; } }, 'rp');
    assert.equal(claims, 3);assert.equal(sends, failure === 'http' ? 3 : 2);
    assert.equal(store.settled.filter(s => s.outcome.kind === 'delivered').length, 2);
  }
});

test('missing endpoint and oversized oldest row dead-letter without bypassing or HTTP', async () => {
  const store = new FakeStore();let signs = 0;
  const deps = { store, async sign() { signs++;return 'signed'; }, async send() { throw new Error('unexpected HTTP'); } };
  store.current.uri = null;await deliverDestination(deps, 'rp');
  assert.deepEqual(store.settled[0].outcome, { kind: 'dead', code: 'destination_unavailable' });
  store.current.events = [row(ID, { text: 'x'.repeat(EVENT_BYTES_MAX) }), row(ID2)];
  await deliverDestination(deps, 'rp');
  assert.deepEqual(store.settled[1], { ids: [ID], outcome: { kind: 'dead', code: 'event_too_large' } });
  assert.equal(signs, 0);
});

test('signing and transport failures use fixed diagnostic codes and capped backoff', async () => {
  const store = new FakeStore();store.current.failures = 49;
  await deliverDestination({ store, random: () => 0, async sign() { throw new Error('secret signing detail'); }, async send() { return 204; } }, 'rp');
  assert.deepEqual(store.settled[0].outcome, { kind: 'retry', code: 'signing_failed', delayMs: 3_600_000 });
  await deliverDestination({ store, random: () => 0, async sign() { return 'signed'; }, async send() { throw new Error('secret endpoint detail'); } }, 'rp');
  assert.deepEqual(store.settled[1].outcome, { kind: 'retry', code: 'delivery_failed', delayMs: 3_600_000 });
  assert.equal(backoffMs(1, () => 0), 60_000);assert.equal(backoffMs(1e9, () => 0), 3_600_000);
});

class InsertDb implements EventQuery {
  calls: { sql: string; values: unknown[] }[] = [];
  saved = new Map<string, unknown[]>();
  async query(sql: string, values: unknown[] = []) {
    this.calls.push({ sql, values });
    if (sql.startsWith('INSERT INTO event_outbox')) {
      if (this.saved.has(String(values[0]))) return { rows: [] };
      this.saved.set(String(values[0]), structuredClone(values));return { rows: [{ id: values[0] }] };
    }
    if (sql.startsWith('SELECT id')) {
      const existing = this.saved.get(String(values[0]));
      return { rows: existing && values.every((v, i) => JSON.stringify(v) === JSON.stringify(existing[i])) ? [{ id: values[0], status: existing[7] ?? 'pending' }] : [] };
    }
    return { rows: [] };
  }
}

test('insert freezes payload, preserves bigint revision, and refuses conflicting exact IDs', async () => {
  const db = new InsertDb(), event = { id: ID, type: 'account.roles_change', payload: { role_id: 7 }, version: '9007199254740993' };
  const pending = insertEvents(db, 'rp', [event]);event.payload.role_id = 8;await pending;
  assert.equal(db.saved.get(ID)?.[3], '{"role_id":7}');assert.equal(db.saved.get(ID)?.[4], '9007199254740993');
  await insertEvents(db, 'rp', [{ ...event, payload: { role_id: 7 } }]);
  await assert.rejects(insertEvents(db, 'rp', [event]), /event_id_conflict/);
  assert.ok(db.calls.findIndex(c => c.sql.includes('FOR UPDATE')) < db.calls.findIndex(c => c.sql.startsWith('INSERT INTO event_outbox')));
});

test('invalid or oversized new events fail before any SQL write', async () => {
  for (const event of [
    { type: 'logout', payload: {}, version: '01' }, { type: 'logout', payload: {}, version: '9223372036854775808' },
    { type: 'logout', payload: {}, version: 1 as unknown as string }, { type: 'logout', payload: { text: '界'.repeat(EVENT_BYTES_MAX) } },
  ]) {
    const db = new InsertDb();await assert.rejects(insertEvents(db, 'rp', [event]));assert.equal(db.calls.length, 0);
  }
});

const legacy = (type = 'logout') => JSON.stringify({ id: ID, type, payload: { sub: SUBJECT, role_id: 7 }, attempts: 4, created_at: 1000 });
test('legacy receipts preserve ID, payload, attempts, timestamps and exact raw bytes', async () => {
  const db = new InsertDb(), member = legacy('account.roles_change');
  const event = parseLegacyEvent(member, '4000');
  assert.equal(await insertLegacyEvent(db, 'rp', event), true);
  const values = db.saved.get(ID)!;
  assert.deepEqual(values.slice(0, 5), [ID, 'account.roles_change', 'rp', '{"sub":"'+SUBJECT+'","role_id":7}', 4]);
  assert.equal((values[5] as Date).getTime(), 4000);assert.equal((values[6] as Date).getTime(), 1000);
  assert.equal(values[7], 'dead');assert.equal(values[8], 'legacy_role_replaced');assert.equal(values[9], member);
  assert.equal(await insertLegacyEvent(db, 'rp', event), false);
});

function redisFixture(member = legacy()) {
  const members = new Map<string, string>([[member, '4000']]), timeline: string[] = [];
  const redis: LegacyRedis = {
    async scan() { return ['0', ['events:out:orphan-rp']]; }, async sscan() { return ['0', []]; },
    async zscan() { return ['0', [...members].flat()]; },
    async zrem(_key, raw) { timeline.push('remove');return members.delete(raw) ? 1 : 0; },
  };
  return { redis, members, timeline };
}

test('orphan legacy queue imports only after durable commit, and retries after commit/remove gap', async () => {
  const fixture = redisFixture(), stored = new Set<string>(), reports: string[] = [];
  let failDelete = true;
  const remove = fixture.redis.zrem;
  fixture.redis.zrem = async (key, member) => { if (failDelete) { failDelete = false;throw new Error('Redis unavailable'); }return remove(key, member); };
  const run = createLegacyImporter({ redis: fixture.redis,
    async persist(clientId, event) { assert.equal(clientId, 'orphan-rp');stored.add(event.id);fixture.timeline.push('commit'); },
    report: code => reports.push(code) });
  await run();assert.equal(stored.size, 1);assert.equal(fixture.members.size, 1);
  await run();assert.equal(stored.size, 1);assert.equal(fixture.members.size, 0);
  assert.deepEqual(fixture.timeline, ['commit', 'commit', 'remove']);assert.deepEqual(reports, ['legacy_import_failed']);
});

test('failed persistence, corrupt and oversized legacy entries remain with bounded diagnostics', async () => {
  for (const member of [legacy(), '{bad secret body', 'x'.repeat(LEGACY_MEMBER_BYTES_MAX + 1)]) {
    const fixture = redisFixture(member), diagnostics: { code: string; digest: string }[] = [];
    const run = createLegacyImporter({ redis: fixture.redis, async persist() { throw new Error('secret database details'); },
      report: (code, digest) => diagnostics.push({ code, digest }) });
    await run();assert.equal(fixture.members.size, 1);assert.deepEqual(fixture.timeline, []);
    assert.equal(diagnostics.length, 1);assert.match(diagnostics[0].digest, /^[a-f0-9]{64}$/);
    assert.ok(!JSON.stringify(diagnostics).includes('secret'));
  }
});

test('legacy parser rejects malformed timestamps, attempts and undeliverable nonrole size', () => {
  for (const patch of [{ attempts: -1 }, { attempts: 1.5 }, { created_at: null }, { payload: null }, { id: 'invalid' }]) {
    assert.throws(() => parseLegacyEvent(JSON.stringify({ ...JSON.parse(legacy()), ...patch }), '4000'), /legacy_member_invalid/);
  }
  assert.throws(() => parseLegacyEvent(legacy(), 'NaN'), /legacy_member_invalid/);
  assert.throws(() => parseLegacyEvent(JSON.stringify({ ...JSON.parse(legacy()), payload: { text: 'x'.repeat(EVENT_BYTES_MAX) } }), '4000'), /legacy_event_too_large/);
});
