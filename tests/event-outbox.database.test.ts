import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { deliverDestination, insertEvents, insertLegacyEvent, parseLegacyEvent, PostgresOutboxStore } from '../src/events/outboxStore.js';

test('durable outbox transactions, FIFO and lease CAS in isolated PostgreSQL', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  const schema = 'event_outbox_' + crypto.randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 8, options: `-c search_path=${schema},public`, application_name: schema });
  const store = new PostgresOutboxStore(database);
  const transaction = async <T>(work: (db: pg.PoolClient) => Promise<T>): Promise<T> => {
    const db = await database.connect();
    try { await db.query('BEGIN');const value = await work(db);await db.query('COMMIT');return value; }
    catch (error) { await db.query('ROLLBACK');throw error; }
    finally { db.release(); }
  };
  const enqueue = (client: string, payload = {}, id = crypto.randomUUID()) =>
    transaction(db => insertEvents(db, client, [{ id, type: 'test.event', payload }]));
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query(await readFile(new URL('../db/migrations/001-role-event-consistency.sql', import.meta.url), 'utf8'));
    for (const client of ['rollback', 'lease', 'retry', 'delayed', 'network', 'concurrent', 'legacy', 'conflict']) {
      await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,events_uri) VALUES($1,$1,'{}',$2)",
        [client, 'https://rp.example.invalid/backchannel/events']);
    }

    await t.test('enqueue rollback leaves no intent or destination; bigint and ID remain immutable', async () => {
      const id = crypto.randomUUID();
      await assert.rejects(transaction(async db => {
        await insertEvents(db, 'rollback', [{ id, type: 'test.event', payload: { value: null }, version: '9007199254740993' }]);
        throw new Error('injected before commit');
      }), /injected before commit/);
      assert.equal((await database.query("SELECT 1 FROM event_destinations WHERE client_id='rollback'")).rowCount, 0);
      assert.equal((await database.query('SELECT 1 FROM event_outbox WHERE id=$1', [id])).rowCount, 0);
      await transaction(db => insertEvents(db, 'rollback', [{ id, type: 'test.event', payload: { value: null }, version: '9007199254740993' }]));
      const saved = (await database.query('SELECT version::text,payload FROM event_outbox WHERE id=$1', [id])).rows[0];
      assert.equal(saved.version, '9007199254740993');assert.deepEqual(saved.payload, { value: null });
      await assert.rejects(transaction(db => insertEvents(db, 'rollback', [{ id, type: 'test.event', payload: { value: 4 } }])), /event_id_conflict/);
    });

    await t.test('only one live owner; expiry permits recovery and rejects late settlement', async () => {
      const [id] = await enqueue('lease');
      const first = await store.claim('lease');assert.ok(first);
      assert.equal(await store.claim('lease'), null);
      await database.query("UPDATE event_destinations SET lease_until=clock_timestamp()-interval '1 second' WHERE client_id='lease'");
      assert.equal(await store.renew(first), false);
      const second = await store.claim('lease');assert.ok(second);assert.notEqual(first.token, second.token);
      assert.equal(await store.settle(first, [id], { kind: 'delivered' }), false);
      assert.equal((await database.query('SELECT status FROM event_outbox WHERE id=$1', [id])).rows[0].status, 'pending');
      assert.equal(await store.settle(second, [id], { kind: 'delivered' }), true);
      assert.equal((await database.query('SELECT status FROM event_outbox WHERE id=$1', [id])).rows[0].status, 'delivered');
    });

    await t.test('failed send retries atomically and attempt fifty dead-letters without bypassing delayed successor', async () => {
      const [first] = await enqueue('retry', { n: 1 }), [second] = await enqueue('retry', { n: 2 });
      await database.query('UPDATE event_outbox SET attempts=49 WHERE id=$1', [first]);
      const claim = await store.claim('retry');assert.ok(claim);
      await store.settle(claim, [first, second], { kind: 'retry', code: 'delivery_failed', delayMs: 60_000 });
      const rows = (await database.query("SELECT id,status,attempts,last_error_code FROM event_outbox WHERE target_client_id='retry' ORDER BY sequence")).rows;
      assert.deepEqual(rows.map(r => [r.status, r.attempts, r.last_error_code]), [['dead', 50, 'delivery_failed'], ['pending', 1, 'delivery_failed']]);
      const [third] = await enqueue('retry', { n: 3 });assert.equal(await store.claim('retry'), null);
      await database.query("UPDATE event_destinations SET next_attempt_at=now()-interval '1 second' WHERE client_id='retry'");
      assert.equal(await store.claim('retry'), null); // First pending row is still delayed.
      await database.query("UPDATE event_outbox SET next_attempt_at=now()-interval '1 second' WHERE id=$1", [second]);
      await database.query("UPDATE event_destinations SET next_attempt_at=now()-interval '1 second' WHERE client_id='retry'");
      const due = await store.claim('retry');assert.ok(due);assert.deepEqual(due.events.map(e => e.id), [second, third]);
    });

    await t.test('fresh signing and HTTP run after the claim transaction commits', async () => {
      await enqueue('network');let sends = 0;
      await deliverDestination({ store,
        async sign() {
          assert.equal((await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND state='idle in transaction'", [schema])).rowCount, 0);
          return 'synthetic-token';
        },
        async send() {
          sends++;
          assert.equal((await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND state='idle in transaction'", [schema])).rowCount, 0);
          return 204;
        },
      }, 'network');
      assert.equal(sends, 1);
      assert.equal((await database.query("SELECT status FROM event_outbox WHERE target_client_id='network'")).rows[0].status, 'delivered');
    });

    await t.test('destination lock prevents commit-order inversion between two producers', async () => {
      const a = await database.connect(), b = await database.connect();
      const first = crypto.randomUUID(), second = crypto.randomUUID();let secondFinished = false;
      let inserting: Promise<unknown> | undefined;
      try {
        await a.query('BEGIN');await b.query('BEGIN');
        await insertEvents(a, 'concurrent', [{ id: first, type: 'test.event', payload: { n: 1 } }]);
        inserting = insertEvents(b, 'concurrent', [{ id: second, type: 'test.event', payload: { n: 2 } }]).then(() => { secondFinished = true; });
        const deadline = Date.now() + 2000;
        while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [schema])).rowCount) {
          if (Date.now() > deadline) throw new Error('Concurrent producer did not reach the destination lock.');
          await new Promise(resolve => setTimeout(resolve, 5));
        }
        assert.equal(secondFinished, false);await a.query('COMMIT');await inserting;await b.query('COMMIT');
        const claim = await store.claim('concurrent');assert.ok(claim);assert.deepEqual(claim.events.map(e => e.id), [first, second]);
      } finally {
        await a.query('ROLLBACK').catch(() => {});await inserting?.catch(() => {});await b.query('ROLLBACK').catch(() => {});a.release();b.release();
      }
    });

    await t.test('legacy role receipt and fresh replacement commit together and never reactivate old ID', async () => {
      const oldId = crypto.randomUUID(), newId = crypto.randomUUID();
      const member = JSON.stringify({ id: oldId, type: 'account.roles_change', payload: { sub: crypto.randomUUID(), role_id: 99 }, attempts: 3, created_at: 1000 });
      const event = parseLegacyEvent(member, '4000');
      await assert.rejects(transaction(async db => {
        await insertLegacyEvent(db, 'legacy', event);
        await insertEvents(db, 'legacy', [{ id: newId, type: 'account.roles_change', payload: { role_id: null }, version: '1' }]);
        throw new Error('injected replacement failure');
      }), /injected replacement failure/);
      assert.equal((await database.query("SELECT 1 FROM event_outbox WHERE target_client_id='legacy'")).rowCount, 0);
      await transaction(async db => {
        assert.equal(await insertLegacyEvent(db, 'legacy', event), true);
        await insertEvents(db, 'legacy', [{ id: newId, type: 'account.roles_change', payload: { role_id: null }, version: '1' }]);
      });
      await transaction(async db => { assert.equal(await insertLegacyEvent(db, 'legacy', event), false); });
      const rows = (await database.query("SELECT id,status,payload,version::text,legacy_redis_member,legacy_redis_score FROM event_outbox WHERE target_client_id='legacy' ORDER BY sequence")).rows;
      assert.equal(rows.length, 2);assert.equal(rows[0].id, oldId);assert.equal(rows[0].status, 'dead');assert.equal(rows[0].payload.role_id, 99);
      assert.equal(rows[0].legacy_redis_member, member);assert.equal(rows[0].legacy_redis_score, 4000);
      assert.equal(rows[1].id, newId);assert.equal(rows[1].status, 'pending');assert.equal(rows[1].version, '1');assert.equal(rows[1].payload.role_id, null);
      const claim = await store.claim('legacy');assert.ok(claim);assert.deepEqual(claim.events.map(e => e.id), [newId]);
    });
  } finally {
    await database.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
