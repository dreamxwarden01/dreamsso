import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';
import { revokeSessions, withRevocationTransaction } from '../src/oidc/sessionRevocation.js';
import { changeAccountStatus } from '../src/rbac/accountStatus.js';
import { withRoleTransaction } from '../src/rbac/roleChanges.js';

const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
test('session deletion and logout intents commit or roll back together', { skip: !connectionString }, async t => {
  const url = new URL(connectionString!);
  assert.equal(url.hostname, '127.0.0.1');assert.equal(url.pathname, '/dreamsso_role_sync_test');
  const schema = 'revocation_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 1, connectionTimeoutMillis: 1000,
    options: `-c search_path=${schema},public`, application_name: schema + '_revoke' });
  const other = new pg.Pool({ connectionString, max: 1,
    options: `-c search_path=${schema},public`, application_name: schema + '_issuer' });
  const sub = randomUUID(), foreign = randomUUID();
  const seed = async (subject = sub, clients = ['a', 'b']) => {
    const sid = randomUUID();
    await database.query('INSERT INTO sessions(sid,user_sub,token_hash,clients,expires_at) VALUES($1,$2,$3,$4,now()+interval \'1 day\')',
      [sid, subject, randomBytes(32), clients]);return sid;
  };
  const reset = async () => { await database.query('DELETE FROM sessions');await database.query('DELETE FROM event_outbox'); };
  const revoke = (selection: Parameters<typeof revokeSessions>[1]) => withRevocationTransaction(database, db => revokeSessions(db, selection));
  const count = async (table: 'sessions'|'event_outbox') => Number((await database.query(`SELECT count(*) AS n FROM ${table}`)).rows[0].n);
  const waitForLock = async () => {
    const until = Date.now() + 3000;
    while (Date.now() < until) {
      if ((await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [schema + '_revoke'])).rows.length) return;
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    throw Error('Expected local session lock wait not observed');
  };
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await database.query("INSERT INTO identities(sub,username,display_name,password_hash) VALUES($1,'actor','Actor','before'),($2,'foreign','Foreign','before')", [sub, foreign]);
    await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris) VALUES('a','A','{}'),('b','B','{}'),('disabled','Disabled','{}')");
    await database.query("UPDATE oauth_clients SET disabled_at=now() WHERE client_id='disabled'");
    await t.test('one owned SID captures each touched recipient once and duplicate revocation is inert', async () => {
      await reset();const sid = await seed(sub, ['a','b','a']);await seed(foreign);
      assert.equal(await revoke({ subject: sub, sid }), 1);
      const { rows } = await database.query('SELECT kind,target_client_id,payload FROM event_outbox ORDER BY target_client_id');
      assert.deepEqual(rows.map(r => [r.kind,r.target_client_id,r.payload]), [
        ['logout','a',{sub,sid}],['logout','b',{sub,sid}],
      ]);
      assert.equal(await count('sessions'), 1);assert.equal(await revoke({ subject: sub, sid }), 0);assert.equal(await count('event_outbox'), 2);
    });
    await t.test('an outbox insert failure rolls back identity change, session deletion and earlier recipients', async () => {
      await reset();const sid = await seed();
      await database.query(`CREATE FUNCTION reject_fixture_logout() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.target_client_id='b' THEN RAISE EXCEPTION 'fixture_outbox_failure'; END IF; RETURN NEW; END $$`);
      await database.query('CREATE TRIGGER reject_fixture_logout BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION reject_fixture_logout()');
      try {
        await assert.rejects(withRevocationTransaction(database, async db => {
          await db.query("UPDATE identities SET password_hash='after' WHERE sub=$1", [sub]);
          return revokeSessions(db, { subject: sub, sid });
        }), /fixture_outbox_failure/);
        assert.equal((await database.query('SELECT password_hash FROM identities WHERE sub=$1', [sub])).rows[0].password_hash, 'before');
        assert.equal(await count('sessions'), 1);assert.equal(await count('event_outbox'), 0);
      } finally { await database.query('DROP TRIGGER reject_fixture_logout ON event_outbox'); }
    });
    await t.test('all/except and foreign SID selection preserve the caller scope', async () => {
      await reset();const keep = await seed(), removed = await seed(), theirs = await seed(foreign);
      assert.equal(await revoke({ subject: sub, sid: theirs }), 0);
      assert.equal(await revoke({ subject: sub, exceptSid: keep }), 1);
      const events = (await database.query('SELECT payload FROM event_outbox')).rows;
      assert.ok(events.every(r => r.payload.sid === removed));
      assert.equal(await count('sessions'), 2);assert.equal(await revoke({ subject: sub }), 1);
      assert.deepEqual((await database.query('SELECT sid FROM sessions')).rows.map(r=>r.sid), [theirs]);
    });
    await t.test('removed registration does not block logout; disabled existing registration keeps intent', async () => {
      await reset();const sid = await seed(sub, ['removed','disabled']);
      assert.equal(await revoke({ subject: sub, sid }), 1);
      assert.deepEqual((await database.query('SELECT target_client_id FROM event_outbox')).rows, [{ target_client_id:'disabled' }]);
      assert.equal(await count('sessions'), 0);
    });
    await t.test('expiry cleanup retains exact subject and SID payload and leaves active sessions', async () => {
      await reset();const expired = await seed(), active = await seed();
      await database.query("UPDATE sessions SET last_seen=now()-interval '2 days' WHERE sid=$1", [expired]);
      const before = new Date(Date.now()-86400000);
      assert.equal(await revoke({ expired: { idleBefore:before,persistentBefore:before,transientBefore:before } }),1);
      assert.deepEqual((await database.query('SELECT sid FROM sessions')).rows.map(r=>r.sid),[active]);
      assert.ok((await database.query('SELECT payload FROM event_outbox')).rows.every(r=>r.payload.sub===sub&&r.payload.sid===expired));
    });
    await t.test('logout waits for committed participant registration and includes its new recipient', async () => {
      await reset();const sid = await seed(sub, ['a']), issuer = await other.connect();
      let pending:Promise<number>|undefined;
      try {
        await issuer.query('BEGIN');await issuer.query('SELECT sid FROM sessions WHERE sid=$1 FOR UPDATE',[sid]);
        await issuer.query("UPDATE sessions SET clients=array_append(clients,'b') WHERE sid=$1",[sid]);
        pending = revoke({subject:sub,sid});await waitForLock();
        assert.equal((await admin.query(`SELECT count(*)::int AS n FROM ${schema}.sessions`)).rows[0].n,1);
        await issuer.query('COMMIT');assert.equal(await pending,1);
        assert.deepEqual((await database.query('SELECT target_client_id FROM event_outbox ORDER BY target_client_id')).rows.map(r=>r.target_client_id),['a','b']);
      } finally {await issuer.query('ROLLBACK').catch(()=>{});issuer.release();await pending?.catch(()=>{});}
    });
    await t.test('suspend and ordinary logout lock the union of destinations without reversing groups', async () => {
      await reset();
      await database.query("INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES('a',NULL),('b',NULL)");
      await seed(sub, ['b']);await seed(foreign, ['a','b']);
      let announce!: () => void, release!: () => void;
      const firstLock = new Promise<void>(resolve => { announce = resolve; });
      const barrier = new Promise<void>(resolve => { release = resolve; });
      let suspend: Promise<unknown> | undefined;
      const logout = withRevocationTransaction(other, async db => {
        const wrapped = new Proxy(db, { get(target, property) {
          if (property !== 'query') { const value = Reflect.get(target, property);return typeof value === 'function' ? value.bind(target) : value; }
          return async (sql: string, values?: unknown[]) => {
            const result = await target.query(sql, values);
            if (sql === 'SELECT client_id FROM event_destinations WHERE client_id=$1 FOR UPDATE' && values?.[0] === 'a') {
              announce();await barrier;
            }
            return result;
          };
        } });
        return revokeSessions(wrapped, { subject: foreign });
      });
      try {
        await firstLock;
        suspend = withRoleTransaction(db => changeAccountStatus(db, sub, 'disabled', async connection => {
          await revokeSessions(connection, { subject: sub });
        }), database);
        await waitForLock();
        release();
        assert.equal(await logout, 1);await suspend;
        assert.equal(await count('sessions'), 0);
        assert.equal(await count('event_outbox'), 5);
      } finally {
        release();await logout.catch(()=>{});await suspend?.catch(()=>{});
        await database.query("UPDATE identities SET status='active' WHERE sub=$1", [sub]);
      }
    });
    await t.test('transaction wrapper never reports success or retains work after caller failure', async () => {
      await reset();await seed();
      await assert.rejects(withRevocationTransaction(database,async db=>{await revokeSessions(db,{subject:sub});throw Error('fixture_after_delete');}),/fixture_after_delete/);
      assert.equal(await count('sessions'),1);assert.equal(await count('event_outbox'),0);
      assert.equal(database.waitingCount,0);assert.equal(await revoke({subject:sub}),1);
    });
  } finally {
    await database.end();await other.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
