import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

test('role administration preserves authority ceilings and atomic delivery in isolated PostgreSQL', async t => {
  const connectionString = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!connectionString) throw new Error('An isolated DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL fixture is required.');
  const url = new URL(connectionString);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw new Error('Only the generated local fixture database is allowed.');
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = connectionString;
  const { applyUserAccess, applyRoleAccess, createOrgRole, patchOrgRole, deleteOrgRole,
    setDefaultOrgRole, createOrgUser, RoleAccessError } = await import('../src/rbac/roleAdministration.js');
  const { withRoleTransaction } = await import('../src/rbac/roleChanges.js');
  const { pool: unusedDefaultPool } = await import('../src/db.js');
  const schema = 'role_admin_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString, max: 2 });
  const database = new pg.Pool({ connectionString, max: 8, options: `-c search_path=${schema},public`, application_name: schema });
  const ids = Object.fromEntries(['actor', 'target', 'second', 'personalNull', 'personalFixed', 'elevated', 'peer', 'senior', 'outsider', 'noOrg'].map(name => [name, randomUUID()]));
  const grants = ['org.users.edit.permissions.acctPortal', 'org.users.edit.permissions.app',
    'org.roles.edit.permissions.acctPortal', 'org.roles.edit.permissions.app', 'profile.displayname.change',
    'org.roles.create', 'org.roles.edit.rename', 'org.roles.edit.level', 'org.roles.remove', 'org.roles.edit.default', 'org.users.create'];
  const denied = (error: string, status = 403) => (e: unknown) => e instanceof RoleAccessError && e.status === status && e.body.error === error;
  const user = (target: string, changes: Record<string, unknown>, action?: string) =>
    withRoleTransaction(db => applyUserAccess(db, ids.actor, target, changes, action), database);
  const role = (slug: string, changes: Record<string, unknown>, action?: string) =>
    withRoleTransaction(db => applyRoleAccess(db, ids.actor, slug, changes, action), database);
  const events = () => database.query('SELECT id,target_client_id,payload,version::text FROM event_outbox ORDER BY sequence');
  const revisions = async () => (await database.query('SELECT client_id,authority_revision::text FROM app_role_sync_state ORDER BY client_id')).rows;
  const state = async () => {
    const tables = ['identities', 'org_roles', 'settings', 'user_org_roles', 'user_app_role_overrides', 'user_permission_overrides', 'org_role_app_defaults',
      'role_permissions', 'app_role_sync_state', 'app_role_effective', 'event_outbox', 'event_destinations', 'processed_events', 'org_audit_log'];
    return Promise.all(tables.map(async table => ({ table, rows: (await database.query(
      `SELECT COALESCE(jsonb_agg(to_jsonb(t) ORDER BY to_jsonb(t)::text),'[]'::jsonb) AS rows FROM ${table} t`)).rows[0].rows })));
  };
  let migration: string;
  const reset = async () => {
    await database.query('TRUNCATE oauth_clients,identities,org_roles,org_audit_log,processed_events CASCADE');
    await database.query(`INSERT INTO org_roles(slug,label,level) VALUES
      ('administrator','Administrator',10),('peer','Peer',10),('senior','Senior',5),('member','Member',100),
      ('candidate','Candidate',150),('trap','Trap',200),('other','Other',150)`);
    await database.query("INSERT INTO settings(key,value) VALUES('default_org_role','member') ON CONFLICT(key) DO UPDATE SET value='member'");
    for (const [name, id] of Object.entries(ids)) {
      await database.query('INSERT INTO identities(sub,username,display_name) VALUES($1,$2::text,$2::text)', [id, name]);
      const slug = name === 'actor' ? 'administrator' : name === 'peer' ? 'peer' : name === 'senior' ? 'senior'
        : name === 'outsider' ? 'other' : name === 'noOrg' ? null : 'member';
      if (slug) await database.query('INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,$2)', [id, slug]);
    }
    for (const permission of grants) await database.query("INSERT INTO role_permissions(role_slug,perm_key,effect) VALUES('administrator',$1,'grant')", [permission]);
    await database.query("INSERT INTO role_permissions(role_slug,perm_key,effect) VALUES('administrator','profile.security.mfa.disable','deny')");
    for (const client of ['a', 'b']) {
      await database.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,events_uri) VALUES($1,$1,'{}','https://rp.example.invalid/backchannel/events')", [client]);
      for (const [id, level] of [[1, 0], [2, 10], [3, 20], [4, 30]]) {
        await database.query('INSERT INTO app_roles(client_id,role_id,name,level) VALUES($1,$2,$3,$4)', [client, id, 'Role ' + id, level]);
      }
      await database.query('INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES($1,4)', [client]);
      for (const [slug, id] of [['administrator', 2], ['member', 3], ['candidate', 4], ['trap', 1], ['other', 4]] as const) {
        await database.query('INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES($1,$2,$3)', [slug, client, id]);
      }
    }
    await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'a',NULL),($2,'a',4),($3,'a',1)",
      [ids.personalNull, ids.personalFixed, ids.elevated]);
    // Seed the role ledger; upgrade-request delivery is covered by migration tests.
    await database.query(migration);
    await database.query("DELETE FROM event_outbox WHERE kind='roles.sync_request' AND payload->>'reason'='role_event_consistency_upgrade'");
  };
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await database.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    migration = await readFile(new URL('../db/migrations/001-role-event-consistency.sql', import.meta.url), 'utf8');
    await database.query(migration);

    await t.test('org targets, promotions, current app role and new app role retain their ceilings', async () => {
      await reset();const before = await state();
      for (const target of [ids.actor, ids.peer, ids.senior]) await assert.rejects(user(target, { app_roles: { a: 3 } }), denied('not_found', 404));
      await assert.rejects(user(ids.target, { org_role: 'administrator' }), denied('role_above_level'));
      await assert.rejects(user(ids.target, { app_roles: { a: 1 } }), denied('app_role_above_level'));
      await assert.rejects(user(ids.elevated, { app_roles: { a: 4 } }), denied('app_role_above_level'));
      await assert.rejects(user(ids.target, { org_role: 'trap' }), denied('app_role_above_level'));
      await assert.rejects(role('member', { app_defaults: { a: 2 } }), denied('app_role_above_level'));
      await assert.rejects(role('administrator', { app_defaults: { a: 4 } }), denied('role_above_level'));
      assert.deepEqual(await state(), before);
      // User assignment permits an equal app level; defining a role does not.
      await user(ids.target, { app_roles: { a: 2 } }, 'user.app_role_change');
      const out = (await events()).rows;assert.equal(out.length, 1);assert.equal(out[0].payload.role_id, 2);
    });

    await t.test('denied inherit performs no temporary delete or grant', async () => {
      await reset();
      await database.query("UPDATE user_org_roles SET org_role_slug='trap' WHERE user_sub=$1", [ids.target]);
      await database.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'a',3)", [ids.target]);
      await database.query(`CREATE FUNCTION reject_override_delete() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'temporary delete attempted'; END $$;
        CREATE TRIGGER reject_override_delete BEFORE DELETE ON user_app_role_overrides FOR EACH ROW EXECUTE FUNCTION reject_override_delete()`);
      const before = await state();
      try { await assert.rejects(user(ids.target, { app_roles: { a: 'inherit' } }), denied('app_role_above_level'));assert.deepEqual(await state(), before); }
      finally { await database.query('DROP TRIGGER reject_override_delete ON user_app_role_overrides; DROP FUNCTION reject_override_delete()'); }
    });

    await t.test('single user changes and repeated no-op saves produce only current committed role events', async () => {
      await reset();
      await user(ids.target, { app_roles: { a: 4 } }, 'user.app_role_change');
      await user(ids.target, { app_roles: { a: 4 } }, 'user.app_role_change');
      await user(ids.target, { app_roles: { a: 'inherit' } }, 'user.app_role_change');
      const out = (await events()).rows;
      assert.deepEqual(out.map(r => [r.target_client_id, r.payload.sub, r.payload.role_id, r.payload.authority_revision, r.version]),
        [['a', ids.target, 4, '1', '1'], ['a', ids.target, 3, '2', '2']]);
      assert.equal(new Set(out.map(r => r.id)).size, 2);assert.equal(new Set(out.map(r => r.payload.authority_epoch)).size, 1);
      assert.deepEqual(await revisions(), [{ client_id: 'a', authority_revision: '2' }, { client_id: 'b', authority_revision: '0' }]);
      assert.equal((await database.query("SELECT 1 FROM user_app_role_overrides WHERE user_sub=$1 AND client_id='a'", [ids.target])).rowCount, 0);
    });

    await t.test('single org-role assignment notifies both inherited apps; personal NULL stays explicit', async () => {
      await reset();await user(ids.target, { org_role: 'candidate' }, 'user.role_change');
      const out = (await events()).rows;
      assert.deepEqual(out.map(r => [r.target_client_id, r.payload.role_id, r.payload.authority_revision]), [['a', 4, '1'], ['b', 4, '1']]);
      await user(ids.personalNull, { org_role: 'candidate' }, 'user.role_change');
      const deniedOut = (await events()).rows.filter(r => r.payload.sub === ids.personalNull);
      assert.deepEqual(deniedOut.map(r => [r.target_client_id, r.payload.role_id]), [['b', 4]]);
      assert.equal((await database.query("SELECT app_role_id FROM user_app_role_overrides WHERE user_sub=$1 AND client_id='a'", [ids.personalNull])).rows[0].app_role_id, null);
    });

    await t.test('batch user save resolves inheritance against the final org role and emits the effective diff', async () => {
      await reset();
      await user(ids.target, { org_role: 'candidate', app_roles: { a: 3, b: null }, permissions: { 'profile.displayname.change': 'grant' } });
      const out = (await events()).rows;assert.equal(out.length, 1);
      assert.deepEqual([out[0].target_client_id, out[0].payload.role_id, out[0].payload.authority_revision], ['b', null, '1']);
      assert.equal((await database.query('SELECT org_role_slug FROM user_org_roles WHERE user_sub=$1', [ids.target])).rows[0].org_role_slug, 'candidate');
      assert.equal((await database.query('SELECT effect FROM user_permission_overrides WHERE user_sub=$1', [ids.target])).rows[0].effect, 'grant');
      // Supplying a safe explicit override may accompany a role whose unused
      // default outranks the actor; every remaining inherited app is checked.
      await assert.rejects(user(ids.second, { org_role: 'trap', app_roles: { a: 3 } }), denied('app_role_above_level'));
      await user(ids.second, { org_role: 'trap', app_roles: { a: 3, b: 3 } });
    });

    await t.test('single and batch role defaults notify only affected effective users with one revision per client', async () => {
      await reset();await role('member', { app_defaults: { a: 4 } }, 'role.app_default_change');
      let out = (await events()).rows;
      assert.deepEqual(out.map(r => r.payload.sub).sort(), [ids.target, ids.second].sort());
      assert.ok(out.every(r => r.payload.role_id === 4 && r.version === '1' && r.payload.authority_revision === '1'));
      assert.ok(!out.some(r => [ids.personalNull, ids.personalFixed, ids.elevated, ids.outsider, ids.noOrg].includes(r.payload.sub)));
      await reset();await role('member', { app_defaults: { a: 4, b: null }, permissions: { 'profile.displayname.change': 'grant' } });
      out = (await events()).rows;
      const a = out.filter(r => r.target_client_id === 'a'), b = out.filter(r => r.target_client_id === 'b');
      assert.deepEqual(a.map(r => r.payload.sub).sort(), [ids.target, ids.second].sort());
      assert.deepEqual(b.map(r => r.payload.sub).sort(), [ids.target, ids.second, ids.personalNull, ids.personalFixed, ids.elevated].sort());
      for (const group of [a, b]) {
        assert.equal(new Set(group.map(r => r.payload.authority_epoch)).size, 1);
        assert.ok(group.every(r => r.payload.authority_revision === '1' && r.version === '1'));
      }
      assert.ok(b.every(r => r.payload.role_id === null));
      assert.equal((await database.query("SELECT app_role_id FROM user_app_role_overrides WHERE user_sub=$1 AND client_id='a'", [ids.personalNull])).rows[0].app_role_id, null);
    });

    await t.test('permission delegation preserves held-key rule and the specific MFA-disable exception', async () => {
      await reset();const before = await state();
      await assert.rejects(user(ids.target, { permissions: { 'org.users.remove': 'grant' } }), denied('permission_denied'));
      await assert.rejects(role('member', { permissions: { 'org.users.remove': 'grant' } }), denied('permission_denied'));
      assert.deepEqual(await state(), before);
      await user(ids.target, { permissions: { 'profile.security.mfa.disable': 'grant' } });
      await role('member', { permissions: { 'profile.security.mfa.disable': 'grant' } });
      assert.equal((await events()).rows.length, 0);assert.deepEqual(await revisions(), [{ client_id: 'a', authority_revision: '0' }, { client_id: 'b', authority_revision: '0' }]);
    });

    await t.test('outbox failure rolls back user and role batches, revision, ledger, audit and caller inbox', async () => {
      await reset();await database.query("INSERT INTO processed_events(source,id) VALUES('existing-fixture',$1)", [randomUUID()]);
      await database.query(`CREATE FUNCTION fail_role_outbox() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.kind='account.roles_change' THEN RAISE EXCEPTION 'injected outbox failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER fail_role_outbox BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION fail_role_outbox()`);
      const before = await state();
      try {
        for (const apply of [
          (db: pg.PoolClient) => applyUserAccess(db, ids.actor, ids.target, { org_role: 'candidate', app_roles: { a: null }, permissions: { 'profile.displayname.change': 'grant' } }),
          (db: pg.PoolClient) => applyRoleAccess(db, ids.actor, 'member', { app_defaults: { a: null, b: 4 }, permissions: { 'profile.displayname.change': 'grant' } }),
        ]) {
          await assert.rejects(withRoleTransaction(async db => {
            await db.query("INSERT INTO processed_events(source,id) VALUES('failed-fixture',$1)", [randomUUID()]);await apply(db);
          }, database), /injected outbox failure/);
          assert.deepEqual(await state(), before);
        }
      } finally { await database.query('DROP TRIGGER fail_role_outbox ON event_outbox; DROP FUNCTION fail_role_outbox()'); }
    });

    await t.test('actor permission is rechecked after a role-write lock wait, before any mutation', async () => {
      await reset();let release!: () => void, entered!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), holding = new Promise<void>(resolve => { entered = resolve; });
      const revoke = withRoleTransaction(async db => {
        entered();await gate;
        await db.query("UPDATE role_permissions SET effect='deny' WHERE role_slug='administrator' AND perm_key='org.users.edit.permissions.app'");
      }, database);
      await holding;
      let callbackEntered = false;
      const pending = withRoleTransaction(async db => {
        callbackEntered = true;await applyUserAccess(db, ids.actor, ids.target, { app_roles: { a: 4 } });
      }, database);
      // Attach rejection handling before releasing the competing transaction.
      const rejected = assert.rejects(pending, denied('permission_denied'));
      try {
        const deadline = Date.now() + 2000;
        while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [schema])).rowCount) {
          if (Date.now() > deadline) throw new Error('Role mutation did not reach the serialization lock.');
          await new Promise(resolve => setTimeout(resolve, 5));
        }
        assert.equal(callbackEntered, false);
      } finally { release(); }
      await revoke;await rejected;
      assert.equal(callbackEntered, true);assert.equal((await events()).rows.length, 0);
      assert.equal((await database.query('SELECT 1 FROM user_app_role_overrides WHERE user_sub=$1', [ids.target])).rowCount, 0);
      assert.deepEqual(await revisions(), [{ client_id: 'a', authority_revision: '0' }, { client_id: 'b', authority_revision: '0' }]);
    });

    await t.test('role patch validates all fields and permissions before writing, preserving system/root rules', async () => {
      await reset();const before = await state();
      await assert.rejects(withRoleTransaction(db => patchOrgRole(db, ids.actor, 'candidate', { label: 'Should not persist', level: 0 }), database),
        (error: unknown) => error instanceof RoleAccessError && error.status === 422 && typeof error.body.errors === 'object');
      assert.deepEqual(await state(), before);
      await database.query("UPDATE role_permissions SET effect='deny' WHERE role_slug='administrator' AND perm_key='org.roles.edit.level'");
      await assert.rejects(withRoleTransaction(db => patchOrgRole(db, ids.actor, 'candidate', { label: 'Also rejected', level: 170 }), database), denied('permission_denied'));
      assert.equal((await database.query("SELECT label FROM org_roles WHERE slug='candidate'")).rows[0].label, 'Candidate');
      await database.query("UPDATE role_permissions SET effect='grant' WHERE role_slug='administrator' AND perm_key='org.roles.edit.level'");
      await database.query("UPDATE org_roles SET is_system=true WHERE slug='candidate'");
      await withRoleTransaction(db => patchOrgRole(db, ids.actor, 'candidate', { label: 'Changed system role', level: 160 }), database);
      assert.deepEqual((await database.query("SELECT label,level FROM org_roles WHERE slug='candidate'")).rows[0], { label: 'Changed system role', level: 160 });
      await assert.rejects(withRoleTransaction(db => deleteOrgRole(db, ids.actor, 'candidate'), database), denied('system_role', 409));
      await database.query("INSERT INTO org_roles(slug,label,level) VALUES('root','Root',0)");
      await assert.rejects(withRoleTransaction(db => patchOrgRole(db, ids.actor, 'root', { level: 100 }), database), denied('role_above_level'));
      await assert.rejects(withRoleTransaction(db => createOrgRole(db, ids.actor, { slug: 'new_root', label: 'New Root', level: 0 }), database),
        (error: unknown) => error instanceof RoleAccessError && error.status === 422);
    });

    await t.test('role creation rolls back failed seeding and assignments cannot see a half-initialized role', async () => {
      await reset();
      await database.query("INSERT INTO role_permissions(role_slug,perm_key,effect) VALUES('member','profile.displayname.change','grant')");
      await database.query(`CREATE FUNCTION reject_role_seed() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.role_slug='broken_role' THEN RAISE EXCEPTION 'injected seed failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_role_seed BEFORE INSERT ON org_role_app_defaults FOR EACH ROW EXECUTE FUNCTION reject_role_seed()`);
      const before = await state();
      try {
        await assert.rejects(withRoleTransaction(db => createOrgRole(db, ids.actor, { slug: 'broken_role', label: 'Broken', level: 150 }), database), /injected seed failure/);
        assert.deepEqual(await state(), before);
      } finally { await database.query('DROP TRIGGER reject_role_seed ON org_role_app_defaults; DROP FUNCTION reject_role_seed()'); }
      let release!: () => void, entered!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), staged = new Promise<void>(resolve => { entered = resolve; });
      const creation = withRoleTransaction(async db => {
        await createOrgRole(db, ids.actor, { slug: 'new_role', label: 'New role', level: 150 });entered();await gate;
      }, database);
      await Promise.race([staged, creation]);
      let assigned = false;
      const assignment = user(ids.target, { org_role: 'new_role' }).then(() => { assigned = true; });
      try {
        const deadline = Date.now() + 2000;
        while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event='advisory'", [schema])).rowCount) {
          if (Date.now() > deadline) throw new Error('Assignment did not wait for role creation.');
          await new Promise(resolve => setTimeout(resolve, 5));
        }
        assert.equal(assigned, false);assert.equal((await database.query("SELECT 1 FROM org_roles WHERE slug='new_role'")).rowCount, 0);
      } finally { release(); }
      await creation;await assignment;
      assert.deepEqual((await database.query("SELECT client_id,app_role_id FROM org_role_app_defaults WHERE role_slug='new_role' ORDER BY client_id")).rows,
        [{ client_id: 'a', app_role_id: 3 }, { client_id: 'b', app_role_id: 3 }]);
      assert.equal((await database.query("SELECT effect FROM role_permissions WHERE role_slug='new_role' AND perm_key='profile.displayname.change'")).rows[0].effect, 'grant');
    });

    await t.test('delete waits for earlier ordinary FK membership and cannot cascade it away', async () => {
      await reset();const member = await database.connect(), sub = randomUUID();
      try {
        await member.query('BEGIN');
        await member.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'pending-member','Pending member')", [sub]);
        await member.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'candidate')", [sub]);
        const deletion = withRoleTransaction(db => deleteOrgRole(db, ids.actor, 'candidate'), database);
        const rejected = assert.rejects(deletion, denied('role_in_use', 409));
        const deadline = Date.now() + 2000;
        while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [schema])).rowCount) {
          if (Date.now() > deadline) throw new Error('Deletion did not wait for the existing FK writer.');
          await new Promise(resolve => setTimeout(resolve, 5));
        }
        await member.query('COMMIT');await rejected;
        assert.equal((await database.query("SELECT 1 FROM org_roles WHERE slug='candidate'")).rowCount, 1);
        assert.equal((await database.query("SELECT 1 FROM user_org_roles WHERE user_sub=$1 AND org_role_slug='candidate'", [sub])).rowCount, 1);
      } finally { await member.query('ROLLBACK').catch(() => {});member.release(); }
    });

    await t.test('membership arriving after role deletion waits and fails instead of being silently removed', async () => {
      await reset();let release!: () => void, entered!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), staged = new Promise<void>(resolve => { entered = resolve; });
      const deletion = withRoleTransaction(async db => { await deleteOrgRole(db, ids.actor, 'candidate');entered();await gate; }, database);
      await Promise.race([staged, deletion]);
      const member = await database.connect();const sub = randomUUID();
      try {
        await member.query('BEGIN');await member.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'late-member','Late member')", [sub]);
        const membership = member.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'candidate')", [sub]);
        const rejected = assert.rejects(membership, (error: unknown) => (error as { code?: string }).code === '23503');
        try {
          const deadline = Date.now() + 2000;
          while (!(await admin.query("SELECT 1 FROM pg_stat_activity WHERE application_name=$1 AND wait_event_type='Lock'", [schema])).rowCount) {
            if (Date.now() > deadline) throw new Error('New membership did not wait for deletion.');
            await new Promise(resolve => setTimeout(resolve, 5));
          }
        } finally { release(); }
        await deletion;await rejected;await member.query('ROLLBACK');
        assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [sub])).rowCount, 0);
        assert.equal((await database.query("SELECT 1 FROM org_roles WHERE slug='candidate'")).rowCount, 0);
      } finally { release();await member.query('ROLLBACK').catch(() => {});member.release(); }
    });

    await t.test('default pointer and competing deletion serialize against the same current role', async () => {
      await reset();let release!: () => void, entered!: () => void;
      const gate = new Promise<void>(resolve => { release = resolve; }), staged = new Promise<void>(resolve => { entered = resolve; });
      const setting = withRoleTransaction(async db => { await setDefaultOrgRole(db, ids.actor, 'candidate');entered();await gate; }, database);
      await Promise.race([staged, setting]);
      const deletion = withRoleTransaction(db => deleteOrgRole(db, ids.actor, 'candidate'), database);
      const rejected = assert.rejects(deletion, denied('role_is_default', 409));
      try {
        assert.equal((await database.query("SELECT value FROM settings WHERE key='default_org_role'")).rows[0].value, 'member');
      } finally { release(); }
      await setting;await rejected;
      assert.equal((await database.query("SELECT value FROM settings WHERE key='default_org_role'")).rows[0].value, 'candidate');
      assert.equal((await database.query("SELECT 1 FROM org_roles WHERE slug='candidate'")).rowCount, 1);
    });

    await t.test('admin user creation requires create permission only and atomically establishes membership', async () => {
      await reset();
      await database.query("DELETE FROM role_permissions WHERE role_slug='administrator' AND perm_key IN('org.users.edit.permissions.acctPortal','org.users.edit.permissions.app')");
      const input = { sub: randomUUID(), username: 'created-user', displayName: 'Created user', email: '', passwordHash: 'synthetic-hash', roleSlug: 'candidate' };
      await withRoleTransaction(db => createOrgUser(db, ids.actor, input), database);
      assert.equal((await database.query('SELECT org_role_slug FROM user_org_roles WHERE user_sub=$1', [input.sub])).rows[0].org_role_slug, 'candidate');
      assert.equal((await events()).rows.length, 0);
      const rejected = { ...input, sub: randomUUID(), username: 'rejected-user', roleSlug: 'administrator' };
      await assert.rejects(withRoleTransaction(db => createOrgUser(db, ids.actor, rejected), database),
        (error: unknown) => error instanceof RoleAccessError && error.status === 422);
      assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [rejected.sub])).rowCount, 0);
      await database.query(`CREATE FUNCTION fail_new_membership() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN RAISE EXCEPTION 'injected membership failure'; END $$;
        CREATE TRIGGER fail_new_membership BEFORE INSERT ON user_org_roles FOR EACH ROW EXECUTE FUNCTION fail_new_membership()`);
      const failing = { ...input, sub: randomUUID(), username: 'failed-user' };
      try { await assert.rejects(withRoleTransaction(db => createOrgUser(db, ids.actor, failing), database), /injected membership failure/); }
      finally { await database.query('DROP TRIGGER fail_new_membership ON user_org_roles; DROP FUNCTION fail_new_membership()'); }
      assert.equal((await database.query('SELECT 1 FROM identities WHERE sub=$1', [failing.sub])).rowCount, 0);
      await database.query("UPDATE role_permissions SET effect='deny' WHERE role_slug='administrator' AND perm_key='org.users.create'");
      await assert.rejects(withRoleTransaction(db => createOrgUser(db, ids.actor, failing), database), denied('permission_denied'));
    });
  } finally {
    await database.end();await unusedDefaultPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
