import test from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import pg from 'pg';

test('user provisioning shares registration and role authority transactions', async t => {
  const source = process.env.DREAMSSO_ROLE_SYNC_TEST_DATABASE_URL;
  if (!source) throw Error('Use the isolated role-sync database fixture.');
  const url = new URL(source);
  if (url.hostname !== '127.0.0.1' || url.pathname !== '/dreamsso_role_sync_test') throw Error('Only the generated local fixture is allowed.');
  process.env.DOTENV_CONFIG_PATH = '/dev/null';process.env.DATABASE_URL = source;
  const { withRoleTransaction, publishRoleChanges, publishInitialUserAccess } = await import('../src/rbac/roleChanges.js');
  const { commitRegistration } = await import('../src/registrationStore.js');
  const { createInvitation } = await import('../src/invitations.js');
  const { createOrgUser, applyUserAccess, applyRoleAccess } = await import('../src/rbac/roleAdministration.js');
  const { pool: unusedDefaultPool } = await import('../src/db.js');
  const schema = 'user_provision_' + randomUUID().replaceAll('-', '');
  const admin = new pg.Pool({ connectionString: source, max: 2 });
  const db = new pg.Pool({ connectionString: source, max: 6, options: `-c search_path=${schema},public` });
  const actor = randomUUID();let sequence = 0;
  const clients = ['full', 'profile', 'email', 'none', 'denied'];
  const tx = <T>(work: (connection: pg.PoolClient) => Promise<T>) => withRoleTransaction(work, db);
  const events = async (subject: string, client = 'full') => (await db.query(
    "SELECT id,payload,version::text,status,attempts FROM event_outbox WHERE kind='account.roles_change' AND target_client_id=$1 AND payload->>'sub'=$2 ORDER BY sequence", [client, subject])).rows;
  const seed = async (name = 'Fixture User') => {
    const sub = randomUUID(), username = 'fixture_' + (++sequence), email = username + '@example.invalid';
    await db.query('INSERT INTO identities(sub,username,display_name,email,email_verified,avatar) VALUES($1,$2,$3,$4,true,$5)',
      [sub, username, name, email, `${sub}-0123456789abcdef.webp`]);
    await db.query("INSERT INTO user_org_roles(user_sub,org_role_slug) VALUES($1,'member')", [sub]);
    return { sub, username, email, name };
  };
  const registration = (): Parameters<typeof commitRegistration>[1] => ({ sub: randomUUID(), username: 'registered_' + (++sequence), displayName: 'Registered User',
    email: 'registered-' + randomUUID() + '@example.invalid', passwordHash: 'synthetic-test-hash', proofHash: randomBytes(32),
    requestHash: randomBytes(32), code: null, proofExpiresAt: new Date(Date.now() + 60_000), modernProof: false });
  try {
    await admin.query('CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public');
    await admin.query('CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public');
    await admin.query(`CREATE SCHEMA ${schema}`);
    await db.query((await readFile(new URL('../db/schema.sql', import.meta.url), 'utf8')).replace(/^CREATE EXTENSION[^\n]*$/gm, ''));
    await db.query("INSERT INTO org_roles(slug,label,level) VALUES('admin','Admin',10),('member','Member',100)");
    await db.query("INSERT INTO settings(key,value) VALUES('enable_registration','true'),('default_org_role','member')");
    await db.query("INSERT INTO identities(sub,username,display_name) VALUES($1,'actor','Actor')", [actor]);
    await db.query("INSERT INTO user_org_roles VALUES($1,'admin')", [actor]);
    for (const key of ['org.users.create', 'org.users.edit.permissions.app', 'org.roles.edit.permissions.app', 'org.invites.create']) {
      await db.query("INSERT INTO role_permissions VALUES('admin',$1,'grant')", [key]);
    }
    for (const client of [...clients, 'unmanaged']) {
      const scopes = client === 'profile' ? ['openid', 'profile'] : client === 'email' ? ['openid', 'email']
        : client === 'none' ? ['openid'] : ['openid', 'profile', 'email'];
      await db.query("INSERT INTO oauth_clients(client_id,name,redirect_uris,events_uri,allowed_scopes) VALUES($1,$1,'{}','https://rp.example.invalid/backchannel/events',$2)", [client, scopes]);
      if (client === 'unmanaged') continue;
      for (const [id, name, level] of [[1, 'Admin', 10], [2, 'Member', 100], [3, 'Guest', 200]]) {
        await db.query('INSERT INTO app_roles(client_id,role_id,name,level) VALUES($1,$2,$3,$4)', [client, id, name, level]);
      }
      await db.query('INSERT INTO app_role_catalogs(client_id,default_role_id) VALUES($1,$2)', [client, client === 'denied' ? null : 2]);
      await db.query("INSERT INTO org_role_app_defaults(role_slug,client_id,app_role_id) VALUES('admin',$1,1)", [client]);
    }

    await t.test('new allowed subjects get scoped creation seeds; denial and unmanaged destinations get no profile', async () => {
      const user = await seed();assert.equal(await tx(c => publishInitialUserAccess(c, user.sub)), 4);
      const profile = { preferred_username: user.username, name: user.name, picture: `${user.sub}-0123456789abcdef.webp` };
      const email = { email: user.email, email_verified: true };
      assert.deepEqual((await events(user.sub))[0].payload.profile, { ...profile, ...email });
      assert.deepEqual((await events(user.sub, 'profile'))[0].payload.profile, profile);
      assert.deepEqual((await events(user.sub, 'email'))[0].payload.profile, email);
      assert.deepEqual((await events(user.sub, 'none'))[0].payload.profile, {});
      assert.equal((await events(user.sub, 'denied')).length, 0);
      assert.equal((await db.query("SELECT 1 FROM app_role_effective WHERE client_id='denied' AND user_sub=$1", [user.sub])).rowCount, 0);
      assert.equal((await events(user.sub, 'unmanaged')).length, 0);
      assert.equal(await tx(c => publishInitialUserAccess(c, user.sub)), 0);
    });

    await t.test('unknown role, disabled, locked and deleted states never carry creation metadata', async () => {
      const user = await seed();
      await db.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'full',999)", [user.sub]);
      await tx(c => publishInitialUserAccess(c, user.sub));
      assert.equal((await events(user.sub)).length, 0);
      await db.query("DELETE FROM user_app_role_overrides WHERE user_sub=$1", [user.sub]);
      await tx(c => publishRoleChanges(c, clients, [user.sub]));
      for (const status of ['disabled', 'locked', 'deleted']) {
        await tx(async c => {
          if (status === 'deleted') await c.query('UPDATE identities SET deleted_at=now() WHERE sub=$1', [user.sub]);
          else await c.query('UPDATE identities SET status=$2 WHERE sub=$1', [user.sub, status]);
          await publishRoleChanges(c, clients, [user.sub]);
        });
        const event = (await events(user.sub)).at(-1)!;
        assert.equal(event.payload.account_status, status);assert.equal(event.payload.profile, undefined);
      }
    });

    await t.test('individual grant and role defaults publish seeds through the same ordered authority', async () => {
      const user = await seed();
      await db.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'full',NULL)", [user.sub]);
      await tx(c => publishInitialUserAccess(c, user.sub));
      assert.equal((await events(user.sub)).length, 0);
      const revisionBefore = (await db.query("SELECT authority_revision::text AS revision FROM app_role_sync_state WHERE client_id='full'")).rows[0].revision;
      await tx(c => applyUserAccess(c, actor, user.sub, { app_roles: { full: 2 } }));
      const allowed = (await events(user.sub)).at(-1)!;
      assert.ok(BigInt(allowed.version) > BigInt(revisionBefore));assert.equal(allowed.payload.profile.preferred_username, user.username);
      const inherited = await seed();await tx(c => publishInitialUserAccess(c, inherited.sub));
      await tx(c => applyRoleAccess(c, actor, 'member', { app_defaults: { profile: 3 } }));
      const changed = (await events(inherited.sub, 'profile')).at(-1)!;
      assert.equal(changed.payload.role_id, 3);assert.equal(changed.payload.profile.preferred_username, inherited.username);
      assert.equal(changed.payload.profile.email, undefined);
    });

    await t.test('registration identity, role, receipt and outbox become visible together; replay emits nothing', async () => {
      const input = registration(), connection = await db.connect();
      try {
        await connection.query('BEGIN');await commitRegistration(connection, input);
        assert.equal((await db.query('SELECT 1 FROM identities WHERE sub=$1', [input.sub])).rowCount, 0);
        assert.equal((await events(input.sub)).length, 0);
        await connection.query('COMMIT');
      } finally { await connection.query('ROLLBACK').catch(() => {});connection.release(); }
      const out = await events(input.sub);assert.equal(out.length, 1);
      assert.deepEqual(out[0].payload.profile, { preferred_username: input.username, name: input.displayName,
        picture: null, email: input.email, email_verified: true });
      const replay = await tx(c => commitRegistration(c, { ...input, sub: randomUUID() }));
      assert.equal(replay.replayed, true);assert.equal(replay.sub, input.sub);assert.deepEqual(await events(input.sub), out);
    });

    await t.test('outbox failure rolls back registration and administrator creation completely', async () => {
      const input = registration(), adminInput = { sub: randomUUID(), username: 'created_' + (++sequence),
        displayName: 'Created User', email: '', passwordHash: 'synthetic-test-hash', roleSlug: 'member' };
      const invitation = (await tx(c => createInvitation(c, actor, { request_id: randomUUID(), role_slug: 'member',
        email: input.email, delivery: 'link', validity_hours: 72, note: '' }))).invitation;
      input.code = invitation.code;input.modernProof = true;
      await db.query(`INSERT INTO invitation_mail_jobs(invitation_id,request_id,actor_key,email,proof_hash,expires_at,state)
        VALUES($1,$2,'synthetic',$3,$4,$5,'sent')`, [invitation.id, randomUUID(), input.email, input.proofHash, input.proofExpiresAt]);
      await db.query(`CREATE FUNCTION reject_provisioning() RETURNS trigger LANGUAGE plpgsql AS $$
        BEGIN IF NEW.kind='account.roles_change' THEN RAISE EXCEPTION 'injected provisioning failure'; END IF; RETURN NEW; END $$;
        CREATE TRIGGER reject_provisioning BEFORE INSERT ON event_outbox FOR EACH ROW EXECUTE FUNCTION reject_provisioning()`);
      try {
        await assert.rejects(tx(c => commitRegistration(c, input)), /injected provisioning failure/);
        await assert.rejects(tx(c => createOrgUser(c, actor, adminInput)), /injected provisioning failure/);
        for (const sub of [input.sub, adminInput.sub]) {
          assert.equal((await db.query('SELECT 1 FROM identities WHERE sub=$1', [sub])).rowCount, 0);
          assert.equal((await db.query('SELECT 1 FROM user_org_roles WHERE user_sub=$1', [sub])).rowCount, 0);
          assert.equal((await events(sub)).length, 0);
        }
        assert.equal((await db.query('SELECT 1 FROM registration_completions WHERE proof_hash=$1', [input.proofHash])).rowCount, 0);
        assert.deepEqual((await db.query('SELECT used_by,used_at FROM invitation_codes WHERE id=$1', [invitation.id])).rows[0],
          { used_by: null, used_at: null });
      } finally { await db.query('DROP TRIGGER reject_provisioning ON event_outbox; DROP FUNCTION reject_provisioning()'); }
      await tx(c => commitRegistration(c, input));
      assert.equal((await db.query('SELECT used_by FROM invitation_codes WHERE id=$1', [invitation.id])).rows[0].used_by, input.sub);
      assert.equal((await events(input.sub)).length, 1);
    });

    await t.test('invalid historical metadata preserves valid groups or empty seeds without blocking grants or revocations', async () => {
      const user = await seed('x'.repeat(101));let warnings = 0;
      const original = console.warn;console.warn = (...args: unknown[]) => { assert.deepEqual(args, ['provisioning_profile_omitted']);warnings++; };
      try {
        await tx(c => publishInitialUserAccess(c, user.sub));
        assert.deepEqual((await events(user.sub))[0].payload.profile, { email: user.email, email_verified: true });assert.equal(warnings, 2);
        assert.deepEqual((await events(user.sub, 'profile'))[0].payload.profile, {});
        assert.deepEqual((await events(user.sub, 'email'))[0].payload.profile, { email: user.email, email_verified: true });
        await tx(c => applyUserAccess(c, actor, user.sub, { app_roles: { full: null } }));
        assert.equal((await events(user.sub)).at(-1)!.payload.role_id, null);assert.equal(warnings, 2);
        const malformed = await seed('x'.repeat(101));
        await db.query('UPDATE identities SET email=$2 WHERE sub=$1', [malformed.sub, 'x'.repeat(255)]);
        assert.equal(await tx(c => publishInitialUserAccess(c, malformed.sub)), 4);
        for (const client of ['full', 'profile', 'email', 'none']) {
          assert.deepEqual((await events(malformed.sub, client))[0].payload.profile, {});
        }
        assert.equal(warnings, 6);
        await db.query("UPDATE oauth_clients SET allowed_scopes=ARRAY['profile',NULL]::text[] WHERE client_id='none'");
        try {
          const fresh = await seed();
          assert.equal(await tx(c => publishInitialUserAccess(c, fresh.sub)), 4);
          assert.deepEqual((await events(fresh.sub, 'none'))[0].payload.profile, {});
          assert.equal(warnings, 7);
        } finally { await db.query("UPDATE oauth_clients SET allowed_scopes=ARRAY['openid']::text[] WHERE client_id='none'"); }
      } finally { console.warn = original; }
    });

    await t.test('explicit allowed-only reconciliation emits fresh seeds without touching existing queued work', async () => {
      const user = await seed(), denied = await seed();
      await db.query("INSERT INTO user_app_role_overrides(user_sub,client_id,app_role_id) VALUES($1,'full',NULL)", [denied.sub]);
      await tx(c => publishRoleChanges(c, ['full'], [user.sub, denied.sub]));
      await db.query("UPDATE event_outbox SET status='dead',attempts=50,last_error_code='delivery_failed' WHERE target_client_id='full'");
      const before = (await db.query("SELECT * FROM event_outbox WHERE target_client_id='full' ORDER BY sequence")).rows;
      const old = (await events(user.sub)).at(-1)!;
      await db.query("UPDATE identities SET display_name='Current User' WHERE sub=$1", [user.sub]);
      await tx(c => publishRoleChanges(c, ['full'], [user.sub, denied.sub], { force: true, allowedOnly: true }));
      const fresh = (await events(user.sub)).at(-1)!;
      assert.ok(BigInt(fresh.version) > BigInt(old.version));assert.equal(fresh.payload.profile.name, 'Current User');
      assert.equal(fresh.status, 'pending');assert.equal((await events(denied.sub)).length, 1);
      const preserved = (await db.query('SELECT * FROM event_outbox WHERE id=ANY($1::uuid[]) ORDER BY sequence', [before.map(row => row.id)])).rows;
      assert.deepEqual(preserved, before);
    });
  } finally {
    await db.end();await unusedDefaultPool.end();await admin.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`);await admin.end();
  }
});
