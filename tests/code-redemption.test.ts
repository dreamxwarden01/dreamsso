import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import type pg from 'pg';
import { createCodeStore, type AuthCode } from '../src/oidc/codeStore.js';
import { redeemAuthorizationCode, CodeRedemptionError, type CodeRedemptionDependencies } from '../src/oidc/codeRedemption.js';

const sub = '11111111-1111-4111-8111-111111111111', sid = '22222222-2222-4222-8222-222222222222';
const verifier = 'synthetic-pkce-verifier', redirectUri = 'https://rp.example.invalid/callback';
const payload: AuthCode = { clientId: 'ordinary-rp', redirectUri, userSub: sub, sid,
  codeChallenge: createHash('sha256').update(verifier).digest('base64url'), codeChallengeMethod: 'S256',
  scope: 'openid profile email', amr: ['pwd'], authTime: 1_000_000, nonce: 'synthetic-nonce' };
interface Options { identityActive?: boolean; session?: 'missing' | 'foreign' | 'idle' | 'absolute';
  allowedScopes?: string[]; accessAllowed?: boolean; authority?: boolean; managed?: boolean; signingFails?: boolean; clientEnabled?: boolean }
async function fixture(options: Options = {}) {
  const values = new Map<string, string>();let gets = 0, connects = 0, releases = 0, prepared = false, locked = false;
  const order: string[] = [], minted: unknown[] = [];
  const store = createCodeStore({
    save: async (key, value, ttl) => { assert.equal(ttl, 60);values.set(key, value); },
    getdel: async key => { gets++;const value = values.get(key) ?? null;values.delete(key);return value; },
  });
  const code = await store.createCode(payload);
  const db = {
    async query(sql: string, parameters?: unknown[]) {
      order.push(sql);
      if (sql === 'BEGIN' || sql.startsWith('SET LOCAL')) return { rows: [] };
      if (sql === 'COMMIT' || sql === 'ROLLBACK') { locked = false;return { rows: [] }; }
      if (sql.startsWith('SELECT sub FROM identities')) {
        assert.ok(sql.includes("status='active' AND deleted_at IS NULL FOR SHARE"));assert.deepEqual(parameters, [sub]);
        return { rows: options.identityActive === false ? [] : [{ sub }] };
      }
      if (sql.includes('FROM sessions WHERE sid=$1 AND user_sub=$2 FOR UPDATE')) {
        assert.deepEqual(parameters, [sid, sub, 24, 720, 24]);locked = true;
        return { rows: ['missing', 'foreign'].includes(options.session ?? '') ? [] : [{ persistent: true, created_at: '1000000',
          idle_valid: options.session !== 'idle', absolute_valid: options.session !== 'absolute' }] };
      }
      if (sql === 'SELECT allowed_scopes FROM oauth_clients WHERE client_id=$1 AND disabled_at IS NULL') {
        assert.deepEqual(parameters, ['ordinary-rp']);return { rows: options.clientEnabled === false ? [] : [{ allowed_scopes: options.allowedScopes ?? ['openid', 'profile', 'email'] }] };
      }
      if (sql.startsWith('SELECT username, display_name')) return { rows: [{ username: 'fixture', display_name: 'Fixture', email: 'fixture@example.invalid', email_verified: true, avatar: null }] };
      if (sql.startsWith('UPDATE sessions SET clients=')) { assert.equal(locked, true);assert.deepEqual(parameters, [sid, 'ordinary-rp']);return { rows: [], rowCount: 1 }; }
      throw Error('Unexpected synthetic SQL');
    },
    release() { releases++; },
  } as unknown as pg.PoolClient;
  const deps: CodeRedemptionDependencies = {
    database: { connect: async () => { assert.equal(prepared, true);connects++;return db; } } as Pick<pg.Pool, 'connect'>,
    consumeCode: store.consumeCode,
    prepare: async () => { prepared = true;return { windows: { idleHours: 24, maxHours: 720, transientMaxHours: 24 }, siteName: 'Fixture',
      mintIdToken: async claims => { assert.equal(locked, true);minted.push(claims);if (options.signingFails) throw Error('synthetic signing unavailable');return 'synthetic-id'; },
      mintAccessToken: async claims => { assert.equal(locked, true);minted.push(claims);return 'synthetic-access'; } }; },
    readAccessStateSnapshot: async connection => {
      assert.equal(connection, db);assert.equal(locked, true);return { states: [{ sub, account: { status: 'active' },
        rp: { catalog_synced: options.managed ?? false, role_id: 7, role_source: 'catalog', access: 'allowed' }, allowed: options.accessAllowed !== false }],
        authority: options.authority === false ? null : { epoch: '33333333-3333-4333-8333-333333333333', revision: '42' } };
    },
  };
  const input = { clientId: 'ordinary-rp', code, redirectUri, verifier };
  return { input, deps, order, minted, stats: () => ({ gets, connects, releases }) };
}
const denied = (status: number, code: string) => (error: unknown) => error instanceof CodeRedemptionError && error.status === status && error.code === code;

test('atomic code storage admits exactly one of many concurrent redemption requests', async () => {
  const f = await fixture();
  const results = await Promise.allSettled(Array.from({ length: 32 }, () => redeemAuthorizationCode(f.input, f.deps)));
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  for (const result of results) if (result.status === 'rejected') assert.ok(denied(400, 'invalid_grant')(result.reason));
  assert.equal(f.minted.length, 2);assert.deepEqual(f.stats(), { gets: 32, connects: 1, releases: 1 });
});

test('ordinary RP login keeps profile, session durability, role-authority and original SID claims', async () => {
  const f = await fixture({ managed: true });const result = await redeemAuthorizationCode(f.input, f.deps);
  assert.deepEqual(result, { access_token: 'synthetic-access', token_type: 'Bearer', expires_in: 900, id_token: 'synthetic-id', scope: 'openid profile email' });
  const id = f.minted[0] as { sid: string; clientId: string; extra: Record<string, unknown> };
  assert.equal(id.sid, sid);assert.equal(id.clientId, 'ordinary-rp');assert.equal(id.extra.name, 'Fixture');
  assert.equal(id.extra.sess_persistent, true);assert.equal(id.extra.sess_exp, 1_000_000 + 720 * 3600);
  assert.equal(id.extra.app_role, 7);assert.equal(id.extra.app_role_revision, '42');
  const identityLock = f.order.findIndex(sql => sql.includes('FOR SHARE'));
  const sessionLock = f.order.findIndex(sql => sql.includes('FOR UPDATE'));
  assert.ok(identityLock >= 0 && sessionLock > identityLock);assert.equal(f.order.at(-1), 'COMMIT');
});

test('deleted/foreign/expired original session cannot issue tokens; active identity is required', async () => {
  for (const session of ['missing', 'foreign', 'idle', 'absolute'] as const) {
    const f = await fixture({ session });await assert.rejects(redeemAuthorizationCode(f.input, f.deps), denied(400, 'invalid_grant'));
    assert.equal(f.minted.length, 0);assert.equal(f.order.at(-1), 'ROLLBACK');assert.equal(f.stats().releases, 1);
  }
  const f = await fixture({ identityActive: false });await assert.rejects(redeemAuthorizationCode(f.input, f.deps), denied(403, 'access_denied'));
  assert.equal(f.minted.length, 0);assert.ok(!f.order.some(sql => sql.includes('FOR UPDATE')));
});

test('scope grant narrowed after authorization, disabled client and current app denial remain enforced', async () => {
  for (const [options, status, code] of [
    [{ allowedScopes: ['openid'] }, 400, 'invalid_scope'], [{ clientEnabled: false }, 401, 'invalid_client'],
    [{ accessAllowed: false }, 403, 'access_denied'], [{ managed: true, authority: false }, 503, 'temporarily_unavailable'],
  ] as const) {
    const f = await fixture(options as Options);await assert.rejects(redeemAuthorizationCode(f.input, f.deps), denied(status, code));
    assert.equal(f.minted.length, 0);assert.equal(f.order.at(-1), 'ROLLBACK');
  }
});

test('wrong client, redirect and verifier never acquire transaction authority', async () => {
  for (const patch of [{ clientId: 'other-rp' }, { redirectUri: 'https://other.example.invalid/callback' }, { verifier: 'wrong' }]) {
    const f = await fixture();await assert.rejects(redeemAuthorizationCode({ ...f.input, ...patch }, f.deps), denied(400, 'invalid_grant'));
    assert.equal(f.stats().connects, 0);assert.equal(f.minted.length, 0);
  }
});

test('signing failure rolls back touched-client update and releases the session lock', async () => {
  const f = await fixture({ signingFails: true });await assert.rejects(redeemAuthorizationCode(f.input, f.deps), /synthetic signing unavailable/);
  assert.ok(f.order.some(sql => sql.startsWith('UPDATE sessions SET clients=')));assert.equal(f.order.at(-1), 'ROLLBACK');assert.equal(f.stats().releases, 1);
});
