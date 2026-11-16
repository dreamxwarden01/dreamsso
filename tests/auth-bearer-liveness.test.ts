import assert from 'node:assert/strict';
import test from 'node:test';
import type { Request, Response } from 'express';
import type pg from 'pg';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createAccountResourceAuth, type AuthedRequest } from '../src/accountResourceAuth.js';
import { createUserinfoHandler } from '../src/oidc/userinfo.js';
import { readAccessTokenState, type AccessTokenState } from '../src/oidc/accessTokenState.js';
import { resolveSessionWindows, readSessionWindows } from '../src/oidc/sessionWindows.js';

const issuer = 'https://issuer.example.invalid', sub = '11111111-1111-4111-8111-111111111111', sid = '22222222-2222-4222-8222-222222222222';
const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-state-key';
const jwks = { keys: [jwk] };
async function signed(changes: Record<string, unknown> = {}, omitted: string[] = []) {
  const now = Math.floor(Date.now() / 1000);
  const claims: Record<string, unknown> = { iss: issuer, aud: issuer, sub, client_id: 'account', sid,
    scope: 'openid profile email', iat: now, exp: now + 900, ...changes };
  for (const name of omitted) delete claims[name];
  return new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt', kid: jwk.kid }).sign(keys.privateKey);
}
function response() { return { statusCode: 200, body: undefined as unknown,
  status(n: number) { this.statusCode = n;return this; }, set() { return this; }, setHeader() {},
  json(body: unknown) { this.body = body;return this; } }; }
function fixture(state: AccessTokenState | Error = 'active') {
  let reads = 0;
  const auth = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => 'account', jwks: async () => jwks,
    readState: async identity => { reads++;assert.equal(identity.sub, sub);assert.equal(identity.sid, sid);
      if (state instanceof Error) throw state;return state; } });
  const userinfo = createUserinfoHandler({ verifyAccessToken: auth.verifyAccessToken, profile: async subject => {
    assert.equal(subject, sub);return { sub, username: 'fixture', display_name: 'Fixture', email: 'fixture@example.invalid', email_verified: true, avatar: null };
  } });
  async function account(token?: string) { const res = response();let next = false;
    await auth.requireScope('profile')({ headers: token ? { authorization: 'Bearer ' + token } : {} } as AuthedRequest,
      res as unknown as Response, () => { next = true; });return { res, next }; }
  async function profile(token?: string) { const res = response();await userinfo({ headers: token ? { authorization: 'Bearer ' + token } : {} } as Request, res as unknown as Response);return res; }
  return { auth, account, profile, reads: () => reads };
}

test('active original SID preserves Account and ordinary RP userinfo while retaining resource client pin', async () => {
  const f = fixture();assert.equal((await f.account(await signed())).next, true);
  const rp = await signed({ client_id: 'ordinary-rp' });const denied = await f.account(rp);
  assert.equal(denied.next, false);assert.equal(denied.res.statusCode, 403);
  assert.equal((await f.profile(rp)).statusCode, 200);
});

test('SID revocation/expiry is 401 and account or RP disable is 403 on both bearer surfaces', async () => {
  for (const [state, expected] of [['session_gone', 401], ['account_inactive', 403], ['client_disabled', 403]] as const) {
    const f = fixture(state), token = await signed();
    const account = await f.account(token);assert.equal(account.next, false);assert.equal(account.res.statusCode, expected);
    assert.equal((await f.profile(token)).statusCode, expected);
  }
});

test('legacy no-SID, malformed, expired and excessive-lifetime tokens fail before state storage reads', async () => {
  const f = fixture();const now = Math.floor(Date.now() / 1000);
  for (const token of [undefined, 'malformed', await signed({}, ['sid']), await signed({}, ['client_id']), await signed({}, ['exp']),
    await signed({ sid: 'not-a-uuid' }), await signed({ exp: now - 1, iat: now - 900 }), await signed({ exp: now + 901 }),
    await signed({ aud: 'https://other.example.invalid' })]) {
    assert.equal((await f.account(token)).res.statusCode, 401);assert.equal((await f.profile(token)).statusCode, 401);
  }
  assert.equal(f.reads(), 0);
});

test('token-state storage outage is sanitized 503, not authentication failure or admission', async () => {
  const f = fixture(Error('synthetic private storage detail')), token = await signed();
  assert.equal((await f.account(token)).res.statusCode, 503);
  const userinfo = await f.profile(token);assert.equal(userinfo.statusCode, 503);
  assert.ok(!JSON.stringify(userinfo.body).includes('private storage'));
});

test('transaction verification uses its connection for both key and liveness reads', async () => {
  const db = {} as pg.PoolClient;let keyReads = 0, stateReads = 0;
  const auth = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => 'account',
    jwks: async connection => { assert.equal(connection, db);keyReads++;return jwks; },
    readState: async (identity, connection) => { assert.equal(connection, db);assert.equal(identity.sid, sid);stateReads++;return 'active'; } });
  const result = await auth.verifyAccessToken({ headers: { authorization: 'Bearer ' + await signed() } } as Request, db);
  assert.equal(result?.sid, sid);assert.equal(keyReads, 1);assert.equal(stateReads, 1);
});

test('single-statement state reader maps identity/client/session decisions and rejects malformed storage shape', async () => {
  for (const [flags, expected] of [
    [[true, true, true], 'active'], [[false, true, true], 'account_inactive'], [[true, false, true], 'client_disabled'], [[true, true, false], 'session_gone'],
  ] as const) {
    const db = { query: async (sql: string, args: unknown[]) => {
      assert.ok(sql.includes('s.sid=$3::uuid AND s.user_sub=$1::uuid'));
      assert.deepEqual(args, [sub, 'account', sid, 72, 168, 24]);
      return { rows: [{ account_active: flags[0], client_enabled: flags[1], session_active: flags[2] }] };
    } } as unknown as pg.PoolClient;
    assert.equal(await readAccessTokenState(db, { sub, clientId: 'account', sid }, { idleHours: 72, maxHours: 168, transientMaxHours: 24 }), expected);
  }
  await assert.rejects(readAccessTokenState({ query: async () => ({ rows: [{}] }) } as unknown as pg.PoolClient,
    { sub, clientId: 'account', sid }, { idleHours: 72, maxHours: 168, transientMaxHours: 24 }), /unavailable/);
});


test('shared session windows preserve defaults, limits and transaction-owned settings reads', async () => {
  assert.deepEqual(resolveSessionWindows([]), { idleHours: 72, maxHours: 168, transientMaxHours: 24 });
  assert.deepEqual(resolveSessionWindows(['200', '100', '150']), { idleHours: 100, maxHours: 100, transientMaxHours: 100 });
  assert.deepEqual(resolveSessionWindows(['0', '99999', 'bad']), { idleHours: 72, maxHours: 168, transientMaxHours: 24 });
  assert.deepEqual(resolveSessionWindows(['1', '1', '24']), { idleHours: 1, maxHours: 1, transientMaxHours: 1 });
  let reads = 0;
  const db = { query: async (sql: string, args: unknown[]) => {
    reads++;assert.equal(sql, 'SELECT key,value FROM settings WHERE key=ANY($1::text[])');
    assert.deepEqual(args, [['session_idle_hours', 'session_max_hours', 'session_transient_max_hours']]);
    return { rows: [{ key: 'session_idle_hours', value: '2' }, { key: 'session_max_hours', value: '8' }] };
  } } as unknown as pg.PoolClient;
  assert.deepEqual(await readSessionWindows(db), { idleHours: 2, maxHours: 8, transientMaxHours: 8 });assert.equal(reads, 1);
});
