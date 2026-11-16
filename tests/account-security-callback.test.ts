import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';

// Complete callback source, synthetic verified claims and session store. No
// runtime config, credentials, Redis, DB, network or listeners are imported.
function callbackFixture(claims: Record<string, unknown>, options: { ttl?: number; advanceUserinfoMs?: number } = {}) {
  let clock = 1_000_000_250;
  const routes = new Map<string, Function>();
  const created: { data: any; ttl: number; sid: string }[] = [];
  const dependencies: Record<string, unknown> = {
    express: { Router: () => ({ get: (path: string, handler: Function) => routes.set(path, handler) }) },
    '../config.js': { config: { sessionTtl: options.ttl ?? 86400 } },
    '../oidc.js': {
      exchangeCode: async () => ({ id_token: 'synthetic-id', access_token: 'synthetic-access', expires_in: 900 }),
      verifyIdToken: async () => claims,
      userinfo: async () => { clock += options.advanceUserinfoMs ?? 0; return { name: 'Fresh profile' }; },
    },
    '../session.js': { createSession: async (data: any, ttl: number) => {
      assert.ok(Number.isSafeInteger(ttl) && ttl > 0, 'actual createSession contract');
      const sid = 'new-bff-' + created.length; created.push({ data, ttl, sid }); return sid;
    } },
  };
  const source = fs.readFileSync(new URL('../account/server/src/routes/auth.ts', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  vm.runInNewContext(output, { exports: {}, require: (id: string) => { assert.ok(id in dependencies, id); return dependencies[id]; },
    Date: { now: () => clock }, console: { error: () => {} } });
  const invoke = async () => {
    const cookies: { name: string; value: string; options: any }[] = [];
    const res = { destination: '', cleared: [] as string[], cookie: (name: string, value: string, opts: any) => { cookies.push({ name, value, options: opts }); },
      clearCookie(name: string) { this.cleared.push(name); }, redirect(path: string) { this.destination = path; } };
    await routes.get('/auth/callback')!({ secure: true, query: { code: 'synthetic-code', state: 'fixture-state' },
      cookies: { acct_flow: JSON.stringify({ verifier: 'fixture-verifier', state: 'fixture-state', nonce: 'fixture-nonce', returnTo: '/security?tab=mfa' }) } }, res);
    return { ...res, cookies };
  };
  return { invoke, created, now: () => clock / 1000 };
}

test('Account callback accepts fractional transient and persistent NumericDate without extending the SSO expiry', async () => {
  for (const persistent of [false, true]) {
    const fixture = callbackFixture({ sub: 'fixture', sid: 'master', sess_exp: 1_000_120.875, sess_persistent: persistent });
    const res = await fixture.invoke();
    assert.equal(res.destination, '/security?tab=mfa'); assert.equal(fixture.created[0].ttl, 120);
    assert.ok(fixture.now() + fixture.created[0].ttl <= 1_000_120.875);
    assert.equal(fixture.created[0].data.ssoSid, 'master'); assert.equal(fixture.created[0].data.claims.name, 'Fresh profile');
    const cookie = res.cookies.find(c => c.name === 'acct_sid')!;
    assert.equal(cookie.options.maxAge, persistent ? 120000 : undefined);
    assert.equal(cookie.options.httpOnly, true); assert.equal(cookie.options.secure, true); assert.equal(cookie.options.sameSite, 'lax');
    assert.deepEqual(res.cleared, ['acct_flow']);
  }
});

test('Account callback caps normal integer expiries and preserves explicit legacy missing-claim fallback', async () => {
  for (const [claims, expected] of [[{ sess_exp: 1_001_000 }, 60], [{}, 60]] as const) {
    const fixture = callbackFixture({ sub: 'fixture', sid: 'master', sess_persistent: true, ...claims }, { ttl: 60 });
    const res = await fixture.invoke(); assert.equal(res.destination, '/security?tab=mfa');
    assert.equal(fixture.created[0].ttl, expected); assert.equal(res.cookies[0].options.maxAge, expected * 1000);
  }
});

test('Account callback near expiry gets only remaining whole seconds, never the former extra sixty seconds', async () => {
  const fixture = callbackFixture({ sub: 'fixture', sid: 'master', sess_exp: 1_000_002, sess_persistent: true });
  const res = await fixture.invoke(); assert.equal(res.destination, '/security?tab=mfa');
  assert.equal(fixture.created[0].ttl, 1); assert.equal(res.cookies[0].options.maxAge, 1000);
  assert.ok(fixture.now() + fixture.created[0].ttl <= 1_000_002);
});

test('Account callback rejects expired, subsecond and malformed supplied expiries without opening a session', async () => {
  for (const expiry of [1_000_000, 1_000_000.25, 1_000_000.875, 0, -1, Infinity, -Infinity, NaN, '1001000', null]) {
    const fixture = callbackFixture({ sub: 'fixture', sid: 'master', sess_exp: expiry, sess_persistent: true });
    const res = await fixture.invoke();
    assert.match(res.destination, /^\/auth\/error\?code=(session_expired|invalid_session_expiry)$/);
    assert.equal(fixture.created.length, 0); assert.equal(res.cookies.length, 0);
  }
  const delayed = callbackFixture({ sub: 'fixture', sid: 'master', sess_exp: 1_000_002 }, { advanceUserinfoMs: 2500 });
  assert.equal((await delayed.invoke()).destination, '/auth/error?code=session_expired'); assert.equal(delayed.created.length, 0);
});

test('same-SID successful callbacks still create new BFF sessions through atomic store rotation', async () => {
  const fixture = callbackFixture({ sub: 'fixture', sid: 'same-master', sess_exp: 1_000_120 });
  const first = await fixture.invoke(), second = await fixture.invoke();
  assert.equal(first.destination, '/security?tab=mfa'); assert.equal(second.destination, '/security?tab=mfa');
  assert.equal(fixture.created.length, 2);
  assert.equal(fixture.created[0].data.ssoSid, 'same-master'); assert.equal(fixture.created[1].data.ssoSid, 'same-master');
  assert.notEqual(first.cookies[0].value, second.cookies[0].value);
});
