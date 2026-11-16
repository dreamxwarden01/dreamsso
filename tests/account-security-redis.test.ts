import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import { Redis } from 'ioredis';

// This file is run only by the disposable-database fixture runner. Never import
// Account's config/redis modules: they load real environment and connect eagerly.
const fixtureUrl = process.env.TEST_REDIS_URL;
test('Account session Lua preserves expiry and index integrity across late writes, rotation and revocation', { skip: !fixtureUrl }, async t => {
  const url = new URL(fixtureUrl!);
  assert.ok(['redis:', 'rediss:'].includes(url.protocol));
  assert.ok(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname), 'fixture Redis must be loopback');
  assert.equal(url.pathname, '/15', 'require the explicitly isolated fixture database');
  const redis = new Redis(fixtureUrl!, { lazyConnect: true, maxRetriesPerRequest: 0, retryStrategy: () => null });
  const namespace = `account-security:${crypto.randomUUID()}:`;
  const owned = new Set<string>();
  const key = (value: string) => { const result = namespace + value; owned.add(result); return result; };
  const injectedRedis = {
    get: (name: string) => redis.get(key(name)),
    set: (name: string, ...args: any[]) => (redis.set as any)(key(name), ...args),
    eval: (script: string, count: number, ...args: (string | number)[]) => redis.eval(script, count,
      ...args.map((arg, i) => i < count ? key(String(arg)) :
        (arg === 'acct:sess:' || arg === 'acct:ssosid:') ? namespace + arg : arg)),
  };
  const source = fs.readFileSync(new URL('../account/server/src/session.ts', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { esModuleInterop: true, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const exported: any = {};
  vm.runInNewContext(output, { exports: exported, require: (id: string) => {
    if (id === 'node:crypto') return crypto;
    if (id === './redis.js') return { redis: injectedRedis };
    if (id === './config.js') return { config: { sessionTtl: 60 } };
    throw Error('unexpected dependency: ' + id);
  } });
  const { createSession, updateSession, getSession, destroySession, revokeBySsoSid } = exported;
  const data = (ssoSid: string | undefined = 'fixture-master') => ({ sub: 'fixture-sub', ssoSid, claims: {}, accessToken: 'synthetic', idToken: 'synthetic', accessExpiresAt: 900, amr: [], createdAt: 1 });
  const sessionKey = (sid: string) => key('acct:sess:' + sid);
  const indexKey = (sid: string) => key('acct:ssosid:' + sid);
  try {
    await redis.connect();
    await t.test('update keeps the exact absolute millisecond expiry and rejects identity/index changes', async () => {
      const sid = await createSession(data(), 60);
      assert.deepEqual(await redis.smembers(indexKey('fixture-master')), [sid]);
      await redis.pexpire(sessionKey(sid), 12050);
      const expires = await redis.pexpiretime(sessionKey(sid));
      assert.equal(await updateSession(sid, { ...data(), claims: { name: 'updated' } }), true);
      assert.equal(await redis.pexpiretime(sessionKey(sid)), expires);
      assert.equal((await getSession(sid)).claims.name, 'updated');
      for (const changed of [{ ...data(), sub: 'another-user' }, data('another-master'), { ...data(), ssoSid: undefined }]) {
        assert.equal(await updateSession(sid, changed), false);
        assert.equal(await redis.pexpiretime(sessionKey(sid)), expires);
      }
      assert.deepEqual(await redis.smembers(indexKey('fixture-master')), [sid]);
    });
    await t.test('revocation before a retained record write cannot recreate it; duplicate revoke stays empty', async () => {
      const sid = await createSession(data(), 60), retained = await getSession(sid);
      assert.equal(await revokeBySsoSid('fixture-master'), 1);
      assert.equal(await updateSession(sid, retained), false);
      assert.equal(await getSession(sid), null); assert.equal(await redis.exists(indexKey('fixture-master')), 0);
      assert.equal(await revokeBySsoSid('fixture-master'), 0);
      assert.equal(await updateSession(sid, retained), false);
    });
    await t.test('local destruction removes the index member and fences late writes', async () => {
      const sid = await createSession(data(), 60), retained = await getSession(sid);
      await destroySession(sid);
      assert.equal(await updateSession(sid, retained), false);
      assert.deepEqual(await redis.smembers(indexKey('fixture-master')), []);
      await destroySession(undefined); await destroySession(sid);
    });
    await t.test('expiry, absent, non-expiring and corrupt records are never given a new lifetime', async () => {
      const sid = await createSession(data(), 60);
      await redis.pexpireat(sessionKey(sid), Date.now() - 1);
      assert.equal(await updateSession(sid, data()), false); assert.equal(await redis.exists(sessionKey(sid)), 0);
      assert.equal(await updateSession('never-created', data()), false);
      await redis.set(sessionKey(sid), JSON.stringify(data()));
      assert.equal(await updateSession(sid, data()), false); assert.equal(await redis.pttl(sessionKey(sid)), -1);
      for (const value of ['invalid-json', 'null', '"scalar"']) {
        await redis.set(sessionKey(sid), value, 'EX', 60);
        assert.equal(await updateSession(sid, data()), false);
        assert.equal(await redis.get(sessionKey(sid)), value);
        await destroySession(sid);
        assert.equal(await redis.exists(sessionKey(sid)), 0, 'even corrupt local state can be destroyed');
      }
    });
    await t.test('same-SID callback rotation publishes one complete indexed session; old retained state cannot recreate a key', async () => {
      const first = await createSession(data('rotation'), 60), retained = await getSession(first);
      const second = await createSession(data('rotation'), 60);
      assert.notEqual(second, first); assert.equal(await getSession(first), null);
      assert.equal(await updateSession(first, retained), false);
      assert.deepEqual(await redis.smembers(indexKey('rotation')), [second]);
      assert.ok(await getSession(second)); assert.equal(await revokeBySsoSid('rotation'), 1);
      assert.equal(await getSession(second), null);
    });
    await t.test('concurrent create/revoke/update commands leave no unindexed surviving session', async () => {
      for (let i = 0; i < 10; i++) {
        const master = 'race-' + i, first = await createSession(data(master), 60);
        const retained = await getSession(first);
        const [second] = await Promise.all([createSession(data(master), 60), revokeBySsoSid(master), updateSession(first, retained)]);
        const members = await redis.smembers(indexKey(master));
        for (const sid of [first, second]) assert.equal(Boolean(await getSession(sid)), members.includes(sid));
        await revokeBySsoSid(master);
        for (const sid of [first, second]) assert.equal(await getSession(sid), null);
      }
    });
    await t.test('sessions without SSO SID remain supported, but cannot change into an indexed identity', async () => {
      const unbound = { ...data(), ssoSid: undefined }, sid = await createSession(unbound, 60);
      assert.equal(await updateSession(sid, unbound), true); assert.equal(await updateSession(sid, data()), false);
      await destroySession(sid); assert.equal(await getSession(sid), null);
      await assert.rejects(createSession(data(), 0), /invalid_session_ttl/);
    });
  } finally {
    if (redis.status === 'ready' && owned.size) await redis.del(...owned);
    redis.disconnect();
  }
});
