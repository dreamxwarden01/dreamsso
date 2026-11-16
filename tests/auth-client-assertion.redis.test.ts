import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { Redis } from 'ioredis';
import { createClientAssertionVerifier, CLIENT_ASSERTION_TYPE } from '../src/oidc/clientAssertionValidation.js';

const fixtureUrl = process.env.DREAMSSO_AUTH_TEST_REDIS_URL;
test('Redis atomically claims each client assertion across authentication endpoints', { skip: !fixtureUrl }, async () => {
  const address = new URL(fixtureUrl!);
  if (address.hostname !== '127.0.0.1' || address.pathname !== '/15') throw Error('Only the generated local auth Redis fixture is allowed.');
  const redis = new Redis(fixtureUrl!, { lazyConnect: true, maxRetriesPerRequest: 1 });
  const prefix = 'assertion-test:' + randomUUID() + ':', stored = new Set<string>();
  const issuer = 'https://issuer.example.invalid', client = 'fixture-rp', now = Math.floor(Date.now() / 1000);
  let clock = now * 1000, delayAfterClaim = 0;
  const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-assertion-key';
  const verify = createClientAssertionVerifier({ issuer: () => issuer, now: () => clock,
    loadClient: async id => id === client ? { client_id: client, disabled_at: null } : null,
    keySet: () => createLocalJWKSet({ keys: [jwk] }),
    claimNonce: async (key, ttl) => { stored.add(prefix + key);const result = await redis.set(prefix + key, '1', 'EX', ttl, 'NX');
      if (result === 'OK') clock += delayAfterClaim;return result === 'OK'; },
  });
  const body = async (jti: string, path: string) => ({ client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await new SignJWT({ method: 'POST', path }).setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuer(client).setSubject(client).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60).setJti(jti).sign(keys.privateKey) });
  try {
    await redis.connect();
    const proof = await body(randomUUID(), '/token');
    const values = await Promise.all(Array.from({ length: 32 }, () => verify(proof, { method: 'POST', path: '/token' })));
    assert.equal(values.filter(value => value === client).length, 1);
    const sharedNonce = randomUUID();
    assert.equal(await verify(await body(sharedNonce, '/token'), { method: 'POST', path: '/token' }), client);
    assert.equal(await verify(await body(sharedNonce, '/internal/avatar'), { method: 'POST', path: '/internal/avatar' }), null);
    delayAfterClaim = 70_000;
    assert.equal(await verify(await body(randomUUID(), '/token'), { method: 'POST', path: '/token' }), null);
    assert.equal(stored.size, 3, 'the late-expired proof retains its consumed real Redis nonce');
    for (const key of stored) { const ttl = await redis.ttl(key);assert.ok(ttl > 0 && ttl <= 70); }
  } finally {
    if (stored.size) await redis.del(...stored).catch(() => {});
    await redis.quit().catch(() => redis.disconnect());
  }
});
