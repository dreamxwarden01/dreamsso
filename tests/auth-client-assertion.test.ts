import assert from 'node:assert/strict';
import test from 'node:test';
import { generateKeyPair, exportJWK, SignJWT, createLocalJWKSet, errors } from 'jose';
import { createClientAssertionVerifier, ClientAssertionUnavailable, CLIENT_ASSERTION_TYPE } from '../src/oidc/clientAssertionValidation.js';

const issuer = 'https://issuer.example.invalid', clientId = 'fixture-rp', now = 2_000_000_000;
const keys = await generateKeyPair('EdDSA'), publicKey = await exportJWK(keys.publicKey);publicKey.kid = 'fixture';
const keySet = createLocalJWKSet({ keys: [publicKey] });
let sequence = 0;
async function assertion(changes: Record<string, unknown> = {}, omit: string[] = []) {
  const claims: Record<string, unknown> = { iss: clientId, sub: clientId, aud: issuer, iat: now, exp: now + 60, jti: 'fixture-' + ++sequence, method: 'POST', path: '/token', ...changes };
  for (const key of omit) delete claims[key];
  return { client_assertion_type: CLIENT_ASSERTION_TYPE,
    client_assertion: await new SignJWT(claims).setProtectedHeader({ alg: 'EdDSA', kid: publicKey.kid }).sign(keys.privateKey) };
}
const operation = { method: 'POST', path: '/token' };
function fixture(options: { unavailable?: boolean; disabled?: boolean; unknown?: boolean } = {}) {
  const claimed = new Set<string>(), ttlValues: number[] = [];
  const verifyOperation = createClientAssertionVerifier({ issuer: () => issuer, now: () => now * 1000,
    loadClient: async id => options.unknown ? null : { client_id: id, disabled_at: options.disabled ? 'disabled' : null },
    keySet: () => keySet,
    claimNonce: async (key, ttl) => { if (options.unavailable) throw Error('synthetic outage');ttlValues.push(ttl);if (claimed.has(key)) return false;claimed.add(key);return true; },
  });
  const verify = (body: Record<string, unknown>, context = operation, expectedClientId?: string) => verifyOperation(body, context, expectedClientId);
  return { verify, claimed, ttlValues };
}

test('current first-party issuer and token audiences, 60-second fields remain compatible', async () => {
  const f = fixture();
  assert.equal(await f.verify(await assertion()), clientId);
  assert.equal(await f.verify(await assertion({ aud: issuer + '/token' })), clientId);
  assert.deepEqual(f.ttlValues, [70, 70]);
});

test('every assertion requires pinned identity, bounded integral timestamps and nonce', async () => {
  for (const omit of ['iss', 'sub', 'aud', 'iat', 'exp', 'jti']) assert.equal(await fixture().verify(await assertion({}, [omit])), null);
  for (const fields of [{ sub: 'other' }, { aud: 'https://other.example.invalid' }, { aud: [issuer, issuer + '/token'] },
    { exp: now + 121 }, { iat: now - 121, exp: now + 1 }, { iat: now + 11, exp: now + 60 },
    { iat: now + 0.5 }, { exp: now + 60.5 }, { exp: now }, { jti: '' }, { jti: 'x'.repeat(257) }]) {
    assert.equal(await fixture().verify(await assertion(fields)), null);
  }
  assert.equal(await fixture({ disabled: true }).verify(await assertion()), null);
  assert.equal(await fixture({ unknown: true }).verify(await assertion()), null);
  assert.equal(await fixture().verify(await assertion(), operation, 'account'), null);
});

test('one client nonce is single-use across token and internal authentication operations', async () => {
  const f = fixture(), proof = await assertion();
  const outcomes = await Promise.all(Array.from({ length: 16 }, () => f.verify(proof,
    { method: 'POST', path: '/token' })));
  assert.equal(outcomes.filter(value => value === clientId).length, 1);
  assert.equal(f.claimed.size, 1);
  const boundA = await assertion({ jti: 'same-client-nonce', path: '/token' });
  const boundB = await assertion({ jti: 'same-client-nonce', path: '/internal/avatar' });
  assert.equal(await f.verify(boundA), clientId);
  assert.equal(await f.verify(boundB, { method: 'POST', path: '/internal/avatar' }), null);
  assert.equal(await f.verify(await assertion({ iss: 'other-rp', sub: 'other-rp', jti: 'shared' })), 'other-rp');
  assert.equal(await f.verify(await assertion({ jti: 'shared' })), clientId);
});

test('signed operation is required and enforced without a legacy fallback', async () => {
  const proof = await assertion({ method: 'POST', path: '/internal/avatar' });
  const f = fixture();
  assert.equal(await f.verify(proof, { method: 'POST', path: '/token' }), null);
  assert.equal(await f.verify(proof), null);
  assert.equal(await f.verify(await assertion({}, ['method', 'path'])), null);
  assert.equal(await f.verify(proof, { method: 'POST', path: '/internal/avatar' }), clientId);
  assert.equal(await fixture().verify(await assertion({ method: 'POST' }, ['path']), { method: 'POST', path: '/token' }), null);
});

test('replay storage and key storage unavailability fail closed rather than authenticating', async () => {
  await assert.rejects(fixture({ unavailable: true }).verify(await assertion()), ClientAssertionUnavailable);
  const verify = createClientAssertionVerifier({ issuer: () => issuer, now: () => now * 1000,
    loadClient: async () => { throw Error('synthetic private details'); }, keySet: () => keySet, claimNonce: async () => true });
  await assert.rejects(verify(await assertion(), operation), ClientAssertionUnavailable);
  const resolver = (unavailable: boolean) => createClientAssertionVerifier({ issuer: () => issuer, now: () => now * 1000,
    loadClient: async () => ({ client_id: clientId, disabled_at: null }),
    keySet: () => async () => { if (unavailable) throw Error('synthetic key transport unavailable');throw new errors.JWKSNoMatchingKey(); },
    claimNonce: async () => { throw Error('Invalid proof must not claim a nonce'); } });
  await assert.rejects(resolver(true)(await assertion(), operation), ClientAssertionUnavailable);
  assert.equal(await resolver(false)(await assertion(), operation), null);
});


test('delayed key resolution rechecks current expiry, age and future iat before claiming a nonce', async () => {
  for (const [delaySeconds, lifetime, expected] of [[69, 60, clientId], [70, 60, null], [131, 120, null], [-10, 60, clientId], [-11, 60, null]] as const) {
    let clock = now * 1000, claims = 0;
    const ttlValues: number[] = [];
    const verify = createClientAssertionVerifier({ issuer: () => issuer, now: () => clock,
      loadClient: async () => ({ client_id: clientId, disabled_at: null }),
      keySet: () => async (header, flattened) => {
        const key = await keySet(header, flattened);clock += delaySeconds * 1000;return key;
      },
      claimNonce: async (_key, ttl) => { claims++;ttlValues.push(ttl);return true; },
    });
    assert.equal(await verify(await assertion({ exp: now + lifetime }), operation), expected);
    assert.equal(claims, expected ? 1 : 0);
    if (delaySeconds === 69) assert.deepEqual(ttlValues, [1]);
  }
});

test('delayed successful nonce claim cannot admit an expired proof and never releases its consumed nonce', async () => {
  for (const [delaySeconds, expected] of [[69, clientId], [70, null], [-10, clientId], [-11, null]] as const) {
    let clock = now * 1000;
    const consumed = new Set<string>();
    const verify = createClientAssertionVerifier({ issuer: () => issuer, now: () => clock,
      loadClient: async () => ({ client_id: clientId, disabled_at: null }), keySet: () => keySet,
      claimNonce: async key => { await Promise.resolve();consumed.add(key);clock += delaySeconds * 1000;return true; },
    });
    assert.equal(await verify(await assertion(), operation), expected);
    assert.equal(consumed.size, 1, 'a late rejection must not roll back the replay claim');
  }
  let clock = now * 1000;
  const verify = createClientAssertionVerifier({ issuer: () => issuer, now: () => clock,
    loadClient: async () => ({ client_id: clientId, disabled_at: null }), keySet: () => keySet,
    claimNonce: async () => { clock += 70_000;throw Error('synthetic storage outage'); },
  });
  await assert.rejects(verify(await assertion(), operation), ClientAssertionUnavailable);
});
