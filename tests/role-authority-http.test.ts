import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import express from 'express';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { ACCESS_QUERY_TYPE, ACCESS_STATE_PATH, createAccessStateRouter,
  type AccessState, type AccessStateSnapshot } from '../src/backchannel/accessState.js';

const ISSUER = 'https://issuer.example.invalid', CLIENT = 'fixture-rp';
const EPOCH = '11111111-1111-4111-8111-111111111111';
const SUBJECTS = ['22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333'];
const now = new Date();
const keys = await generateKeyPair('EdDSA'), publicJwk = await exportJWK(keys.publicKey);
publicJwk.kid = 'generated-fixture-key';
const managed: AccessState[] = SUBJECTS.map((sub, i) => ({ sub, account: { status: 'active' },
  rp: { catalog_synced: true, role_id: i ? null : 0, role_source: i ? 'override' : 'catalog', access: i ? 'no_access' : 'allowed' }, allowed: !i }));
const unmanaged: AccessState[] = SUBJECTS.map(sub => ({ sub, account: { status: 'active' },
  rp: { catalog_synced: false, role_id: null, role_source: 'none', access: 'unmanaged' }, allowed: true }));
async function signed() {
  const jti = randomUUID(), iat = Math.floor(now.getTime() / 1000);
  return { jti, token: await new SignJWT({ method: 'GET', path: ACCESS_STATE_PATH, action: 'access-state', subjects: SUBJECTS })
    .setProtectedHeader({ alg: 'EdDSA', typ: ACCESS_QUERY_TYPE, kid: publicJwk.kid })
    .setIssuer(CLIENT).setSubject(CLIENT).setAudience(ISSUER + ACCESS_STATE_PATH).setIssuedAt(iat).setExpirationTime(iat + 120).setJti(jti).sign(keys.privateKey) };
}
const authorityHeaders = (response: Response) => [response.headers.get('x-dreamsso-authority-epoch'), response.headers.get('x-dreamsso-authority-revision')];

test('authority headers pair with the unchanged strict JSON response, while legacy readers remain compatible', async () => {
  let value: unknown = { states: managed, authority: { epoch: EPOCH, revision: '9007199254740993' } };
  let reads = 0, fallbackReads = 0;
  const diagnostics: unknown[] = [];
  const app = express();app.set('etag', false);
  const dependencies = { issuer: () => ISSUER, now: () => now,
    loadClient: async () => ({ client_id: CLIENT, disabled_at: null }),
    keySet: () => createLocalJWKSet({ keys: [publicJwk] }),
    readStates: async () => { fallbackReads++;return managed; },
    diagnostic: (event: unknown) => diagnostics.push(event),
  };
  app.use('/versioned', createAccessStateRouter({ ...dependencies,
    readSnapshot: async () => { reads++;if (value instanceof Error) throw value;return value as AccessStateSnapshot; } }));
  app.use('/legacy', createAccessStateRouter(dependencies));
  const server = app.listen(0, '127.0.0.1');await new Promise<void>((resolve, reject) => { server.once('listening', resolve);server.once('error', reject); });
  const origin = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const request = async (prefix = '/versioned') => {
    const proof = await signed();return { proof, response: await fetch(origin + prefix + ACCESS_STATE_PATH, { headers: { authorization: 'Bearer ' + proof.token } }) };
  };
  try {
    const first = await request();assert.equal(first.response.status, 200);
    assert.deepEqual(authorityHeaders(first.response), [EPOCH, '9007199254740993']);
    assert.deepEqual(await first.response.json(), { client_id: CLIENT, request_id: first.proof.jti,
      checked_at: now.toISOString(), complete: true, subjects: managed });
    assert.equal(first.response.headers.get('cache-control'), 'no-store');assert.equal(first.response.headers.get('etag'), null);
    assert.equal(reads, 1);assert.equal(fallbackReads, 0);

    value = { states: unmanaged, authority: null };
    const free = await request();assert.equal(free.response.status, 200);assert.deepEqual(authorityHeaders(free.response), [null, null]);
    assert.deepEqual((await free.response.json()).subjects, unmanaged);
    const legacy = await request('/legacy');assert.equal(legacy.response.status, 200);assert.deepEqual(authorityHeaders(legacy.response), [null, null]);
    assert.deepEqual((await legacy.response.json()).subjects, managed);assert.equal(fallbackReads, 1);

    const invalidSnapshots: unknown[] = [
      null, { states: managed, authority: null }, { states: managed },
      { states: managed, authority: { epoch: EPOCH } },
      ...[0, -1, '01', '-1', '9223372036854775808', '', null].map(revision => ({ states: managed, authority: { epoch: EPOCH, revision } })),
      { states: managed, authority: { epoch: 'not-an-epoch', revision: '1' } },
      { states: unmanaged, authority: { epoch: EPOCH, revision: '1' } },
      { states: [managed[0], unmanaged[1]], authority: { epoch: EPOCH, revision: '1' } },
      { states: [...managed].reverse(), authority: { epoch: EPOCH, revision: '1' } },
      { states: [managed[0]], authority: { epoch: EPOCH, revision: '1' } },
      new Error('synthetic private database details'),
    ];
    for (const invalid of invalidSnapshots) {
      value = invalid;const result = await request();assert.equal(result.response.status, 503);
      assert.deepEqual(authorityHeaders(result.response), [null, null]);
      assert.deepEqual(await result.response.json(), { error: 'access_state_unavailable' });
    }
    assert.equal(fallbackReads, 1);assert.ok(!JSON.stringify(diagnostics).includes('private database'));
    const beforeUnauthenticated = reads;
    const rejected = await fetch(origin + '/versioned' + ACCESS_STATE_PATH);
    assert.equal(rejected.status, 401);assert.equal(reads, beforeUnauthenticated);assert.deepEqual(authorityHeaders(rejected), [null, null]);
  } finally { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); }
});
