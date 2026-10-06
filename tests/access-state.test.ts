import assert from 'node:assert/strict';
import test from 'node:test';
import crypto from 'node:crypto';
import express from 'express';
import { SignJWT, generateKeyPair, exportJWK, createLocalJWKSet } from 'jose';
import { createAccessStateRouter, ACCESS_STATE_PATH, ACCESS_QUERY_TYPE, type AccessState } from '../src/backchannel/accessState.js';
import type { AddressInfo } from 'node:net';
const ISSUER = 'https://issuer.example.invalid', RP = 'test-rp';
const SUBJECT = '11111111-1111-4111-8111-111111111111';
const keys = await generateKeyPair('EdDSA'), attacker = await generateKeyPair('EdDSA');
const jwk = await exportJWK(keys.publicKey);jwk.kid = 'synthetic';
const otherKeys = await generateKeyPair('EdDSA'), otherJwk = await exportJWK(otherKeys.publicKey);otherJwk.kid = 'synthetic';
const state: AccessState = { sub: SUBJECT, account: { status: 'active' }, rp: { catalog_synced: true, role_id: 2, role_source: 'catalog', access: 'allowed' }, allowed: true };
async function signed(overrides: Record<string, unknown> = {}, options: { typ?: string; audience?: string | string[]; issuer?: string; subject?: string; lifetime?: number; past?: number; attacker?: boolean } = {}) {
  const now = Math.floor(Date.now() / 1000) - (options.past ?? 0);
  return new SignJWT({ method: 'GET', path: ACCESS_STATE_PATH, action: 'access-state', subjects: [SUBJECT], ...overrides })
    .setProtectedHeader({ alg: 'EdDSA', typ: options.typ ?? ACCESS_QUERY_TYPE, kid: 'synthetic' })
    .setIssuer(options.issuer ?? RP).setSubject(options.subject ?? RP)
    .setAudience(options.audience ?? ISSUER + ACCESS_STATE_PATH).setIssuedAt(now)
    .setExpirationTime(now + (options.lifetime ?? 60)).setJti(crypto.randomUUID()).sign(options.attacker ? attacker.privateKey : keys.privateKey);
}
test('signed GET validation, client scoping, read-only failures and legacy routing', async () => {
  let reads = 0, disabled = false, missing = false, failRead = false, incomplete = false, failKey = false, multipleKeys = false, rotatedKeys = false;
  const app = express();app.set('etag', false);
  app.post('/backchannel/events', (_req, res) => res.status(204).end());
  app.use(createAccessStateRouter({ issuer: () => ISSUER,
    loadClient: async id => missing || id !== RP ? null : { client_id: RP, disabled_at: disabled ? 'synthetic-date' : null },
    keySet: () => failKey ? async () => { throw new Error('synthetic key host failure'); } : createLocalJWKSet({ keys: multipleKeys ? [jwk, otherJwk] : rotatedKeys ? [jwk, { ...otherJwk, kid: 'old-key' }] : [jwk] }),
    readStates: async (id, subjects) => { reads++;assert.equal(id, RP);assert.deepEqual(subjects, [SUBJECT]);if (failRead) throw new Error('synthetic failure');return incomplete ? [] : [state]; },
  }));
  const server = app.listen(0, '127.0.0.1');await new Promise<void>(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const request = (token?: string, path = ACCESS_STATE_PATH, method = 'GET') => fetch(base + path, { method, headers: token ? { Authorization: `Bearer ${token}` } : {} });
  try {
    assert.equal((await request()).status, 401);assert.equal(reads, 0);
    const good = await signed({ client_id: 'another-rp' }), response = await request(good);
    assert.equal(response.status, 200);assert.equal(response.headers.get('cache-control'), 'no-store');assert.equal(response.headers.get('etag'), null);
    const body = await response.json();assert.equal(body.client_id, RP);assert.equal(body.complete, true);assert.deepEqual(body.subjects, [state]);assert.equal(reads, 1);
    for (const token of [await signed({}, { typ: 'events+jwt' }), await signed({}, { audience: [ISSUER + ACCESS_STATE_PATH, ISSUER] }), await signed({}, { audience: ISSUER }), await signed({}, { subject: 'other' }),
      await signed({}, { issuer: 'other' }), await signed({}, { attacker: true }), await signed({}, { lifetime: 121 }), await signed({}, { past: 300 }),
      await signed({ method: 'POST' }), await signed({ path: '/backchannel/events' }), await signed({ action: 'roles.sync' })]) {
      assert.equal((await request(token)).status, 401);
    }
    assert.equal(reads, 1);
    for (const subjects of [[], ['not-a-uuid'], [SUBJECT, SUBJECT], Array(101).fill(SUBJECT), [{ sub: SUBJECT }]]) {
      assert.equal((await request(await signed({ subjects }))).status, 400);
    }
    assert.equal((await request(good, ACCESS_STATE_PATH + '?client_id=other')).status, 400);
    assert.equal((await request(good, ACCESS_STATE_PATH, 'POST')).status, 405);
    assert.equal((await request(good, ACCESS_STATE_PATH, 'HEAD')).status, 405);
    assert.equal((await fetch(base + '/backchannel/events', { method: 'POST' })).status, 204);
    disabled = true;assert.equal((await request(good)).status, 401);disabled = false;
    missing = true;assert.equal((await request(good)).status, 401);missing = false;
    multipleKeys = true;assert.equal((await request(await signed({}, { attacker: true }))).status, 401);assert.equal((await request(good)).status, 401);multipleKeys = false;
    rotatedKeys = true;assert.equal((await request(good)).status, 200);rotatedKeys = false;
    failKey = true;assert.equal((await request(good)).status, 503);failKey = false;
    failRead = true;assert.equal((await request(good)).status, 503);failRead = false;
    incomplete = true;assert.equal((await request(good)).status, 503);
  } finally { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); }
});

test('unavailability diagnostics correlate stages without exposing credentials or subjects', async () => {
  const diagnostics: import('../src/backchannel/accessState.js').AccessStateDiagnostic[] = [];
  let fault = 'key_config';
  const secret = 'synthetic-private-error-text';
  const app = express();
  app.use(createAccessStateRouter({ issuer: () => ISSUER,
    loadClient: async () => { if (fault === 'load_client') throw Object.assign(new Error(secret), { code: '08006' });return { client_id: RP, disabled_at: null }; },
    keySet: (_client, context) => {
      assert.equal(context?.operation, 'access_state');assert.match(context?.requestId ?? '', /^[0-9a-f-]{36}$/);
      if (fault === 'key_config') throw new Error(secret);
      if (fault === 'missing_key') return null;
      if (fault === 'key_resolution') return async () => { throw Object.assign(new Error(secret), { code: 'EPERM' }); };
      return createLocalJWKSet({ keys: [jwk] });
    },
    readStates: async () => { if (fault === 'read_states') throw Object.assign(new Error(secret), { code: '42703' });return fault === 'read_shape' ? [] : [state]; },
    diagnostic: event => diagnostics.push(event),
  }));
  const server = app.listen(0, '127.0.0.1');await new Promise<void>(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}${ACCESS_STATE_PATH}`;
  try {
    const good = await signed();
    for (const stage of ['load_client', 'key_config', 'key_resolution', 'read_states', 'read_shape']) {
      fault = stage;const response = await fetch(base, { headers: { Authorization: `Bearer ${good}` } });
      assert.equal(response.status, 503);assert.deepEqual(await response.json(), { error: 'access_state_unavailable' });
      const event = diagnostics.at(-1)!;assert.equal(event.stage, stage);assert.equal(event.request_id, response.headers.get('x-request-id'));
      assert.ok(event.elapsed_ms >= 0);
    }
    assert.equal(diagnostics[0].error_code, '08006');assert.equal(diagnostics[2].error_code, 'EPERM');assert.equal(diagnostics[3].error_code, '42703');
    const serialized = JSON.stringify(diagnostics);assert.ok(!serialized.includes(good));assert.ok(!serialized.includes(SUBJECT));assert.ok(!serialized.includes(secret));
    fault = 'missing_key';assert.equal((await fetch(base, { headers: { Authorization: `Bearer ${good}` } })).status, 401);
    fault = 'none';assert.equal((await fetch(base, { headers: { Authorization: `Bearer ${await signed({}, { attacker: true })}` } })).status, 401);
    assert.equal(diagnostics.length, 5);
    assert.equal((await fetch(base, { headers: { Authorization: `Bearer ${good}` } })).status, 200);
  } finally { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); }
});
