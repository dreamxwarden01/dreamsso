import assert from 'node:assert/strict';
import test from 'node:test';
import express from 'express';
import { randomUUID } from 'node:crypto';
import type { AddressInfo } from 'node:net';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createEventReceiver } from '../src/backchannel/eventReceiver.js';
import { EVENT_PATH, MAX_EVENT_FORM_BYTES, MAX_EVENT_TOKEN_BYTES, eventForm } from '../src/backchannel/eventForm.js';
import { EventError } from '../src/backchannel/rolesSync.js';

const ISSUER = 'https://issuer.example.invalid', CLIENT = 'synthetic-rp';
const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'test';
const now = 2_000_000_000_000;
async function token(events: unknown, options: { typ?: string; iat?: number; exp?: number } = {}) {
  return new SignJWT({ events }).setProtectedHeader({ alg: 'EdDSA', typ: options.typ ?? 'events+jwt', kid: 'test' })
    .setIssuer(CLIENT).setAudience(ISSUER).setIssuedAt(options.iat ?? now / 1000).setExpirationTime(options.exp ?? now / 1000 + 120)
    .setJti(randomUUID()).sign(keys.privateKey);
}
const roles = () => [{ id: randomUUID(), type: 'roles.sync', payload: { default_role: null, roles: [{ role_id: 0, name: 'Owner', level: 0 }] } }];

test('actual signed event route uses its bounded form parser before the global parser', async () => {
  let calls = 0, clientLoads = 0, blocked = false, failure: Error | null = null;
  const app = express();
  // Same order as server.ts: setup gate, scoped event parser, normal parsers.
  app.use((_req, res, next) => blocked ? void res.status(503).end() : next());
  app.use(EVENT_PATH, eventForm);app.use(express.urlencoded({ extended: false }));app.use(express.json());
  app.use(createEventReceiver({ issuer: () => ISSUER, now: () => now,
    loadClient: async id => { clientLoads++;return id === CLIENT ? { client_id: id, disabled_at: null } : null; },
    keySet: () => createLocalJWKSet({ keys: [jwk] }),
    process: async (clientId, time, events) => { assert.equal(clientId, CLIENT);assert.equal(time.iat, now / 1000);assert.ok(events.length);calls++;if (failure) throw failure; },
  }));
  app.post('/ordinary', (_req, res) => res.status(204).end());
  app.use((error: { status?: number }, _req: express.Request, res: express.Response, _next: express.NextFunction) => res.status(error.status ?? 500).end());
  const server = app.listen(0, '127.0.0.1');await new Promise<void>(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  const post = (body: string, contentType = 'application/x-www-form-urlencoded', path = EVENT_PATH) => fetch(base + path,
    { method: 'POST', headers: { 'Content-Type': contentType }, body });
  const signedPost = async (events = roles(), options: Parameters<typeof token>[1] = {}) => post(new URLSearchParams({ event_token: await token(events, options) }).toString());
  try {
    assert.equal((await signedPost()).status, 204);assert.equal(calls, 1);
    const large = await token([{ id: randomUUID(), type: 'future.type', payload: { padding: 'x'.repeat(150_000) } }]);
    assert.ok(Buffer.byteLength(large) > 200_000 && Buffer.byteLength(large) < MAX_EVENT_TOKEN_BYTES);
    assert.equal((await post(new URLSearchParams({ event_token: large }).toString())).status, 204);assert.equal(calls, 2);
    const nearLimitEvent = { id: randomUUID(), type: 'future.type', payload: { padding: '' } };
    const minimum = await token([nearLimitEvent]);
    nearLimitEvent.payload.padding = 'x'.repeat(Math.floor((MAX_EVENT_TOKEN_BYTES - minimum.length) / 4) * 3);
    const nearLimit = await token([nearLimitEvent]);
    assert.ok(nearLimit.length <= MAX_EVENT_TOKEN_BYTES && nearLimit.length > MAX_EVENT_TOKEN_BYTES - 4);
    assert.equal((await post(new URLSearchParams({ event_token: nearLimit }).toString())).status, 204);assert.equal(calls, 3);
    assert.equal((await post('data=' + 'x'.repeat(110_000), undefined, '/ordinary')).status, 413);
    const priorLoads = clientLoads;
    assert.equal((await post('event_token=a.b.' + 'x'.repeat(MAX_EVENT_FORM_BYTES))).status, 413);
    assert.equal((await post('event_token=a.b.' + 'x'.repeat(MAX_EVENT_TOKEN_BYTES))).status, 400);
    assert.equal((await post('event_token=a.b')).status, 400);
    assert.equal((await post('event_token=a.b.c&event_token=d.e.f')).status, 413);
    assert.equal((await post(JSON.stringify({ event_token: large }), 'application/json')).status, 415);
    assert.equal(clientLoads, priorLoads);assert.equal(calls, 3);
    assert.equal((await signedPost(roles(), { typ: 'JWT' })).status, 401);
    assert.equal((await signedPost(roles(), { iat: now / 1000 - 311, exp: now / 1000 + 120 })).status, 401);
    assert.equal((await signedPost(roles(), { exp: now / 1000 - 10 })).status, 401);
    const malformed = [{ ...roles()[0], payload: { roles: [{ role_id: null, name: 'Bad', level: 0 }] } }];
    assert.equal((await signedPost(malformed as ReturnType<typeof roles>)).status, 400);assert.equal(calls, 3);
    const invalidDefault=[{...roles()[0]!,payload:{roles:[{role_id:0,name:'Owner',level:0}],default_role:false}}];
    const rejectedDefault=await signedPost(invalidDefault as unknown as ReturnType<typeof roles>);assert.equal(rejectedDefault.status,400);
    assert.deepEqual(await rejectedDefault.json(),{error:'invalid_default_role'});assert.equal(calls,3);
    failure = new EventError('catalog_order_ambiguous', 409);
    const conflict = await signedPost();assert.equal(conflict.status, 409);assert.deepEqual(await conflict.json(), { error: 'catalog_order_ambiguous' });
    failure = new Error('synthetic-secret-database-message');
    const unavailable = await signedPost();assert.equal(unavailable.status, 503);assert.deepEqual(await unavailable.json(), { error: 'events_unavailable' });
    const beforeBlocked = calls;blocked = true;
    assert.equal((await post('event_token=' + 'x'.repeat(MAX_EVENT_FORM_BYTES + 1))).status, 503);assert.equal(calls, beforeBlocked);
  } finally { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); }
});
