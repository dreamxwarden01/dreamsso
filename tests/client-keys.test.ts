import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import https from 'node:https';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import type { AddressInfo } from 'node:net';
import { SignJWT, generateKeyPair, exportJWK, jwtVerify, errors } from 'jose';
import { ClientKeyResolver, safeKeyError, type KeyDiagnostic } from '../src/clientKeys.js';
const pair = await generateKeyPair('EdDSA'), rotated = await generateKeyPair('EdDSA');
const first = { ...await exportJWK(pair.publicKey), kid: 'synthetic-a', alg: 'EdDSA', use: 'sig' };
const second = { ...await exportJWK(rotated.publicKey), kid: 'synthetic-b', alg: 'EdDSA', use: 'sig' };
const signed = (key = pair.privateKey, kid = 'synthetic-a') => new SignJWT({}).setProtectedHeader({ alg: 'EdDSA', kid })
  .setIssuer('synthetic-rp').setAudience('https://issuer.example.invalid').setExpirationTime('60s').sign(key);
async function fixture() {
  let count = 0, status = 200, body = JSON.stringify({ keys: [first] });
  const headers: { ua: string | undefined; accept: string | undefined }[] = [];
  const server = http.createServer((req, res) => {
    count++;headers.push({ ua: req.headers['user-agent'], accept: req.headers.accept });
    res.writeHead(status, { 'content-type': 'application/json', ...(status === 302 ? { location: '/real' } : {}) }).end(body);
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks?secret=synthetic-private-query`,
    get count() { return count; }, headers, set status(value: number) { status = value; }, set body(value: string) { body = value; },
    async close() { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); } };
}

test('registration and every runtime operation share direct-200 transport and request headers', async () => {
  const f = await fixture(), events: KeyDiagnostic[] = [], resolver = new ClientKeyResolver(event => events.push(event));
  try {
    f.status = 302;
    assert.ok((await resolver.verifyUri(f.url)).error);
    const client = { client_id: 'synthetic-rp', jwks_uri: f.url, jwks: null };
    await assert.rejects(jwtVerify(await signed(), resolver.keySet(client, { operation: 'token' })!));
    assert.equal(f.count, 2);assert.deepEqual(f.headers[0], f.headers[1]);assert.equal(f.headers[0].accept, 'application/json');
    assert.equal(events.length, 2);assert.equal(events[0].reason, 'jwks_http_non_200');assert.equal(events[1].reason, 'jwks_http_non_200');
    assert.equal(events[0].operation, 'registration');assert.equal(events[1].operation, 'token');
    assert.equal(events[1].jwks_host, '127.0.0.1');assert.ok(!JSON.stringify(events).includes('synthetic-private-query'));
    f.status = 200;
    assert.equal((await resolver.verifyUri(f.url)).error, null);
    for (const operation of ['token', 'events', 'reset', 'client_assertion', 'access_state'] as const) {
      await jwtVerify(await signed(), resolver.keySet(client, { operation })!);
    }
    assert.equal(f.count, 4); // Registration refreshes independently; all runtime consumers share one cache.
  } finally { await f.close(); }
});

test('shared cache coalesces concurrent cold fetches, isolates RP/URL, and preserves unknown-kid cooldown', async () => {
  const f = await fixture(), resolver = new ClientKeyResolver(() => {});
  try {
    const client = { client_id: 'synthetic-rp', jwks_uri: f.url, jwks: null }, token = await signed();
    await Promise.all(Array.from({ length: 16 }, () => jwtVerify(token, resolver.keySet(client)!)));
    assert.equal(f.count, 1);
    f.body = JSON.stringify({ keys: [first, second] });
    await assert.rejects(jwtVerify(await signed(rotated.privateKey, 'synthetic-b'), resolver.keySet(client)!), errors.JWKSNoMatchingKey);
    assert.equal(f.count, 1);
    await jwtVerify(token, resolver.keySet({ ...client, client_id: 'other-rp' })!);assert.equal(f.count, 2);
    await jwtVerify(token, resolver.keySet({ ...client, jwks_uri: f.url + '&changed=1' })!);assert.equal(f.count, 3);
  } finally { await f.close(); }
});

test('failed fetch retries are unchanged and never fall back to the registration snapshot', async () => {
  const f = await fixture(), resolver = new ClientKeyResolver(() => {});
  try {
    f.status = 503;
    const client = { client_id: 'synthetic-rp', jwks_uri: f.url, jwks: { keys: [first] } }, token = await signed();
    for (let i = 0; i < 3; i++) await assert.rejects(jwtVerify(token, resolver.keySet(client)!));
    assert.equal(f.count, 3);
    f.status = 200;await jwtVerify(token, resolver.keySet(client)!);assert.equal(f.count, 4);
  } finally { await f.close(); }
});

test('inline keys, missing keys, and invalid key matching keep their authentication semantics', async () => {
  const diagnostics: KeyDiagnostic[] = [], resolver = new ClientKeyResolver(event => diagnostics.push(event));
  const client = { client_id: 'synthetic-rp', jwks_uri: null, jwks: { keys: [first] } };
  await jwtVerify(await signed(), resolver.keySet(client)!);
  await assert.rejects(jwtVerify(await signed(rotated.privateKey, 'synthetic-b'), resolver.keySet(client)!), errors.JWKSNoMatchingKey);
  await assert.rejects(jwtVerify(await signed(), resolver.keySet({ ...client, jwks: { keys: [first, { ...second, kid: 'synthetic-a' }] } })!), errors.JWKSMultipleMatchingKeys);
  assert.equal(diagnostics.length, 0);
  assert.equal(resolver.keySet({ ...client, jwks: null }), null);
});

test('configuration and response diagnostics redact raw errors, URLs, bodies, tokens and untrusted codes', async () => {
  const f = await fixture(), events: KeyDiagnostic[] = [], resolver = new ClientKeyResolver(event => events.push(event));
  const secret = 'synthetic-token-that-must-not-be-logged';
  try {
    f.body = '<html>' + secret + '</html>';
    const check = await resolver.verifyUri(f.url);assert.ok(check.error?.includes('jwks_bad_json'));
    const context = { operation: 'access_state' as const, requestId: '11111111-1111-4111-8111-111111111111' };
    await assert.rejects(jwtVerify(await signed(), resolver.keySet({ client_id: 'synthetic-rp', jwks_uri: f.url, jwks: null }, context)!));
    assert.equal(events[1].request_id, context.requestId);
    assert.ok((await resolver.verifyUri('http://remote.example.invalid/' + secret)).error);
    assert.throws(() => resolver.keySet({ client_id: 'synthetic-rp', jwks_uri: 'https://[invalid/' + secret, jwks: null }));
    assert.ok(!JSON.stringify(events).includes(secret));assert.ok(!JSON.stringify(events).includes('secret='));
    assert.deepEqual(safeKeyError({ code: 'EPERM', message: secret }), { code: 'EPERM', reason: 'key_transport_or_material_failure' });
    assert.equal(safeKeyError({ cause: { code: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE', message: secret } }).code, 'UNABLE_TO_VERIFY_LEAF_SIGNATURE');
    assert.equal(safeKeyError({ code: secret, message: secret }).code, 'UNKNOWN');
  } finally { await f.close(); }
});

test('registration rejects empty documents and diagnostic sink errors cannot grant access', async () => {
  const f = await fixture(), resolver = new ClientKeyResolver(() => { throw new Error('synthetic logger failure'); });
  try {
    f.body = JSON.stringify({ keys: [] });assert.ok((await resolver.verifyUri(f.url)).error);
    f.status = 503;
    await assert.rejects(jwtVerify(await signed(), resolver.keySet({ client_id: 'synthetic-rp', jwks_uri: f.url, jwks: null })!));
  } finally { await f.close(); }
});


test('registration and runtime preserve TLS certificate verification and redact TLS failure details', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'sso-jwks-tls-'));
  let server: https.Server | undefined;
  const events: KeyDiagnostic[] = [], resolver = new ClientKeyResolver(event => events.push(event));
  try {
    // Test-only, ephemeral certificate: no real server key or trust-store changes.
    await promisify(execFile)('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-nodes',
      '-subj', '/CN=localhost', '-days', '1', '-keyout', join(directory, 'key.pem'), '-out', join(directory, 'cert.pem')]);
    server = https.createServer({ key: await readFile(join(directory, 'key.pem')), cert: await readFile(join(directory, 'cert.pem')) },
      (_req, res) => res.end(JSON.stringify({ keys: [first] })));
    await new Promise<void>(resolve => server!.listen(0, '127.0.0.1', resolve));
    const uri = `https://127.0.0.1:${(server.address() as AddressInfo).port}/jwks?token=synthetic-private-query`;
    assert.ok((await resolver.verifyUri(uri)).error);
    await assert.rejects(jwtVerify(await signed(), resolver.keySet({ client_id: 'synthetic-rp', jwks_uri: uri, jwks: null })!));
    assert.equal(events.length, 2);assert.equal(events[0].error_code, 'DEPTH_ZERO_SELF_SIGNED_CERT');
    assert.equal(events[1].error_code, 'DEPTH_ZERO_SELF_SIGNED_CERT');
    assert.ok(!JSON.stringify(events).includes('synthetic-private-query'));
  } finally {
    if (server) { server.closeAllConnections();await new Promise<void>(resolve => server!.close(() => resolve())); }
    await rm(directory, { recursive: true, force: true });
  }
});

test('existing registered HTTP endpoints retain runtime behavior without broadening registration policy', async () => {
  let count = 0;
  const server = http.createServer((_req, res) => { count++;res.end(JSON.stringify({ keys: [first] })); });
  await new Promise<void>(resolve => server.listen(0, '::1', resolve));
  const resolver = new ClientKeyResolver(() => {});
  try {
    // IPv6 loopback HTTP was usable by the old runtime resolver, but not admitted by the admin form.
    const uri = `http://[::1]:${(server.address() as AddressInfo).port}/jwks`;
    assert.ok((await resolver.verifyUri(uri)).error);assert.equal(count, 0);
    await jwtVerify(await signed(), resolver.keySet({ client_id: 'synthetic-rp', jwks_uri: uri, jwks: null })!);
    assert.equal(count, 1);
  } finally { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); }
});

// The network timeout is an aggregate deadline, including an already received
// 200 response whose body never finishes. These fixtures use no external hosts.
import { fetchClientJwks, ClientJwksTooLarge } from '../src/clientJwksTransport.js';

async function transportFixture(handler: http.RequestListener) {
  const server = http.createServer(handler);
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    url: new URL(`http://127.0.0.1:${(server.address() as AddressInfo).port}/jwks`),
    async close() { server.closeAllConnections();await new Promise<void>(resolve => server.close(() => resolve())); },
  };
}

test('whole-response timeout aborts a stalled header and closes the socket', async () => {
  let closed!: () => void;
  const socketClosed = new Promise<void>(resolve => { closed = resolve; });
  const f = await transportFixture((_req, res) => { res.on('close', closed); });
  try {
    await assert.rejects(fetchClientJwks(f.url, { timeoutMs: 160 }), errors.JWKSTimeout);
    await Promise.race([socketClosed, new Promise((_, reject) => {
      const timer = setTimeout(() => reject(new Error('Transport socket was not closed')), 1000);timer.unref();
    })]);
  } finally { await f.close(); }
});

test('headers and continuing trickle bytes do not reset the whole-response deadline', async () => {
  let writes = 0;
  let closed!: () => void;
  const socketClosed = new Promise<void>(resolve => { closed = resolve; });
  const f = await transportFixture((_req, res) => {
    res.writeHead(200, { 'Content-Type': 'application/json' });res.write('{"keys":[');
    const interval = setInterval(() => { writes++;res.write(' '); }, 20);
    res.on('close', () => { clearInterval(interval);closed(); });
  });
  try {
    const start = performance.now();
    await assert.rejects(fetchClientJwks(f.url, { timeoutMs: 180 }), errors.JWKSTimeout);
    assert.ok(performance.now() - start < 1500);
    assert.ok(writes > 0);
    let watchdog: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([socketClosed, new Promise((_, reject) => {
        watchdog = setTimeout(() => reject(new Error('Trickle socket was not closed')), 1000);
      })]);
    } finally { clearTimeout(watchdog); }
  } finally { await f.close(); }
});

test('body limit covers both declared and chunked sizes, with no raw-content diagnostic', async () => {
  let declared = true;
  const f = await transportFixture((_req, res) => {
    res.writeHead(200, { ...(declared ? { 'Content-Length': '9999' } : {}) });
    res.end('synthetic-private-value'.repeat(5));
  });
  try {
    for (const flag of [true, false]) {
      declared = flag;
      await assert.rejects(fetchClientJwks(f.url, { maxBytes: 32 }), ClientJwksTooLarge);
    }
    assert.deepEqual(safeKeyError(new ClientJwksTooLarge()), {
      code: 'ERR_JWKS_RESPONSE_TOO_LARGE', reason: 'jwks_response_too_large',
    });
  } finally { await f.close(); }
});

test('complete exact-limit bodies parse; partial or malformed documents fail', async () => {
  let mode = 'valid';
  const body = JSON.stringify({ keys: [first] });
  const f = await transportFixture((_req, res) => {
    if (mode === 'partial') { res.writeHead(200, { 'Content-Length': '9999' });res.end(body);return; }
    res.end(mode === 'valid' ? body : '{bad-json');
  });
  try {
    assert.deepEqual(await fetchClientJwks(f.url, { maxBytes: Buffer.byteLength(body) }), { keys: [first] });
    mode = 'bad';await assert.rejects(fetchClientJwks(f.url), /Failed to parse/);
    mode = 'partial';await assert.rejects(fetchClientJwks(f.url, { timeoutMs: 120 }));
  } finally { await f.close(); }
});

test('registration and runtime deadlines release their fetch slots for a later successful retry', async () => {
  let stall = true, count = 0, closed = 0;
  const events: KeyDiagnostic[] = [], resolver = new ClientKeyResolver(event => events.push(event));
  const f = await transportFixture((_req, res) => {
    count++;
    if (stall) { res.writeHead(200);res.write('{');res.on('close', () => closed++); }
    else res.end(JSON.stringify({ keys: [first] }));
  });
  const client = { client_id: 'timeout-fixture', jwks_uri: f.url.href, jwks: { keys: [first] } };
  try {
    const token = await signed();
    const outcomes = await Promise.all([
      resolver.verifyUri(f.url.href),
      ...Array.from({ length: 6 }, () => assert.rejects(jwtVerify(token, resolver.keySet(client)!), errors.JWKSTimeout)),
    ]);
    assert.ok(outcomes[0]?.error?.includes('jwks_timeout'));
    assert.equal(count, 2); // One registration probe and one coalesced runtime read.
    assert.ok(events.every(event => event.error_code === 'ERR_JWKS_TIMEOUT'));
    stall = false;
    await jwtVerify(token, resolver.keySet(client)!);
    assert.equal((await resolver.verifyUri(f.url.href)).error, null);
    assert.equal(count, 4);assert.equal(closed, 2);
  } finally { await f.close(); }
});

test('elapsed cooldown permits unknown-kid refresh and expired keys never mask a fetch failure', async (t) => {
  const f = await fixture(), resolver = new ClientKeyResolver(() => {});
  const client = { client_id: 'time-fixture', jwks_uri: f.url, jwks: { keys: [first] } };
  let now = Date.now();
  t.mock.method(Date, 'now', () => now);
  try {
    const key = resolver.keySet(client)!;
    await key({ alg: 'EdDSA', kid: 'synthetic-a' }, { payload: new Uint8Array(), protected: '', signature: new Uint8Array() });
    f.body = JSON.stringify({ keys: [first, second] });
    now += 30_001;
    await key({ alg: 'EdDSA', kid: 'synthetic-b' }, { payload: new Uint8Array(), protected: '', signature: new Uint8Array() });
    assert.equal(f.count, 2);
    now += 600_001;f.status = 503;
    await assert.rejects(key({ alg: 'EdDSA', kid: 'synthetic-a' }, { payload: new Uint8Array(), protected: '', signature: new Uint8Array() }));
    assert.equal(f.count, 3);
    f.status = 200;
    await key({ alg: 'EdDSA', kid: 'synthetic-a' }, { payload: new Uint8Array(), protected: '', signature: new Uint8Array() });
    assert.equal(f.count, 4);
  } finally { await f.close(); }
});
