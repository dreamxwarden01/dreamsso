import test from 'node:test';
import assert from 'node:assert/strict';
import { getMe, listClients, createClient, updateClient, apiErrorMessage } from './api.js';

const json = (body, status = 200) => new Response(JSON.stringify(body), {
  status, headers: { 'content-type': 'application/json; charset=utf-8' },
});
const tick = () => new Promise((resolve) => setImmediate(resolve));

function fixture(t, fetch) {
  t.mock.method(globalThis, 'fetch', fetch);
  const previous = Object.getOwnPropertyDescriptor(globalThis, 'location');
  Object.defineProperty(globalThis, 'location', { configurable: true, value: {
    pathname: '/admin/clients/new', href: '', reload: t.mock.fn(),
  } });
  t.after(() => previous ? Object.defineProperty(globalThis, 'location', previous) : delete globalThis.location);
}

test('valid create uses canonical server ID and sends the synchronizer token', async (t) => {
  const calls = [];
  fixture(t, async (url, opts) => {
    calls.push({ url, opts });
    return url.endsWith('/me') ? json({ csrf: 'synthetic-csrf' }) : json({ client: { client_id: 'canonical-id' } }, 201);
  });
  await getMe();
  assert.equal((await createClient({ client_id: 'INPUT' })).client.client_id, 'canonical-id');
  assert.equal(calls[1].opts.headers['x-csrf-token'], 'synthetic-csrf');
  assert.equal(calls[1].opts.credentials, 'same-origin');
});

test('422 field errors survive without converting a rejection into an uncertain save', async (t) => {
  fixture(t, async () => json({ errors: { jwks_uri: 'JWKS endpoint unreachable' } }, 422));
  await assert.rejects(createClient({}), (e) => {
    assert.equal(e.status, 422);
    assert.equal(e.data.errors.jwks_uri, 'JWKS endpoint unreachable');
    assert.equal(e.uncertain, false);
    return true;
  });
});

test('fetch rejection is typed and no mutation is retried automatically', async (t) => {
  let count = 0;
  fixture(t, async () => { count++; throw new TypeError('offline'); });
  await assert.rejects(createClient({}), (e) => e.code === 'network_error' && e.status === 0 && e.uncertain);
  assert.equal(count, 1);
});

test('deadline ends a hanging fetch and ignores late success', async (t) => {
  let finish;
  let signal;
  fixture(t, (_, opts) => { signal = opts.signal; return new Promise((resolve) => { finish = resolve; }); });
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const p = assert.rejects(createClient({}), (e) => e.code === 'request_timeout' && e.uncertain);
  t.mock.timers.tick(15_000);
  await p;
  assert.equal(signal.aborted, true);
  finish(json({ client: { client_id: 'late' } }, 201));
  await tick();
  assert.equal(location.href, '');
});

test('deadline includes a stalled response body and prevents late auth side effects', async (t) => {
  let finish;
  fixture(t, async () => ({ status: 403, ok: false, headers: new Headers({ 'content-type': 'application/json' }),
    json: () => new Promise((resolve) => { finish = resolve; }) }));
  t.mock.timers.enable({ apis: ['setTimeout'] });
  const p = assert.rejects(createClient({}), (e) => e.code === 'request_timeout' && e.status === 403);
  await tick();
  t.mock.timers.tick(15_000);
  await p;
  finish({ error: 'step_up_required' });
  await tick();
  assert.equal(location.reload.mock.callCount(), 0);
});

test('malformed/HTML/wrong-shape success is uncertain, never a successful create', async (t) => {
  const replies = [new Response('<html>gateway</html>', { status: 201, headers: { 'content-type': 'text/html' } }),
    new Response('{', { status: 201, headers: { 'content-type': 'application/json' } }),
    json({}, 201), json({ client: {} }, 201), json({ client: { client_id: 'x' } }, 200),
    new Response(null, { status: 204 })];
  fixture(t, async () => replies.shift());
  while (replies.length) await assert.rejects(createClient({}), (e) => e.code === 'invalid_response' && e.uncertain);
});

test('Cloudflare challenge and ordinary 403 do not redirect to login', async (t) => {
  fixture(t, async () => new Response('<html>challenge</html>', { status: 403,
    headers: { 'content-type': 'text/html', 'cf-mitigated': 'challenge' } }));
  await assert.rejects(createClient({}), (e) => e.code === 'challenge_required' && !e.uncertain);
  t.mock.method(globalThis, 'fetch', async () => json({ error: 'permission_denied' }, 403));
  await assert.rejects(getMe(), (e) => e.code === 'permission_denied' && /permission/.test(apiErrorMessage(e)));
  assert.equal(location.href, '');
  assert.equal(location.reload.mock.callCount(), 0);
});

test('401 redirects to login with route; step-up keeps its existing verification bounce', async (t) => {
  fixture(t, async () => json({ error: 'unauthenticated' }, 401));
  await assert.rejects(getMe(), (e) => e.code === 'unauthenticated' && e.status === 401);
  assert.equal(location.href, '/admin/start-login?next=%2Fadmin%2Fclients%2Fnew');
  t.mock.method(globalThis, 'fetch', async () => json({ error: 'step_up_required' }, 403));
  await assert.rejects(createClient({}), (e) => e.code === 'step_up_required' && !e.uncertain);
  assert.equal(location.reload.mock.callCount(), 1);
});

test('read schema failures are visible and valid 204 updates remain supported', async (t) => {
  fixture(t, async () => json({}));
  await assert.rejects(getMe(), (e) => e.code === 'invalid_response' && !e.uncertain);
  await assert.rejects(listClients(), (e) => e.code === 'invalid_response' && !e.uncertain);
  t.mock.method(globalThis, 'fetch', async () => new Response(null, { status: 204 }));
  assert.equal(await updateClient('x', {}), null);
});

test('5xx mutation failure may follow a commit and must not claim it was not saved', async (t) => {
  fixture(t, async () => json({ error: 'internal_error' }, 500));
  await assert.rejects(createClient({}), (e) => e.uncertain && /may already/.test(apiErrorMessage(e)));
});


test('unknown safe error codes stay diagnosable without reflecting arbitrary server text', () => {
  assert.match(apiErrorMessage({ code: 'key_not_ready', status: 422 }), /key_not_ready/);
  assert.doesNotMatch(apiErrorMessage({ code: 'https://example.invalid/?token=secret', status: 422 }), /token=secret/);
  assert.match(apiErrorMessage({ code: 'request_timeout', uncertain: true }), /timed out.*may already/);
});
