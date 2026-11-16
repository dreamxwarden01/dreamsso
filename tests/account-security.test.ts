import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import crypto from 'node:crypto';
import ts from 'typescript';
import { isTrustedMutation } from '../account/server/src/request-source.js';

// Execute the complete actual route module with explicit synthetic dependencies.
// No application config, Redis connection, secrets, HTTP listener or SSO is loaded.
function loadApi(overrides: Record<string, unknown> = {}) {
  const routes: { method: string; path: string; handlers: Function[] }[] = [];
  let updates = 0, reads = 0, destroys = 0;
  const session = { sub: 'fixture', ssoSid: 'master', claims: {}, accessToken: 'fixture', idToken: 'fixture',
    accessExpiresAt: Math.floor(Date.now() / 1000) + 900, amr: [], createdAt: 1 };
  const dependencies: Record<string, unknown> = {
    express: { Router: () => Object.fromEntries(['get', 'post', 'patch', 'delete', 'use'].map(method =>
      [method, (path: string, ...handlers: Function[]) => routes.push({ method, path, handlers })])), raw: () => (_req: unknown, _res: unknown, next: Function) => next() },
    '../session.js': { getSession: async () => { reads++; return session; }, updateSession: async () => { updates++; return true; }, destroySession: async () => { destroys++; } },
    '../config.js': { config: { internal: 'https://sso.invalid', publicUrl: 'https://account.example', redirectUri: '' } },
    '../oidc.js': { s2sAssertion: async () => 'synthetic' },
    '../s2sFetch.js': { s2sFetch: async () => { throw Error('unexpected upstream call'); } },
    './auth.js': { SESSION_COOKIE: 'acct_sid' }, '../request-source.js': { isTrustedMutation }, ...overrides,
  };
  const source = fs.readFileSync(new URL('../account/server/src/routes/api.ts', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  vm.runInNewContext(output, { exports: {}, require: (id: string) => { assert.ok(id in dependencies, id); return dependencies[id]; }, Buffer, Uint8Array, AbortSignal, Date, console });
  return { routes, session, updates: () => updates, reads: () => reads, destroys: () => destroys };
}

function request(method = 'POST', headers: Record<string, string> = { origin: 'https://account.example' }) {
  return { method, cookies: { acct_sid: 'opaque' }, headers, get: (name: string) => headers[name.toLowerCase()],
    body: {}, query: {}, params: { sid: 'other' }, url: '/users/fixture' };
}
function response() {
  return { statusCode: 200, body: undefined as any, ended: false,
    status(n: number) { this.statusCode = n; return this; }, json(body: any) { this.body = body; this.ended = true; return this; },
    end() { this.ended = true; return this; } };
}
async function run(handlers: Function[], req: any, res = response()) {
  for (const handler of handlers) {
    let next = false;
    await handler(req, res, () => { next = true; });
    if (!next) break;
  }
  return res;
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>(done => { resolve = done; });
  return { promise, resolve };
}

test('Account mutations require an exact configured origin, independent of payload type', () => {
  const cases: [Record<string, string>, boolean][] = [
    [{ origin: 'https://account.example' }, true],
    [{ origin: 'https://account.example', 'sec-fetch-site': 'same-origin' }, true],
    [{ referer: 'https://account.example/security?tab=mfa' }, true],
    [{ origin: 'https://sibling.example', 'sec-fetch-site': 'same-site' }, false],
    [{ origin: 'https://account.example', 'sec-fetch-site': 'cross-site' }, false],
    [{ origin: 'https://account.example', 'sec-fetch-site': 'same-site' }, false],
    [{ origin: 'https://account.example', 'sec-fetch-site': 'none' }, false],
    [{ origin: 'null', referer: 'https://account.example/' }, false],
    [{ origin: 'https://evil.example', referer: 'https://account.example/' }, false],
    [{ origin: 'https://account.example.evil.test' }, false],
    [{ origin: 'http://account.example' }, false],
    [{ origin: 'https://account.example:444' }, false],
    [{ origin: 'https://account.example/path' }, false],
    [{ origin: 'https://account.example https://evil.example' }, false],
    [{ referer: 'https://evil.example/' }, false], [{}, false],
  ];
  for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) for (const [headers, expected] of cases)
    assert.equal(isTrustedMutation(request(method, headers) as any, 'https://account.example', ''), expected, JSON.stringify({ method, headers }));
  assert.equal(isTrustedMutation(request('POST', { origin: 'http://localhost:5173' }) as any, '', 'http://localhost:5173/auth/callback'), true);
  assert.equal(isTrustedMutation(request() as any, 'invalid', 'https://account.example/auth/callback'), false);
  for (const method of ['GET', 'HEAD', 'OPTIONS']) assert.equal(isTrustedMutation(request(method, {}) as any, '', ''), true);
});

test('every cookie-authenticated mutation rejects sibling forms before renewal or forwarding, including binary avatar', async () => {
  const api = loadApi();
  api.session.accessExpiresAt = 0; // a rejected source must not trigger renewal
  let checked = 0;
  for (const route of api.routes) {
    if (!['post', 'patch', 'delete', 'use'].includes(route.method)) continue;
    const req = request(route.method === 'use' ? 'PUT' : route.method.toUpperCase(), { origin: 'https://sibling.example', 'sec-fetch-site': 'same-site', 'content-type': 'application/x-www-form-urlencoded' });
    const res = await run(route.handlers, req);
    assert.equal(res.statusCode, 403, route.path); assert.equal(res.body.error, 'csrf_rejected', route.path); checked++;
  }
  assert.ok(checked >= 25); assert.equal(api.updates(), 0);
  const missing = loadApi({ '../session.js': { getSession: async () => null } });
  const route = missing.routes.find(r => r.path === '/api/security/mfa/enable')!;
  assert.equal((await run(route.handlers, request('POST', { origin: 'https://sibling.example' }))).statusCode, 401);
});

test('legitimate JSON, bodyless actions, step-up, org and binary avatar retain their upstream behavior', async () => {
  const calls: { url: string; init: any }[] = [];
  const api = loadApi({ '../s2sFetch.js': { s2sFetch: async (url: string, init: any) => {
    calls.push({ url, init });
    if (url.endsWith('/account/avatar')) return Response.json({ avatar: 'new.webp' });
    if (url.endsWith('/account/profile')) return Response.json({ identity: { display_name: 'Updated' } });
    return new Response(null, { status: 204 });
  } } });
  for (const [method, path, body] of [['post', '/api/security/mfa/enable', {}], ['post', '/api/stepup/verify', { method: 'password', password: 'synthetic' }],
    ['patch', '/api/profile', { display_name: 'Updated' }], ['use', '/api/org', { test: 'payload' }], ['post', '/api/avatar', Buffer.from([1, 2, 3])]] as const) {
    const req = request(method === 'use' ? 'PUT' : method.toUpperCase()); req.body = body as any;
    req.headers['content-type'] = path === '/api/avatar' ? 'image/png' : 'application/json';
    const res = await run(api.routes.find(r => r.method === method && r.path === path)!.handlers, req);
    assert.ok(res.statusCode < 300, path);
  }
  assert.equal(calls.length, 5); assert.equal(calls[1].init.headers.authorization, 'Bearer fixture');
  assert.equal(JSON.parse(calls[1].init.body).sid, 'master');
  assert.equal(calls[3].init.headers['x-stepup-sid'], 'master');
  assert.equal(calls[4].init.headers['content-type'], 'image/png');
  assert.deepEqual([...calls[4].init.body], [1, 2, 3]); assert.equal(api.updates(), 2);
});

test('every late cache-write caller returns 401 after revocation instead of reporting a live session', async () => {
  for (const [method, path] of [['get', '/api/me'], ['patch', '/api/profile'], ['post', '/api/avatar'], ['delete', '/api/avatar']] as const) {
    const reached = deferred<void>(), upstream = deferred<Response>(); let alive = true, writes = 0;
    const api = loadApi({ '../session.js': { getSession: async () => api.session, updateSession: async () => { writes++; return alive; } },
      '../s2sFetch.js': { s2sFetch: async () => { reached.resolve(); return upstream.promise; } } });
    const req = request(method.toUpperCase()); req.body = (path === '/api/avatar' ? Buffer.from([1]) : { display_name: 'Updated' }) as any;
    const pending = run(api.routes.find(r => r.method === method && r.path === path)!.handlers, req);
    await reached.promise; alive = false;
    upstream.resolve(Response.json({ permissions: ['fixture'], identity: { display_name: 'Updated' }, avatar: 'new.webp' }));
    const res = await pending; assert.equal(res.statusCode, 401, path); assert.equal(res.body.error, 'unauthenticated'); assert.equal(writes, 1);
  }
});

test('renewal cannot continue to a handler when the cached session was revoked during the renewal', async () => {
  const reached = deferred<void>(), upstream = deferred<Response>(); let writes = 0;
  const api = loadApi({ '../session.js': { getSession: async () => api.session, updateSession: async () => { writes++; return false; } },
    '../s2sFetch.js': { s2sFetch: async () => { reached.resolve(); return upstream.promise; } } });
  api.session.accessExpiresAt = 0;
  const pending = run(api.routes.find(r => r.path === '/api/security')!.handlers, request('GET', {}));
  await reached.promise; upstream.resolve(Response.json({ access_token: 'renewed', expires_in: 900 }));
  const res = await pending; assert.equal(res.statusCode, 401); assert.equal(res.body.error, 'unauthenticated'); assert.equal(writes, 1);
});

test('upstream permission and step-up refusals remain 403 and do not masquerade as missing login', async () => {
  for (const error of ['permission_denied', 'step_up_required']) {
    const api = loadApi({ '../s2sFetch.js': { s2sFetch: async () => Response.json({ error }, { status: 403 }) } });
    const res = await run(api.routes.find(r => r.path === '/api/security/mfa/enable')!.handlers, request());
    assert.equal(res.statusCode, 403); assert.equal(res.body.error, error);
  }
});

test('the existing SPA client redirects only for 401 and preserves permission/step-up hooks for 403', async () => {
  const source = fs.readFileSync(new URL('../account/client/src/api.js', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const client: any = {}, location = { pathname: '/security', search: '?tab=mfa', href: '' };
  let status = 401, error = 'unauthenticated', permissionChecks = 0;
  const stepups: string[] = [];
  vm.runInNewContext(output, { exports: client, location, AbortSignal, URLSearchParams,
    fetch: async () => Response.json({ error }, { status }) });
  client.setPermissionDeniedHandler(() => { permissionChecks++; });
  client.setStepUpRequiredHandler((method: string) => { stepups.push(method); });
  await assert.rejects(client.getMe(), /unauthenticated/);
  assert.equal(location.href, '/auth/login?returnTo=%2Fsecurity%3Ftab%3Dmfa');
  location.href = ''; status = 403; error = 'csrf_rejected';
  for (const operation of [() => client.changePassword({ password: 'synthetic' }), () => client.uploadAvatar(new Blob(['fixture'], { type: 'image/png' }))]) {
    await assert.rejects(operation(), (e: any) => e.status === 403 && e.code === 'csrf_rejected');
    assert.equal(location.href, '');
  }
  assert.equal(permissionChecks, 0); assert.deepEqual(stepups, []);
  error = 'step_up_required'; await assert.rejects(client.mfaEnable(), /step_up_required/);
  assert.deepEqual(stepups, ['POST']);
  error = 'permission_denied'; await assert.rejects(client.orgApi('PATCH', '/users/fixture', {}), /permission_denied/);
  assert.equal(permissionChecks, 1); assert.equal(location.href, '');
});

test('/api/me propagates explicit SSO JSON denials without cached permissions or a session write', async () => {
  for (const [status, error] of [[401, 'invalid_token'], [403, 'access_denied'], [403, 'client_not_allowed'], [403, 'insufficient_scope']] as const) {
    const api = loadApi({ '../s2sFetch.js': { s2sFetch: async (url: string) => {
      assert.equal(url, 'https://sso.invalid/account/permissions');
      return Response.json({ error, permissions: ['untrusted-extra-field'] }, { status });
    } } });
    (api.session as any).permissions = ['cached-admin'];
    const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
    assert.equal(res.statusCode, status); assert.equal(res.body.error, error); assert.equal(Object.keys(res.body).length, 1);
    assert.equal(res.body.profile, undefined); assert.equal(res.body.permissions, undefined);
    assert.equal(api.updates(), 0); assert.deepEqual((api.session as any).permissions, ['cached-admin']);
  }
});

test('/api/me keeps only its existing cache on unavailable or non-authoritative permission responses without extending its lease', async () => {
  const cases = [
    () => new Response('<html>edge challenge</html>', { status: 403, headers: { 'content-type': 'text/html' } }),
    () => new Response('<html>proxy error</html>', { status: 502, headers: { 'content-type': 'text/html' } }),
    () => Response.json({ error: 'authentication_unavailable' }, { status: 503 }),
    () => Response.json({ error: 'access_denied' }, { status: 503 }),
    () => Response.json({ error: 'access_denied' }, { status: 403, headers: { 'cf-mitigated': 'challenge' } }),
    () => new Response('{invalid', { status: 403, headers: { 'content-type': 'application/json' } }),
    () => Response.json({ error: 'unknown_edge_error' }, { status: 403 }),
    () => Response.json({ permissions: ['new-grant', 1] }),
    () => { throw new Error('synthetic_transport_failure'); },
  ];
  for (const response of cases) {
    const api = loadApi({ '../s2sFetch.js': { s2sFetch: async () => response() } });
    (api.session as any).permissions = ['cached-read'];
    const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
    assert.equal(res.statusCode, 200); assert.deepEqual(res.body.permissions, ['cached-read']);
    assert.equal(api.updates(), 0, 'unavailability must not refresh the session expiry or cached lease');
  }
});

test('/api/me accepts a current empty permission set as revocation of cached grants', async () => {
  const api = loadApi({ '../s2sFetch.js': { s2sFetch: async () => Response.json({ permissions: [] }) } });
  (api.session as any).permissions = ['cached-admin'];
  const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
  assert.equal(res.statusCode, 200); assert.equal(res.body.permissions.length, 0); assert.equal(api.updates(), 1);
});

function actualSessionReader(raw: string | null, fail: 'session' | 'marker' | 'none' = 'marker', marker: string | null = null) {
  let reads = 0;
  const source = fs.readFileSync(new URL('../account/server/src/session.ts', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { esModuleInterop: true, module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  const dependencies: Record<string, unknown> = {
    'node:crypto': crypto,
    './config.js': { config: { sessionTtl: 60 } },
    './redis.js': { redis: { get: async (key: string) => {
      reads++;
      if (key.startsWith('acct:sess:')) {
        if (fail === 'session') throw new Error('synthetic_private_redis_diagnostic');
        return raw;
      }
      assert.ok(key.startsWith('acct:ssorevoked:'));
      if (fail === 'marker') throw new Error('synthetic_private_redis_diagnostic');
      return marker;
    }, eval: async () => { throw new Error('synthetic_cleanup_failure'); } } },
  };
  const exported: any = {};
  vm.runInNewContext(output, { exports: exported, require: (id: string) => { assert.ok(Object.hasOwn(dependencies, id), id); return dependencies[id]; } });
  return { ...exported, reads: () => reads };
}

test('actual Account session reads distinguish marker-store uncertainty from malformed or revoked records', async () => {
  const data = { sub: crypto.randomUUID(), ssoSid: crypto.randomUUID(), claims: {}, accessToken: 'synthetic', idToken: 'synthetic',
    accessExpiresAt: Math.floor(Date.now() / 1000) + 900, amr: [], createdAt: 1 };
  for (const failure of ['session', 'marker'] as const) {
    const reader = actualSessionReader(JSON.stringify(data), failure);
    await assert.rejects(reader.getSession('fixture'), (error: any) => {
      assert.ok(error instanceof reader.SessionStateUnavailable);
      assert.equal(error.name, 'SessionStateUnavailable');
      assert.equal(error.message, 'Session state unavailable.');
      return true;
    });
  }
  for (const raw of [null, 'invalid-json', 'null', '"scalar"', '[]', JSON.stringify({ ...data, ssoSid: 'invalid' })]) {
    const reader = actualSessionReader(raw, 'marker');
    assert.equal(await reader.getSession('fixture'), null);
    assert.equal(reader.reads(), 1, 'malformed/absent records never query a marker');
  }
  const revoked = actualSessionReader(JSON.stringify(data), 'none', data.sub);
  assert.equal(await revoked.getSession('fixture'), null, 'known denial stays denial despite cleanup failure');
});

test('/api/me returns 503 without profile or redirect when the actual revocation-marker read is unavailable', async () => {
  const reader = actualSessionReader(JSON.stringify({ sub: crypto.randomUUID(), ssoSid: crypto.randomUUID(), claims: {},
    accessToken: 'synthetic', idToken: 'synthetic', accessExpiresAt: Math.floor(Date.now() / 1000) + 900, amr: [], createdAt: 1 }));
  let upstreamCalls = 0, writes = 0;
  const api = loadApi({ '../session.js': { getSession: reader.getSession, updateSession: async () => { writes++; return true; } },
    '../s2sFetch.js': { s2sFetch: async () => { upstreamCalls++; throw Error('unexpected upstream'); } } });
  const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
  assert.equal(res.statusCode, 503); assert.equal(res.body.error, 'session_unavailable');
  assert.equal(res.body.profile, undefined); assert.equal(res.body.permissions, undefined);
  assert.equal(writes, 0); assert.equal(upstreamCalls, 0);
});

test('known renewal denials stop expired and near-expiry requests before any handler and destroy only the local record', async () => {
  for (const error of ['session_gone', 'invalid_client']) for (const remaining of [-1, 20]) for (const [method, path] of [['GET', '/api/me'], ['PATCH', '/api/profile'], ['GET', '/api/security']]) {
    let upstream = 0;
    const api = loadApi({ '../s2sFetch.js': { s2sFetch: async (url: string) => {
      upstream++; assert.equal(url, 'https://sso.invalid/internal/token/renew');
      return Response.json({ error }, { status: 401 });
    } } });
    (api.session as any).permissions = ['cached-admin']; api.session.accessExpiresAt = Math.floor(Date.now() / 1000) + remaining;
    const res = await run(api.routes.find(r => r.path === path)!.handlers, request(method));
    assert.equal(res.statusCode, 401); assert.equal(res.body.error, error);
    assert.equal(res.body.profile, undefined); assert.equal(res.body.permissions, undefined);
    assert.equal(api.destroys(), 1); assert.equal(api.updates(), 0); assert.equal(upstream, 1);
  }
});

test('renewal uncertainty and non-authoritative 403 responses preserve existing soft behavior without destroying or extending local state', async () => {
  const cases = [
    () => new Response('<html>challenge</html>', { status: 401, headers: { 'content-type': 'text/html' } }),
    () => Response.json({ error: 'session_gone' }, { status: 401, headers: { 'cf-mitigated': 'challenge' } }),
    () => Response.json({ error: 'invalid_client' }, { status: 503 }),
    () => Response.json({ error: 'access_denied' }, { status: 403 }),
    () => Response.json({ error: 'unknown_edge_error' }, { status: 401 }),
    () => new Response('invalid-json', { status: 401, headers: { 'content-type': 'application/json' } }),
    () => { throw new Error('synthetic_transport_failure'); },
  ];
  for (const reply of cases) for (const remaining of [-1, 20]) {
    const api = loadApi({ '../s2sFetch.js': { s2sFetch: async (url: string) => url.endsWith('/internal/token/renew') ? reply()
      : Response.json({ error: 'authentication_unavailable' }, { status: 503 }) } });
    (api.session as any).permissions = ['cached-read']; api.session.accessExpiresAt = Math.floor(Date.now() / 1000) + remaining;
    const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
    assert.equal(res.statusCode, 200); assert.deepEqual(res.body.permissions, ['cached-read']);
    assert.equal(api.destroys(), 0); assert.equal(api.updates(), 0);
  }
});

test('failed local destruction after a known renewal denial returns503 without profile or further calls', async () => {
  let upstream = 0, writes = 0, destroys = 0;
  const api = loadApi({ '../session.js': { getSession: async () => api.session,
    updateSession: async () => { writes++; return true; }, destroySession: async () => { destroys++; throw Error('synthetic_store_failure'); } },
    '../s2sFetch.js': { s2sFetch: async () => { upstream++; return Response.json({ error: 'session_gone' }, { status: 401 }); } } });
  api.session.accessExpiresAt = 0; (api.session as any).permissions = ['cached-admin'];
  const res = await run(api.routes.find(r => r.path === '/api/me')!.handlers, request('GET', {}));
  assert.equal(res.statusCode, 503); assert.equal(res.body.error, 'session_unavailable');
  assert.equal(res.body.profile, undefined); assert.equal(res.body.permissions, undefined);
  assert.equal(upstream, 1); assert.equal(writes, 0); assert.equal(destroys, 1);
});
