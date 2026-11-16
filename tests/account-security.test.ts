import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import vm from 'node:vm';
import ts from 'typescript';
import { isTrustedMutation } from '../account/server/src/request-source.js';

// Execute the complete actual route module with explicit synthetic dependencies.
// No application config, Redis connection, secrets, HTTP listener or SSO is loaded.
function loadApi(overrides: Record<string, unknown> = {}) {
  const routes: { method: string; path: string; handlers: Function[] }[] = [];
  let updates = 0, reads = 0;
  const session = { sub: 'fixture', ssoSid: 'master', claims: {}, accessToken: 'fixture', idToken: 'fixture',
    accessExpiresAt: Math.floor(Date.now() / 1000) + 900, amr: [], createdAt: 1 };
  const dependencies: Record<string, unknown> = {
    express: { Router: () => Object.fromEntries(['get', 'post', 'patch', 'delete', 'use'].map(method =>
      [method, (path: string, ...handlers: Function[]) => routes.push({ method, path, handlers })])), raw: () => (_req: unknown, _res: unknown, next: Function) => next() },
    '../session.js': { getSession: async () => { reads++; return session; }, updateSession: async () => { updates++; return true; } },
    '../config.js': { config: { internal: 'https://sso.invalid', publicUrl: 'https://account.example', redirectUri: '' } },
    '../oidc.js': { s2sAssertion: async () => 'synthetic' },
    '../s2sFetch.js': { s2sFetch: async () => { throw Error('unexpected upstream call'); } },
    './auth.js': { SESSION_COOKIE: 'acct_sid' }, '../request-source.js': { isTrustedMutation }, ...overrides,
  };
  const source = fs.readFileSync(new URL('../account/server/src/routes/api.ts', import.meta.url), 'utf8');
  const output = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } }).outputText;
  vm.runInNewContext(output, { exports: {}, require: (id: string) => { assert.ok(id in dependencies, id); return dependencies[id]; }, Buffer, Uint8Array, AbortSignal, Date, console });
  return { routes, session, updates: () => updates, reads: () => reads };
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
