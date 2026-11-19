import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import path from 'node:path';
import crypto from 'node:crypto';
import express from 'express';
import ts from 'typescript';

type JsonResponse = { status: number; body: unknown; headers: Record<string, string> };
const actor = '11111111-1111-4111-8111-111111111111', sessionId = '22222222-2222-4222-8222-222222222222';
const requestId = '33333333-3333-4333-8333-333333333333', client = 'fixture.app', csrf = 'synthetic-csrf';
const base = '/admin/api/clients/' + client + '/delivery';

async function compile(relative: string, imports: Record<string, unknown>) {
  const source = await readFile(new URL('../src/' + relative, import.meta.url), 'utf8');
  const code = ts.transpileModule(source, { compilerOptions: { target: ts.ScriptTarget.ES2022,
    module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
  const exports: Record<string, unknown> = {};
  runInNewContext(code, { exports, process: { cwd: () => '/fixture' }, console: { warn() {}, error() {} },
    require: (name: string) => { if (!Object.hasOwn(imports, name)) throw Error('Unexpected admin HTTP test import: ' + name);return imports[name]; } },
  { timeout: 1000, filename: relative });
  return exports;
}
async function deliveryProjection() {
  // Exercise the actual aggregate response projection. Its SQL provider is a
  // strict stub; role/outbox mutators and runtime modules are never imported.
  const text = await readFile(new URL('../src/events/clientDelivery.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('clientDelivery.ts', text, ts.ScriptTarget.Latest, true);
  const wanted = new Set(['ClientDeliveryError', 'count', 'readClientDelivery']);
  const selected = source.statements.filter(node =>
    ((ts.isClassDeclaration(node) || ts.isFunctionDeclaration(node)) && node.name && wanted.has(node.name.text))
    || (ts.isVariableStatement(node) && node.declarationList.declarations.some(decl => ts.isIdentifier(decl.name) && ['SUPERSEDED', 'OUTCOMES'].includes(decl.name.text))));
  assert.equal(selected.length, 5);
  const exports: Record<string, unknown> = {};
  runInNewContext(ts.transpileModule(selected.map(node => node.getText(source)).join('\n'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText,
  { exports }, { timeout: 1000 });
  return exports as { ClientDeliveryError: new (status: number, code: string) => Error;
    readClientDelivery: (db: unknown, client: string) => Promise<unknown> };
}
async function fixture() {
  const delivery = await deliveryProjection();
  const state = { authenticated: true, permitted: true, stepupRequired: true, fresh: true,
    recoveryError: undefined as unknown, readError: undefined as unknown };
  const calls = { reads: [] as string[], recoveries: [] as { client: string; actor: string; requestId: string }[], transactions: 0, kicks: 0, factors: 0 };
  const safeRecovery = { logout_requeued: 2, role_snapshots: 3, role_superseded: 4, other_retained: 1 };
  const privateMarker = 'synthetic-private-payload-marker';
  const pool = { query: async (sql: string, args: unknown[]) => {
    assert.ok(sql.startsWith('SELECT c.disabled_at,c.events_uri'));assert.deepEqual([...args], [client, 'superseded_by_reconcile']);
    return { rows: [{ disabled_at: null, events_uri: 'https://private-host.example.invalid/events', pending: '2', dead: '1', delivered: '7',
      last_outcome_code: privateMarker, last_outcome_at: '2026-01-01T00:00:00.000Z',
      payload: { sub: privateMarker, sid: privateMarker }, event_token: privateMarker, raw_error: privateMarker }] };
  } };
  const db = { fixture: true };
  const unused = () => { throw Error('Unexpected production dependency in admin delivery test'); };
  // Keep real Express routing, while assimilating cross-VM promises into the
  // host realm so Router receives the native Promise type it expects.
  const routerFactory = () => {
    const router = express.Router();
    for (const name of ['use', 'get', 'post', 'patch', 'put', 'delete'] as const) {
      const register = router[name].bind(router) as (...args: any[]) => unknown;
      (router as any)[name] = (...args: any[]) => register(...args.map(value => typeof value !== 'function' ? value
        : (req: unknown, res: unknown, next: unknown) => Promise.resolve(value(req, res, next))));
    }
    return router;
  };
  const imports: Record<string, unknown> = {
    'node:crypto': crypto, 'node:path': path, 'node:fs': { existsSync: unused, readFileSync: unused },
    express: { Router: routerFactory, static: () => (_req: unknown, _res: unknown, next: () => void) => next() },
    '../adminReturnPath.js': { adminReturnPath: unused }, '../db.js': { pool },
    '../redis.js': { redis: { get: async (key: string) => { assert.equal(key, 'admin:csrf:' + sessionId);return csrf; } } },
    '../config.js': { config: {} },
    '../oidc/sessions.js': { loadSession: async () => state.authenticated ? { sid: sessionId, userSub: actor, stepupAt: 1234, stepupMethod: 'passkey' } : null,
      isStepupFresh: async (value: number) => { assert.equal(value, 1234);return state.fresh; } },
    '../oidc/stepupPolicy.js': { acceptedStepupMethods: async (sub: string, mode: string) => {
      assert.equal(sub, actor);assert.equal(mode, 'strong-mandatory');calls.factors++;return { accepted: ['passkey'] };
    }, stepupSatisfies: (accepted: string[], method: string, fresh: boolean) => fresh && accepted.includes(method) },
    '../oidc/transactions.js': { createTxn: unused },
    '../rbac/index.js': { hasPerm: async (sub: string, permission: string) => { assert.equal(sub, actor);assert.equal(permission, 'org.siteSettings.sso');return state.permitted; } },
    '../mfa.js': { countAuthenticators: unused }, '../webauthn.js': { countPasskeys: unused },
    '../keys.js': { getJwks: unused, rotateSigningKey: unused, getSigningKey: unused, getSigningKeyStatus: unused },
    '../clientKeyStatus.js': { readClientKeyStatus: unused }, '../clientKeys.js': { verifyJwksUri: unused },
    jose: { SignJWT: class { constructor() { unused(); } } }, '../s2sFetch.js': { s2sFetch: unused }, '../mtls.js': {},
    '../views.js': { renderErrorPage: unused },
    '../clientNormalize.js': { normalizeHostname: unused, normalizePath: unused, normalizeSlug: unused, normalizeName: unused, composeUrl: unused, decomposeUrl: unused },
    '../settings.js': { getSetting: async (key: string) => { assert.equal(key, 'stepup_admin_required');return state.stepupRequired ? 'true' : 'false'; },
      setSetting: unused, setSecretSetting: unused, hasSetting: unused },
    '../events.js': { enqueueEvents: unused, kickDrain: () => { calls.kicks++; } },
    '../rbac/roleChanges.js': { withRoleTransaction: async (work: (connection: unknown) => Promise<unknown>) => { calls.transactions++;return work(db); } },
    '../events/clientDelivery.js': { ...delivery,
      readClientDelivery: async (database: unknown, id: string) => {
        assert.equal(database, pool);calls.reads.push(id);if (state.readError) throw state.readError;return delivery.readClientDelivery(database, id);
      },
      recoverClientDelivery: async (connection: unknown, id: string, sub: string, idempotency: string) => {
        assert.equal(connection, db);calls.recoveries.push({ client: id, actor: sub, requestId: idempotency });
        if (state.recoveryError) throw state.recoveryError;return safeRecovery;
      }, setClientEnabled: unused, reconcileChangedEndpoint: unused },
    '../email.js': { sendEmail: unused }, '../emailTemplates.js': { renderTestEmail: unused },
  };
  const module = await compile('routes/admin.ts', imports);
  const router = module.adminRouter as ReturnType<typeof express.Router>;
  const request = (method: string, url = base, body?: unknown, token?: string): Promise<JsonResponse> => new Promise((resolve, reject) => {
    const headers: Record<string, string> = {};if (token !== undefined) headers['x-csrf-token'] = token;
    const req = { method, url, originalUrl: url, headers, body };
    const res = { statusCode: 200, headers: {} as Record<string, string>, status(code: number) { this.statusCode = code;return this; },
      setHeader(key: string, value: string) { this.headers[key.toLowerCase()] = value;return this; },
      json(value: unknown) { resolve({ status: this.statusCode, body: JSON.parse(JSON.stringify(value)), headers: this.headers });return this; },
      end() { resolve({ status: this.statusCode, body: null, headers: this.headers });return this; } };
    router.handle(req as any, res as any, (error?: unknown) => error ? reject(error) : reject(Error('Unexpected unhandled admin delivery route')));
  });
  return { state, calls, request, delivery, privateMarker, safeRecovery };
}

test('admin session and permission guards prevent all delivery reads and recovery effects', async () => {
  const f = await fixture();
  for (const [authenticated, permitted, expected] of [[false, true, 401], [true, false, 403]] as const) {
    f.state.authenticated = authenticated;f.state.permitted = permitted;
    assert.equal((await f.request('GET')).status, expected);
    assert.equal((await f.request('POST', base + '/recover', { request_id: requestId }, csrf)).status, expected);
  }
  assert.deepEqual(f.calls.reads, []);assert.deepEqual(f.calls.recoveries, []);assert.equal(f.calls.transactions, 0);assert.equal(f.calls.kicks, 0);
});

test('metadata GET preserves existing stale-stepup read policy; recovery requires fresh stepup and CSRF', async () => {
  const f = await fixture();f.state.fresh = false;
  const read = await f.request('GET');assert.equal(read.status, 200);assert.equal(read.headers['cache-control'], 'no-store');assert.equal(f.calls.factors, 0);
  const stale = await f.request('POST', base + '/recover', { request_id: requestId }, csrf);
  assert.equal(stale.status, 403);assert.deepEqual(stale.body, { error: 'step_up_required' });
  f.state.fresh = true;
  for (const invalid of [undefined, 'wrong-csrf']) {
    const res = await f.request('POST', base + '/recover', { request_id: requestId }, invalid);
    assert.equal(res.status, 403);assert.deepEqual(res.body, { error: 'csrf_failed' });
  }
  assert.deepEqual(f.calls.recoveries, []);assert.equal(f.calls.transactions, 0);assert.equal(f.calls.kicks, 0);assert.equal(f.calls.reads.length, 1);
});

test('valid admin recovery forwards verified actor, selected client and request ID; exposes aggregates only', async () => {
  const f = await fixture();
  const res = await f.request('POST', base + '/recover', { request_id: requestId, requested_by: 'untrusted-body-actor', payload: f.privateMarker }, csrf);
  assert.equal(res.status, 200);assert.deepEqual(f.calls.recoveries, [{ client, actor, requestId }]);assert.equal(f.calls.transactions, 1);assert.equal(f.calls.kicks, 1);
  assert.deepEqual(res.body, { recovery: f.safeRecovery, delivery: { state: 'ready', counts: { pending: 2, paused: 0, dead: 1, delivered: 7 },
    last_outcome: { code: 'unknown_error', at: '2026-01-01T00:00:00.000Z' }, can_recover: true } });
  const json = JSON.stringify(res.body);
  for (const value of [f.privateMarker, 'private-host', 'payload', 'event_token', 'untrusted-body-actor']) assert.ok(!json.includes(value));
});

test('typed recovery conflicts and invalid request remain409/422; untrusted failures become fixed503', async () => {
  const f = await fixture();
  for (const [status, code] of [[409, 'client_disabled'], [409, 'no_events_endpoint'], [409, 'role_catalog_unavailable'],
    [409, 'recovery_context_mismatch'], [422, 'invalid_recovery_request']] as const) {
    f.state.recoveryError = new f.delivery.ClientDeliveryError(status, code);
    const res = await f.request('POST', base + '/recover', { request_id: status === 422 ? 123 : requestId }, csrf);
    assert.equal(res.status, status);assert.deepEqual(res.body, { error: code });
  }
  assert.equal(f.calls.recoveries.at(-1)?.requestId, '');assert.equal(f.calls.reads.length, 0);assert.equal(f.calls.kicks, 0);
  f.state.recoveryError = Object.assign(Error(f.privateMarker), { status: 409, code: f.privateMarker });
  const unknown = await f.request('POST', base + '/recover', { request_id: requestId }, csrf);
  assert.equal(unknown.status, 503);assert.deepEqual(unknown.body, { error: 'delivery_unavailable' });
  f.state.recoveryError = undefined;f.state.readError = Error(f.privateMarker);
  const read = await f.request('GET');assert.equal(read.status, 503);assert.deepEqual(read.body, { error: 'delivery_unavailable' });
  assert.ok(!JSON.stringify(unknown.body).includes(f.privateMarker));assert.ok(!JSON.stringify(read.body).includes(f.privateMarker));
});
