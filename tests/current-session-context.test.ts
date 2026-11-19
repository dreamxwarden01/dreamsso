import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import type { Request, Response } from 'express';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createAccountResourceAuth, accountResourceError, type AuthedRequest } from '../src/accountResourceAuth.js';
import { currentSessionContextError, requireCurrentSessionContext, SESSION_CONTEXT_MISMATCH } from '../src/oidc/currentSession.js';
import { stepupSatisfies, acceptedStrongStepup, stepupStampFresh, stepupValidityMinutes } from '../src/oidc/stepupRules.js';

const issuer = 'https://issuer.example.invalid', sub = '11111111-1111-4111-8111-111111111111';
const current = '22222222-2222-4222-8222-222222222222', sameUser = '33333333-3333-4333-8333-333333333333', foreign = '44444444-4444-4444-8444-444444444444';
const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-context-key';
let live = true;
const auth = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => 'account', jwks: async () => ({ keys: [jwk] }),
  readState: async identity => { assert.equal(identity.sid, current);return live ? 'active' : 'session_gone'; } });
async function token(expired = false) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ scope: 'openid profile', client_id: 'account', sid: current })
    .setProtectedHeader({ alg: 'EdDSA', typ: 'at+jwt', kid: jwk.kid }).setIssuer(issuer).setAudience(issuer).setSubject(sub)
    .setIssuedAt(now - 60).setExpirationTime(now + (expired ? -1 : 600)).sign(keys.privateKey);
}
function response() { return { statusCode: 200, body: undefined as unknown,
  status(n: number) { this.statusCode = n;return this; }, set() { return this; }, json(body: unknown) { this.body = JSON.parse(JSON.stringify(body));return this; } }; }
async function verified(extra: Record<string, unknown> = {}, expired = false) {
  const req = { ...extra, headers: { authorization: 'Bearer ' + await token(expired), ...extra.headers as object } } as AuthedRequest;
  const res = response();let next = false;
  await auth.requireScope('profile')(req, res as unknown as Response, () => { next = true; });
  return { req, res, next };
}

// Execute original named gate bodies with explicit synthetic dependencies. No
// route module, environment, Redis, pool or credential file can be imported.
async function functions(relative: string, names: string[], globals: Record<string, unknown>) {
  const text = await readFile(new URL('../src/' + relative, import.meta.url), 'utf8');
  const source = ts.createSourceFile(relative, text, ts.ScriptTarget.Latest, true);
  const bodies = source.statements.filter(node => ts.isFunctionDeclaration(node) && node.name && names.includes(node.name.text));
  assert.equal(bodies.length, names.length, relative);
  const js = ts.transpileModule(bodies.map(node => node.getText(source)).join('\n') + '\nglobalThis.selected={' + names.join(',') + '};',
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const context = { ...globals, exports: {}, selected: {} as Record<string, (...args: any[]) => any> };
  runInNewContext(js, context, { timeout: 1000, filename: relative });return context.selected;
}

test('verified current SID is required for header, status/body and keep-SID contexts; expired auth remains401', async () => {
  for (const select of [(req: AuthedRequest) => req.headers['x-stepup-sid'], (req: AuthedRequest) => req.query.sid,
    (req: AuthedRequest) => req.body.sid, (req: AuthedRequest) => req.body.keep_sid]) {
    for (const sid of [current, sameUser, foreign, undefined]) {
      const f = await verified({ headers: { 'x-stepup-sid': sid }, query: { sid }, body: { sid, keep_sid: sid } });
      assert.equal(f.next, true);let admitted = false;
      requireCurrentSessionContext(select)(f.req, f.res as unknown as Response, () => { admitted = true; });
      assert.equal(admitted, sid === current);
      if (!admitted) { assert.equal(f.res.statusCode, 403);assert.deepEqual(f.res.body, { error: SESSION_CONTEXT_MISMATCH }); }
    }
  }
  const expired = await verified({ body: { sid: current } }, true);assert.equal(expired.next, false);assert.equal(expired.res.statusCode, 401);
  live = false;
  try { const gone = await verified({ body: { sid: current } });assert.equal(gone.next, false);assert.equal(gone.res.statusCode, 401); }
  finally { live = true; }
  const canonical = 'abcdefab-cdef-4abc-8def-abcdefabcdef';
  assert.equal(currentSessionContextError({ sid: canonical }, canonical.toUpperCase()), null);
  assert.equal(currentSessionContextError({ sid: current }, undefined, false), null);
  assert.equal(currentSessionContextError({ sid: current }, '', false), SESSION_CONTEXT_MISMATCH);
});

test('security and email gates cannot borrow a same-user fresh session stamp', async () => {
  let lookups = 0;
  const globals = { currentSessionContextError, pool: { query: async () => {
    lookups++;return { rows: [{ user_sub: sub, stepup_at: String(Date.now() / 1000), stepup_method: 'totp' }] };
  } }, acceptedStepupMethods: async () => ({ accepted: ['totp'] }), isStepupFresh: async () => true, stepupSatisfies,
  qstr: (value: unknown) => typeof value === 'string' ? value : '', STEPUP_MAX_S: 600 };
  const security = await functions('routes/security.ts', ['requireSecurityStepup'], globals);
  const email = await functions('routes/emailChangeRoutes.ts', ['requireFreshStepup'], globals);
  for (const selected of [current, sameUser, foreign, undefined]) {
    const f = await verified({ headers: { 'x-stepup-sid': selected } });assert.equal(f.next, true);
    const before = lookups;let admitted = false;
    await security.requireSecurityStepup(600)(f.req, f.res, () => { admitted = true; });assert.equal(admitted, selected === current);
    const res = response();assert.equal(await email.requireFreshStepup({ sub }, f.req, res), selected === current);
    if (selected !== current) { assert.equal(lookups, before);assert.equal(f.res.statusCode, 403);assert.equal(res.statusCode, 403); }
  }
});

test('optional org stepup keeps absent-header policy while binding every supplied current context', async () => {
  let required = false, factorChecks = 0;
  const org = await functions('routes/org.ts', ['orgStepupError', 'requireFreshStepup'], {
    currentSessionContextError, getSetting: async () => required ? 'true' : 'false', qstr: (value: unknown) => typeof value === 'string' ? value : '',
    pool: { query: async () => ({ rows: [{ user_sub: sub, stepup_at: String(Date.now() / 1000), stepup_method: 'totp' }] }) },
    acceptedStepupMethods: async () => { factorChecks++;return { accepted: ['totp'] }; }, isStepupFresh: async () => true, stepupSatisfies,
  });
  for (const enabled of [false, true]) {
    required = enabled;
    for (const selected of [current, sameUser, undefined]) {
      const f = await verified({ headers: { 'x-stepup-sid': selected } });let admitted = false;
      await org.requireFreshStepup(f.req, f.res, () => { admitted = true; });
      assert.equal(admitted, selected === current || (!enabled && selected === undefined));
      if (!admitted) assert.deepEqual(f.res.body, { error: SESSION_CONTEXT_MISMATCH });
    }
    if (!enabled) assert.equal(factorChecks, 0, 'disabled policy must not introduce a new factor challenge');
  }
});

test('transactional org proof binds freshly verified SID rather than the retained middleware object', async () => {
  class ProofError extends Error { constructor(readonly status: number, readonly body: { error: string }) { super(body.error); } }
  let required = true;
  const db = { query: async (sql: string) => {
    if (sql.startsWith('SELECT key,value')) return { rows: [{ key: 'stepup_portal_required', value: required ? 'true' : 'false' }] };
    if (sql.startsWith('SELECT user_sub')) return { rows: [{ user_sub: sub, stepup_at: String(Date.now() / 1000), stepup_method: 'totp' }] };
    if (sql.includes('COUNT(*)')) return { rows: [{ passkeys: 0, totp: 1 }] };
    throw Error('Unexpected proof storage operation');
  } };
  const proof = await functions('rbac/orgProof.ts', ['assertOrgRoleProof'], { currentSessionContextError,
    verifyAccessToken: auth.verifyAccessToken, accountResourceError, config: { accountClientId: 'account' }, RoleAccessError: ProofError,
    acceptedStrongStepup, stepupSatisfies, stepupStampFresh, stepupValidityMinutes });
  const good = await verified({ headers: { 'x-stepup-sid': current } });await proof.assertOrgRoleProof(db, good.req);
  const wrong = await verified({ headers: { 'x-stepup-sid': sameUser } });wrong.req.auth!.sid = sameUser;
  await assert.rejects(proof.assertOrgRoleProof(db, wrong.req), (error: unknown) => error instanceof ProofError && error.status === 403 && error.body.error === SESSION_CONTEXT_MISMATCH);
  required = false;const absent = await verified();await proof.assertOrgRoleProof(db, absent.req);
  await assert.rejects(proof.assertOrgRoleProof(db, wrong.req), (error: unknown) => error instanceof ProofError && error.status === 403);
});

test('actual session routes bind keep_sid but leave explicitly selected target deletion independent', async () => {
  const text = await readFile(new URL('../src/routes/devices.ts', import.meta.url), 'utf8');
  const js = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const routes = new Map<string, ((...args: any[]) => any)[]>(), effects: unknown[] = [];
  const noop = () => {};
  const imports: Record<string, unknown> = {
    '../oidc/currentSession.js': { requireCurrentSessionContext }, express: { Router: () => ({ get: noop,
      post: (path: string, ...handlers: ((...args: any[]) => any)[]) => routes.set('POST ' + path, handlers),
      delete: (path: string, ...handlers: ((...args: any[]) => any)[]) => routes.set('DELETE ' + path, handlers) }) },
    '../db.js': { pool: {} }, '../config.js': { config: { accountClientId: 'account' } }, '../resourceAuth.js': { requireScope: auth.requireScope },
    '../rbac/index.js': { requirePerm: () => (_req: unknown, _res: unknown, next: () => void) => next() },
    '../oidc/backchannel.js': { revokeSessionSet: async (selection: unknown) => { effects.push(JSON.parse(JSON.stringify(selection)));return 1; } },
    '../oidc/sessions.js': { getSessionWindows: noop, hoursAgo: noop }, '../deviceName.js': { parseDevice: noop },
  };
  runInNewContext(js, { exports: {}, require: (name: string) => { assert.ok(Object.hasOwn(imports, name), name);return imports[name]; } }, { timeout: 1000 });
  async function invoke(route: string, req: AuthedRequest) {
    const handlers = routes.get(route);assert.ok(handlers);const res = { ...response(), end() { return this; } };
    for (const handler of handlers) { let next = false;await handler(req, res, () => { next = true; });if (!next) break; }return res;
  }
  const base = { headers: { authorization: 'Bearer ' + await token() } };
  for (const keep of [sameUser, foreign, undefined]) {
    const res = await invoke('POST /account/sessions/terminate-others', { ...base, body: { keep_sid: keep } } as AuthedRequest);
    assert.equal(res.statusCode, 403);assert.deepEqual(res.body, { error: SESSION_CONTEXT_MISMATCH });
  }
  assert.equal(effects.length, 0);
  assert.equal((await invoke('POST /account/sessions/terminate-others', { ...base, body: { keep_sid: current } } as AuthedRequest)).statusCode, 204);
  assert.deepEqual(effects[0], { subject: sub, exceptSid: current });
  assert.equal((await invoke('DELETE /account/sessions/:sid', { ...base, params: { sid: sameUser } } as AuthedRequest)).statusCode, 204);
  assert.deepEqual(effects[1], { subject: sub, sid: sameUser });
});

test('actual stepup registrations enforce current query/body SID before any factor handler', async () => {
  const text = await readFile(new URL('../src/routes/stepup.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('stepup.ts', text, ts.ScriptTarget.Latest, true);
  const declarations = source.statements.filter(node => ts.isVariableStatement(node) && node.declarationList.declarations.some(item =>
    ts.isIdentifier(item.name) && ['scoped', 'currentQuery', 'currentBody'].includes(item.name.text)));
  const registrations = source.statements.filter(node => ts.isExpressionStatement(node) && ts.isCallExpression(node.expression)
    && ts.isPropertyAccessExpression(node.expression.expression) && node.expression.expression.expression.getText(source) === 'stepupRouter');
  assert.equal(registrations.length, 4);
  const handlers = new Map<string, ((...args: any[]) => any)[]>();
  const router = { get: (path: string, ...chain: ((...args: any[]) => any)[]) => handlers.set('GET ' + path, chain),
    post: (path: string, ...chain: ((...args: any[]) => any)[]) => handlers.set('POST ' + path, chain) };
  const js = ts.transpileModule([...declarations, ...registrations].map(node => node.getText(source)).join('\n'),
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  runInNewContext(js, { stepupRouter: router, requireScope: auth.requireScope, requireCurrentSessionContext }, { timeout: 1000 });
  for (const [route, chain] of handlers) {
    for (const sid of [current, sameUser, foreign, undefined]) {
      const req = { headers: { authorization: 'Bearer ' + await token() }, query: { sid }, body: { sid } } as AuthedRequest;
      const res = response();let admitted = true;
      for (const gate of chain.slice(0, -1)) { let next = false;await gate(req, res, () => { next = true; });if (!next) { admitted = false;break; } }
      assert.equal(admitted, sid === current, route);
      if (!admitted) assert.equal(res.statusCode, 403);
    }
  }
});

test('normal BFF callbacks supply their stored SID to the new caller-context checks', async () => {
  const text = await readFile(new URL('../account/server/src/routes/api.ts', import.meta.url), 'utf8');
  const source = ts.createSourceFile('api.ts', text, ts.ScriptTarget.Latest, true);
  const wanted = new Map([
    ['POST /api/security/mfa/enable', 'header'], ['POST /api/stepup/verify', 'body'], ['POST /api/stepup/passkey-options', 'body'],
    ['POST /api/stepup/send-email', 'body'], ['POST /api/sessions/terminate-others', 'keep'], ['GET /api/stepup/status', 'query'],
  ]);
  const callbacks: string[] = [];
  for (const node of source.statements) {
    if (!ts.isExpressionStatement(node) || !ts.isCallExpression(node.expression)) continue;
    const call = node.expression;
    if (!ts.isPropertyAccessExpression(call.expression) || call.expression.expression.getText(source) !== 'apiRouter'
      || !call.arguments.length || !ts.isStringLiteral(call.arguments[0])) continue;
    const route = call.expression.name.text.toUpperCase() + ' ' + call.arguments[0].text;
    if (wanted.has(route)) callbacks.push(JSON.stringify(route) + ':' + call.arguments.at(-1)!.getText(source));
  }
  assert.equal(callbacks.length, wanted.size);
  const requests: { url: string; init: { headers: Record<string, string>; body?: string } }[] = [];
  const forwards = await functions('../account/server/src/routes/api.ts', ['forward', 'forwardOrg'], {
    config: { internal: 'https://issuer.example.invalid' }, s2sFetch: async (url: string, init: { headers: Record<string, string>; body?: string }) => {
      requests.push({ url, init });return { status: 204, json: async () => ({}) };
    }, console: { error() {} },
  });
  const script = ts.transpileModule('globalThis.callbacks={' + callbacks.join(',') + '};',
    { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const context = { ...forwards, callbacks: {} as Record<string, (...args: any[]) => any>,
    config: { internal: 'https://issuer.example.invalid' }, console: { error() {} }, s2sFetch: async (url: string, init: { headers: Record<string, string>; body?: string }) => {
      requests.push({ url, init });return { status: 200, json: async () => ({}) };
    } };
  runInNewContext(script, context, { timeout: 1000 });
  const bearer = await token();
  for (const [route, selector] of wanted) {
    const req = { session: { sub, ssoSid: current, accessToken: bearer, accessExpiresAt: Math.floor(Date.now() / 1000) + 600 },
      body: { sid: sameUser, keep_sid: sameUser, method: 'totp' }, query: { sid: sameUser } };
    const res = { ...response(), end() { return this; } };
    await context.callbacks[route](req, res);
    const request = requests.pop();assert.ok(request, route);
    const body = request.init.body ? JSON.parse(request.init.body) : {};
    const selected = selector === 'header' ? request.init.headers['x-stepup-sid'] : selector === 'keep' ? body.keep_sid
      : selector === 'query' ? new URL(request.url).searchParams.get('sid') : body.sid;
    const verifiedAuth = await auth.verifyAccessToken({ headers: { authorization: request.init.headers.authorization } } as Request);
    assert.equal(currentSessionContextError(verifiedAuth ?? undefined, selected), null, route);
    assert.equal(selected, current, route);
  }
});
