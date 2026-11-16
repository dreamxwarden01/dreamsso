import assert from 'node:assert/strict';
import test from 'node:test';
import type { Request, Response } from 'express';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';
import { createAccountResourceAuth, accountResourceError, type AuthedRequest } from '../src/accountResourceAuth.js';
import { createUserinfoHandler } from '../src/oidc/userinfo.js';
import { scopesAllowed } from '../src/oidc/scopes.js';

const issuer = 'https://sso.example.invalid', sub = '11111111-1111-4111-8111-111111111111';
const sid = '22222222-2222-4222-8222-222222222222';
const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-fixture';
const jwks = { keys: [jwk] };
const auth = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => 'account', jwks: async () => jwks, readState: async () => 'active' });
async function sign(client: string | null, options: { scope?: string; typ?: string; expired?: boolean } = {}) {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT({ sid, scope: options.scope ?? 'openid profile email', ...(client === null ? {} : { client_id: client }) })
    .setProtectedHeader({ alg: 'EdDSA', typ: options.typ ?? 'at+jwt', kid: jwk.kid }).setIssuer(issuer)
    .setAudience(issuer).setSubject(sub).setIssuedAt(now - 60).setExpirationTime(now + (options.expired ? -1 : 600)).sign(keys.privateKey);
}
function response() {
  return { statusCode: 200, body: undefined as unknown, headers: {} as Record<string, string>,
    status(value: number) { this.statusCode = value;return this; },
    set(name: string, value: string) { this.headers[name] = value;return this; },
    setHeader(name: string, value: string) { this.headers[name] = value;return this; },
    json(value: unknown) { this.body = value;return this; } };
}
async function account(token?: string) {
  const req = { headers: token ? { authorization: 'Bearer ' + token } : {} } as AuthedRequest;
  const res = response();let next = false;
  await auth.requireScope('profile')(req, res as unknown as Response, () => { next = true; });
  return { req, res, next };
}

test('ordinary RP access token remains valid at userinfo but cannot cross Account resources', async () => {
  const token = await sign('ordinary-rp');
  const denied = await account(token);assert.equal(denied.res.statusCode, 403);assert.equal(denied.next, false);
  assert.deepEqual(denied.res.body, { error: 'client_not_allowed' });
  const profile = createUserinfoHandler({ verifyAccessToken: auth.verifyAccessToken,
    profile: async subject => { assert.equal(subject, sub);return { sub, username: 'fixture', display_name: 'Fixture',
      email: 'fixture@example.invalid', email_verified: true, avatar: null }; } });
  const res = response();await profile({ headers: { authorization: 'Bearer ' + token } } as Request, res as unknown as Response);
  assert.equal(res.statusCode, 200);assert.deepEqual(res.body, { sub, name: 'Fixture', preferred_username: 'fixture', email: 'fixture@example.invalid', email_verified: true });
});

test('current Account token shape remains compatible; missing grant and scope are authorization denials', async () => {
  const admitted = await account(await sign('account'));assert.equal(admitted.next, true);assert.equal(admitted.req.auth?.clientId, 'account');
  // Current tokens retain the resource client grant and now bind their original SID.
  const missingClient = await account(await sign(null));assert.equal(missingClient.res.statusCode, 401);
  const scope = await account(await sign('account', { scope: 'openid email' }));assert.equal(scope.res.statusCode, 403);assert.deepEqual(scope.res.body, { error: 'insufficient_scope', error_description: 'profile scope required' });
  assert.equal(accountResourceError({ sub, scopes: ['profile'], clientId: 'ordinary-rp' }, 'profile', 'account'), 'client_not_allowed');
});

test('missing, malformed, expired and wrong token type remain authentication failures', async () => {
  for (const token of [undefined, 'malformed', await sign('account', { expired: true }), await sign('account', { typ: 'JWT' })]) {
    const result = await account(token);assert.equal(result.next, false);assert.equal(result.res.statusCode, 401);
  }
});

test('registered scopes must include openid and cover every requested scope at authorize and redemption', () => {
  assert.equal(scopesAllowed('openid profile email', ['openid', 'profile', 'email']), true);
  assert.equal(scopesAllowed('openid', ['openid']), true);
  for (const [requested, allowed] of [['openid profile', ['openid']], ['profile', ['profile']], ['openid admin', ['openid', 'profile']], ['openid', null], ['openid', ['openid', 1]]]) {
    assert.equal(scopesAllowed(requested as string, allowed), false);
  }
});

test('actual portal renewal route and minter issue tokens accepted by the configured Account gate', async () => {
  // Compile the actual route/minter with an explicit import allowlist. Real
  // config, key storage, Redis, Express listeners and database modules cannot load.
  const [{ readFile }, vm, ts, jose] = await Promise.all([
    import('node:fs/promises'), import('node:vm'), import('typescript'), import('jose'),
  ]);
  const config = { issuer, accountClientId: 'custom-account-client' };
  async function isolatedModule(relative: string, imports: Record<string, unknown>) {
    const text = await readFile(new URL('../src/' + relative, import.meta.url), 'utf8');
    const compiled = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022,
      module: ts.ModuleKind.CommonJS, esModuleInterop: true } }).outputText;
    const exports: Record<string, unknown> = {};
    vm.runInNewContext(compiled, { exports, require: (name: string) => {
      if (!Object.hasOwn(imports, name)) throw Error('Unexpected runtime import in isolated renewal test: ' + name);
      return imports[name];
    } }, { timeout: 1000, filename: relative });
    return exports;
  }
  let mintCalls = 0;
  const actualTokens = await isolatedModule('oidc/tokens.ts', {
    jose, '../config.js': { config }, '../keys.js': { getSigningKey: async () => {
      mintCalls++;return { kid: jwk.kid, privateKey: keys.privateKey, publicJwk: jwk };
    } },
  });
  let handler: ((req: Request, res: Response) => Promise<unknown>) | undefined;
  let validClient = true, live = true;
  await isolatedModule('routes/portalToken.ts', {
    express: { Router: () => ({ post: (path: string, route: typeof handler) => {
      assert.equal(path, '/internal/token/renew');handler = route;
    } }) },
    '../config.js': { config }, '../oidc/tokens.js': actualTokens,
    '../oidc/sessions.js': { loadSessionBySid: async (sid: string) => {
      assert.equal(sid, '22222222-2222-4222-8222-222222222222');return live ? { userSub: sub, sid } : null;
    } },
    '../oidc/clientAssertion.js': { assertedPortal: async () => validClient },
  });
  assert.ok(handler);
  const req = { method: 'POST', path: '/internal/token/renew', body: { sid, sub } } as Request;
  const renewed = response();await handler(req, renewed as unknown as Response);
  assert.equal(renewed.statusCode, 200);
  const body = renewed.body as { access_token: string; expires_in: number };
  assert.equal(body.expires_in, 900);assert.equal(mintCalls, 1);
  const verified = await jose.jwtVerify(body.access_token, jose.createLocalJWKSet(jwks), { issuer, audience: issuer, typ: 'at+jwt' });
  assert.equal(verified.payload.client_id, config.accountClientId);
  assert.equal(verified.payload.exp! - verified.payload.iat!, 900);
  const gate = createAccountResourceAuth({ issuer: () => issuer, accountClientId: () => config.accountClientId, jwks: async () => jwks, readState: async () => 'active' });
  let next = false;const res = response();
  await gate.requireScope('profile')({ headers: { authorization: 'Bearer ' + body.access_token } } as AuthedRequest,
    res as unknown as Response, () => { next = true; });
  assert.equal(next, true);

  for (const state of ['invalid-client', 'dead-session', 'wrong-owner'] as const) {
    validClient = state !== 'invalid-client';live = state !== 'dead-session';
    const denied = response();await handler({ body: { sid, sub: state === 'wrong-owner' ? 'another-subject' : sub } } as Request,
      denied as unknown as Response);
    assert.equal(denied.statusCode, 401);assert.equal(mintCalls, 1);
  }
});
