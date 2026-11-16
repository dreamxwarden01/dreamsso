import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import { runInNewContext } from 'node:vm';
import ts from 'typescript';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import * as validation from '../src/oidc/clientAssertionValidation.js';
import { CodeRedemptionError } from '../src/oidc/codeRedemption.js';

async function isolated(relative: string, imports: Record<string, unknown>) {
  const text = await readFile(new URL('../src/' + relative, import.meta.url), 'utf8');
  const code = ts.transpileModule(text, { compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.CommonJS } }).outputText;
  const exports: Record<string, unknown> = {};
  runInNewContext(code, { exports, require: (name: string) => {
    if (!Object.hasOwn(imports, name)) throw Error('Unexpected isolated authentication import: ' + name);
    return imports[name];
  } }, { timeout: 1000, filename: relative });
  return exports;
}
function response() { return { statusCode: 200, body: undefined as unknown,
  setHeader() {}, status(value: number) { this.statusCode = value;return this; }, json(body: unknown) { this.body = body;return this; } }; }

test('actual token and internal assertion adapters share replay claims and preserve sanitized OAuth errors', async () => {
  const issuer = 'https://issuer.example.invalid';
  const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-route-fixture';
  const nonces = new Set<string>();let storageUnavailable = false, redeemed = 0;
  const config = { issuer, accountClientId: 'account' };
  const runtime = await isolated('oidc/clientAssertion.ts', {
    '../config.js': { config }, './clientAssertionValidation.js': validation,
    '../db.js': { pool: { query: async (sql: string, args: unknown[]) => {
      assert.equal(sql, 'SELECT client_id, jwks, jwks_uri, disabled_at FROM oauth_clients WHERE client_id = $1');
      assert.ok(['fixture-rp', 'account'].includes(args[0] as string));
      return { rows: [{ client_id: args[0], disabled_at: null, jwks: { keys: [jwk] }, jwks_uri: null }] };
    } } },
    '../clientKeys.js': { clientKeySet: () => createLocalJWKSet({ keys: [jwk] }) },
    '../redis.js': { redis: { set: async (key: string, value: string, ex: string, ttl: number, nx: string) => {
      assert.equal(ex, 'EX');assert.equal(nx, 'NX');assert.equal(value, '1');assert.ok(ttl > 0 && ttl <= 140);
      if (storageUnavailable) throw Error('synthetic secret-bearing storage details');
      if (nonces.has(key)) return null;nonces.add(key);return 'OK';
    } } },
  });
  type Verify = (body: Record<string, unknown>, operation: { method: string; path: string }) => Promise<string | null>;
  const assertedClient = runtime.assertedClient as Verify;
  const assertedPortal = runtime.assertedPortal as (body: Record<string, unknown>, operation: { method: string; path: string }) => Promise<boolean>;
  const handlers = new Map<string, (req: unknown, res: ReturnType<typeof response>) => Promise<unknown>>();
  const unused = () => { throw Error('Unexpected runtime service in isolated authentication test'); };
  await isolated('routes/token.ts', {
    express: { Router: () => ({ post: (path: string, handler: (req: unknown, res: ReturnType<typeof response>) => Promise<unknown>) => handlers.set(path, handler), get() {} }) },
    '../config.js': { config }, '../oidc/clientAssertion.js': { assertedClient }, '../oidc/clientAssertionValidation.js': validation,
    '../oidc/userinfo.js': { createUserinfoHandler: () => unused }, '../db.js': { pool: {} }, '../oidc/codes.js': { consumeCode: unused },
    '../oidc/sessions.js': { getSessionWindows: unused }, '../oidc/tokens.js': { mintIdToken: unused, mintAccessToken: unused },
    '../backchannel/accessStateStore.js': { readAccessStateSnapshot: unused }, '../keys.js': { getJwks: unused, getSigningKey: unused },
    '../settings.js': { getSetting: unused }, '../resourceAuth.js': { verifyAccessToken: unused }, '../oidc/codeRedemption.js': { CodeRedemptionError, redeemAuthorizationCode: async (input: { clientId: string }) => {
      assert.equal(input.clientId, 'fixture-rp');redeemed++;return { access_token: 'synthetic-output' };
    } },
  });
  const tokenHandler = handlers.get('/token');assert.ok(tokenHandler);
  const proof = async (client: string, path: string, jti: string) => {
    const now = Math.floor(Date.now() / 1000);
    return { client_assertion_type: validation.CLIENT_ASSERTION_TYPE,
      client_assertion: await new SignJWT({ method: 'POST', path }).setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
        .setIssuer(client).setSubject(client).setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60).setJti(jti).sign(keys.privateKey) };
  };
  const body = await proof('fixture-rp', '/token', 'route-one');
  const request = { method: 'POST', path: '/token', body: { grant_type: 'authorization_code', ...body } };
  const good = response();await tokenHandler(request, good);assert.equal(good.statusCode, 200);assert.equal(redeemed, 1);
  const replay = response();await tokenHandler(request, replay);assert.equal(replay.statusCode, 401);assert.equal(redeemed, 1);
  const wrongPath = response();await tokenHandler({ ...request, body: { grant_type: 'authorization_code', ...await proof('fixture-rp', '/internal/avatar', 'route-two') } }, wrongPath);
  assert.equal(wrongPath.statusCode, 401);assert.equal(redeemed, 1);
  storageUnavailable = true;
  const outage = response();await tokenHandler({ ...request, body: { grant_type: 'authorization_code', ...await proof('fixture-rp', '/token', 'route-three') } }, outage);
  assert.equal(outage.statusCode, 503);assert.equal((outage.body as { error: string }).error, 'temporarily_unavailable');assert.equal(redeemed, 1);
  assert.ok(!JSON.stringify(outage.body).includes('storage details'));
  await assert.rejects(assertedPortal(await proof('account', '/internal/token/renew', 'portal-outage'), { method: 'POST', path: '/internal/token/renew' }), validation.ClientAssertionUnavailable);
  storageUnavailable = false;
  assert.equal(await assertedPortal(await proof('account', '/internal/token/renew', 'portal-shared'), { method: 'POST', path: '/internal/token/renew' }), true);
  assert.equal(await assertedClient(await proof('account', '/internal/avatar', 'portal-shared'), { method: 'POST', path: '/internal/avatar' }), null);
  assert.equal(await assertedPortal(await proof('fixture-rp', '/internal/token/renew', 'not-portal'), { method: 'POST', path: '/internal/token/renew' }), false);
});
