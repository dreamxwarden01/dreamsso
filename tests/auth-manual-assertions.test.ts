import assert from 'node:assert/strict';
import test from 'node:test';
import { readFile } from 'node:fs/promises';
import ts from 'typescript';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT } from 'jose';
import { createClientAssertionVerifier, CLIENT_ASSERTION_TYPE } from '../src/oidc/clientAssertionValidation.js';

const consumers: Record<string, string> = {
  'scripts/verify-login.mjs': '/token', 'scripts/sso-admin-test.ts': '/token', 'scripts/sso-key-rotation-test.ts': '/token',
  'scripts/sso-kmsi-test.ts': '/token', 'scripts/sso-mfa-email-test.ts': '/token', 'scripts/sso-mfa-totp-test.ts': '/token',
  'scripts/sso-org-admin-test.ts': '/token', 'scripts/sso-org-test.ts': '/token', 'scripts/sso-passkey-login-test.ts': '/token',
  'scripts/sso-perms-enforce-test.ts': '/token', 'scripts/sso-session-reuse-test.mjs': '/token', 'scripts/sso-stepup-test.ts': '/token',
  'scripts/sso-devices-test.mjs': '/token', 'scripts/sso-activity-test.ts': '/internal/session-activity',
  'scripts/sso-avatar-test.ts': '/internal/avatar', 'scripts/sso-client-key-rotation-test.ts': '/internal/avatar', 'dev-rp/server.mjs': '/token',
};

test('manual/developer assertion declarations bind their intended operation without executing test flows', async () => {
  const keys = await generateKeyPair('EdDSA'), jwk = await exportJWK(keys.publicKey);jwk.kid = 'generated-manual-contract-key';
  const now = Math.floor(Date.now() / 1000), issuer = 'https://issuer.example.invalid';
  const seen = new Set<string>();
  const verify = createClientAssertionVerifier({ issuer: () => issuer,
    loadClient: async id => ({ client_id: id, disabled_at: null }), keySet: () => createLocalJWKSet({ keys: [jwk] }),
    claimNonce: async key => { if (seen.has(key)) return false;seen.add(key);return true; },
  });
  for (const [relative, path] of Object.entries(consumers)) {
    const text = await readFile(new URL('../' + relative, import.meta.url), 'utf8');
    const source = ts.createSourceFile(relative, text, ts.ScriptTarget.Latest, true, relative.endsWith('.ts') ? ts.ScriptKind.TS : ts.ScriptKind.JS);
    const declarations: ts.ObjectLiteralExpression[] = [];
    const visit = (node: ts.Node) => {
      if (ts.isNewExpression(node) && ts.isIdentifier(node.expression) && node.expression.text === 'SignJWT'
        && node.arguments?.length === 1 && ts.isObjectLiteralExpression(node.arguments[0])) {
        // These entrypoints declare the client proof first; later constructors
        // are distinct rotate/event protocols and must not be rewritten.
        declarations.push(node.arguments[0]);
      }
      ts.forEachChild(node, visit);
    };
    visit(source);assert.ok(declarations.length, relative);
    const values: Record<string, string> = {};
    for (const property of declarations[0].properties) {
      assert.ok(ts.isPropertyAssignment(property) && ts.isIdentifier(property.name) && ts.isStringLiteral(property.initializer), relative);
      values[property.name.text] = property.initializer.text;
    }
    assert.deepEqual(values, { method: 'POST', path }, relative);
    const compiled = ts.transpileModule(text, { reportDiagnostics: true,
      compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext } });
    assert.equal((compiled.diagnostics ?? []).filter(item => item.category === ts.DiagnosticCategory.Error).length, 0, relative);
    const token = await new SignJWT(values).setProtectedHeader({ alg: 'EdDSA', kid: jwk.kid })
      .setIssuer('manual-fixture').setSubject('manual-fixture').setAudience(issuer).setIssuedAt(now).setExpirationTime(now + 60).setJti(relative).sign(keys.privateKey);
    assert.equal(await verify({ client_assertion_type: CLIENT_ASSERTION_TYPE, client_assertion: token }, { method: 'POST', path }), 'manual-fixture', relative);
  }
});
