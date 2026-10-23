import test from 'node:test';
import assert from 'node:assert/strict';
import { adminReturnPath } from '../src/adminReturnPath.js';

test('login and step-up return to recognized admin routes', () => {
  for (const path of ['/admin', '/admin/', '/admin/clients', '/admin/clients/new',
    '/admin/clients/example-app', '/admin/keys', '/admin/settings']) assert.equal(adminReturnPath(path), path);
  assert.equal(adminReturnPath('/admin/clients/example%2Dapp'), '/admin/clients/example-app');
});

test('untrusted next values cannot become cross-origin or non-admin redirects', () => {
  for (const input of [null, ['//evil.example'], 'https://evil.example', '//evil.example', '/\\evil.example',
    '/\t/evil.example', '/%5Cevil.example', '/admin/../outside', '/admin/%2e%2e/outside',
    '/admin/clients/%2f%2fevil.example', '/admin/clients/x%0a', '/admin/clients/x%255c',
    '/admin?next=https://evil.example', '/admin#fragment', '/admin/start-login', '/admin/%',
    '/admin/' + 'x'.repeat(600)]) {
    const next = adminReturnPath(input);
    assert.equal(next, '/admin');
    assert.equal(new URL(next, 'https://issuer.example.invalid').origin, 'https://issuer.example.invalid');
  }
});
