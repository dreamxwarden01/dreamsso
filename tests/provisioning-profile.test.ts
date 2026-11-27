import test from 'node:test';
import assert from 'node:assert/strict';
import { provisioningProfile, type ProvisioningIdentity } from '../src/rbac/provisioningProfile.js';

const sub = '12345678-1234-1234-1234-123456789abc';
const identity: ProvisioningIdentity = { user_sub: sub, username: 'sample', display_name: 'Sample User',
  avatar: `${sub}-0123456789abcdef.webp`, email: 'sample@example.invalid', email_verified: true };

test('provisioning claims follow destination scopes as complete groups', () => {
  const profile = { preferred_username: identity.username, name: identity.display_name, picture: identity.avatar };
  const email = { email: identity.email, email_verified: true };
  assert.deepEqual(provisioningProfile(identity, ['openid', 'profile', 'email']), { ...profile, ...email });
  assert.deepEqual(provisioningProfile(identity, ['profile']), profile);
  assert.deepEqual(provisioningProfile(identity, ['email']), email);
  assert.deepEqual(provisioningProfile(identity, ['openid']), {});
  assert.deepEqual(provisioningProfile(identity, []), {});
});

test('explicitly absent avatar and email are retained, not invented or omitted', () => {
  assert.deepEqual(provisioningProfile({ ...identity, avatar: null, email: null, email_verified: false }, ['profile', 'email']),
    { preferred_username: 'sample', name: 'Sample User', picture: null, email: null, email_verified: false });
});

test('invalid historical metadata drops only its group without leaking values or truncating identifiers', () => {
  const invalid: Partial<ProvisioningIdentity>[] = [
    { username: '' }, { username: 'x'.repeat(21) }, { username: null }, { username: '   ' },
    { display_name: '' }, { display_name: 'x'.repeat(101) },
    { display_name: 'name\u0000' }, { display_name: 'name\n' }, { display_name: 'name\u007f' },
    { display_name: 'name\ud800' }, { display_name: 'name\udfff' },
    { avatar: 'https://private.example.invalid/image.webp' },
    { avatar: '00000000-1234-1234-1234-123456789abc-0123456789abcdef.webp' },
    { avatar: `${sub}-0123456789abcdef.webp/../file` },
    { email: '' }, { email: 'x'.repeat(255) }, { email: '\t' }, { email: 'a\r@example.invalid' }, { email_verified: 'true' },
  ];
  for (const value of invalid) {
    const reports: unknown[][] = [];
    const expected = Object.hasOwn(value, 'email') || Object.hasOwn(value, 'email_verified')
      ? { preferred_username: identity.username, name: identity.display_name, picture: identity.avatar }
      : { email: identity.email, email_verified: identity.email_verified };
    assert.deepEqual(provisioningProfile({ ...identity, ...value }, ['profile', 'email'], (...args: unknown[]) => reports.push(args)), expected);
    assert.deepEqual(reports, [[]]);
  }
});

test('all invalid selected groups retain an empty creation seed', () => {
  const reports: unknown[][] = [];
  assert.deepEqual(provisioningProfile({ ...identity, username: '', email: '' }, ['profile', 'email'],
    (...args: unknown[]) => reports.push(args)), {});
  assert.deepEqual(reports, [[], []]);
});

test('malformed scope storage exposes no claims and cannot abort provisioning', () => {
  for (const scopes of [null, undefined, 'profile', {}, 42, ['profile', null]]) {
    const reports: unknown[][] = [];
    assert.deepEqual(provisioningProfile(identity, scopes, (...args: unknown[]) => reports.push(args)), {});
    assert.deepEqual(reports, [[]]);
  }
});

test('unpermitted claims are not consulted, validated or exposed', () => {
  let reports = 0;
  assert.deepEqual(provisioningProfile({ ...identity, avatar: 'invalid', username: null }, ['email'], () => { reports++; }),
    { email: identity.email, email_verified: true });
  assert.deepEqual(provisioningProfile({ ...identity, email: 'x'.repeat(255), email_verified: null }, ['profile'], () => { reports++; }),
    { preferred_username: identity.username, name: identity.display_name, picture: identity.avatar });
  assert.equal(reports, 0);
});

test('wire upper bounds are inclusive', () => {
  assert.deepEqual(provisioningProfile({ ...identity, username: 'u'.repeat(20), display_name: 'n'.repeat(100), email: 'e'.repeat(254) }, ['profile', 'email']),
    { preferred_username: 'u'.repeat(20), name: 'n'.repeat(100), picture: identity.avatar, email: 'e'.repeat(254), email_verified: true });
});

test('wire length counts Unicode code points and never normalizes valid text', () => {
  const name = '😀'.repeat(100), username = 'é'.repeat(20), email = '📧'.repeat(254);
  assert.deepEqual(provisioningProfile({ ...identity, username, display_name: name, email }, ['profile', 'email']),
    { preferred_username: username, name, picture: identity.avatar, email, email_verified: true });
  const report = () => {};
  assert.deepEqual(provisioningProfile({ ...identity, display_name: name + '😀' }, ['profile'], report), {});
  const spaced = { ...identity, username: ' sample ', display_name: ' Sample User ', email: ' sample@example.invalid ' };
  assert.deepEqual(provisioningProfile(spaced, ['profile', 'email']), { preferred_username: spaced.username,
    name: spaced.display_name, picture: identity.avatar, email: spaced.email, email_verified: true });
});

test('diagnostic failure cannot turn malformed optional metadata into an authority failure', () => {
  assert.deepEqual(provisioningProfile({ ...identity, username: '' }, ['profile'], () => { throw Error('diagnostic unavailable'); }), {});
});
