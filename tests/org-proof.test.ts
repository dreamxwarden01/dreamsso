import assert from 'node:assert/strict';
import test from 'node:test';
import { acceptedStrongStepup, stepupSatisfies, stepupStampFresh, stepupValidityMinutes } from '../src/oidc/stepupRules.js';

test('mandatory strong factor matrix preserves passkey precedence and rejects weak methods', () => {
  for (const [passkeys, totp, accepted] of [[0, 0, []], [0, 1, ['totp']], [1, 0, ['passkey']], [1, 1, ['passkey']]] as const) {
    const methods = acceptedStrongStepup(passkeys, totp);assert.deepEqual(methods, accepted);
    for (const weak of ['password', 'email', null]) assert.equal(stepupSatisfies(methods, weak, true), false);
    for (const method of methods) { assert.equal(stepupSatisfies(methods, method, true), true);assert.equal(stepupSatisfies(methods, method, false), false); }
  }
});

test('step-up window retains existing defaults, bounded settings and precise expiry', () => {
  for (const value of [null, undefined, '', '0', '1441', 'bad']) assert.equal(stepupValidityMinutes(value), 30);
  assert.equal(stepupValidityMinutes('1'), 1);assert.equal(stepupValidityMinutes('1440'), 1440);
  assert.equal(stepupStampFresh(null, 30, 2_000_000), false);
  assert.equal(stepupStampFresh(1000, 30, 2_799_999), true);
  assert.equal(stepupStampFresh(1000, 30, 2_800_000), false);
});
