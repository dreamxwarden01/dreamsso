import test from 'node:test';
import assert from 'node:assert/strict';
import { normalizeClientErrors, activeClientErrors, hasBlockingClientErrors,
  removeRedirectErrors, clientErrorsForDisplay, clearEditedServerErrors,
  changedClientFields, missingClientFields } from './clientFormErrors.js';

test('failed JWKS probe is visible and permits same-URL retry after the app comes online', () => {
  const localErrors = {};
  const serverErrors = normalizeClientErrors({ jwks_uri: 'JWKS check failed (ENOTFOUND)' });
  assert.equal(clientErrorsForDisplay(localErrors, serverErrors).jwks_path, 'JWKS check failed (ENOTFOUND)');
  assert.equal(hasBlockingClientErrors(localErrors, 'uri'), false);
  assert.deepEqual(clearEditedServerErrors(serverErrors, { jwks_path: '/corrected.json' }), {});
  assert.equal(hasBlockingClientErrors({ jwks_path: 'Invalid URL' }, 'uri'), true);
});

test('inactive key mode errors do not block the selected mode, but remain when revisited', () => {
  const errors = { jwks_path: 'Invalid URL', jwks: 'Invalid public JWKS' };
  assert.deepEqual(activeClientErrors(errors, 'inline'), { jwks: 'Invalid public JWKS' });
  assert.deepEqual(activeClientErrors(errors, 'uri'), { jwks_path: 'Invalid URL' });
  assert.equal(hasBlockingClientErrors({ jwks_path: 'Invalid URL' }, 'inline'), false);
  assert.equal(hasBlockingClientErrors({ jwks_path: 'Invalid URL' }, 'uri'), true);
});

test('unknown errors remain available for the summary without permanently disabling retry', () => {
  const errors = normalizeClientErrors({ future_field: 'Registration is temporarily unavailable' });
  assert.equal(activeClientErrors(errors, 'uri').future_field, 'Registration is temporarily unavailable');
  assert.equal(hasBlockingClientErrors(errors, 'uri'), false);
});

test('summary preserves every server key error even when its input mode is inactive', () => {
  const server = normalizeClientErrors({ jwks: 'Stored key invalid', jwks_uri: 'Fetch failed', future_field: 'Try later' });
  for (const mode of ['uri', 'inline']) {
    const summary = clientErrorsForDisplay(activeClientErrors({}, mode), server);
    assert.equal(summary.jwks, 'Stored key invalid');
    assert.equal(summary.jwks_path, 'Fetch failed');
    assert.equal(summary.future_field, 'Try later');
  }
});

test('removing a redirect row keeps later errors attached to their surviving inputs', () => {
  const errors = { 'redirect_paths.0': 'First error', 'redirect_paths.2': 'Third error', name: 'Name error' };
  const shifted = removeRedirectErrors(errors, 0);
  assert.deepEqual(shifted, { 'redirect_paths.1': 'Third error', name: 'Name error' });
  assert.equal(hasBlockingClientErrors(shifted, 'uri'), true);
  assert.deepEqual(removeRedirectErrors(shifted, 1), { name: 'Name error' });
});

test('editing related fields clears their server errors while retaining other explanations', () => {
  const errors = { jwks: 'Bad key', jwks_path: 'Unreachable', hostname: 'Bad host', future_field: 'Try later' };
  assert.deepEqual(clearEditedServerErrors(errors, { key_mode: 'inline' }), { hostname: 'Bad host', future_field: 'Try later' });
  assert.deepEqual(clearEditedServerErrors(errors, { hostname: 'fixed.example' }), { jwks: 'Bad key', future_field: 'Try later' });
  assert.equal(clientErrorsForDisplay({ jwks_path: 'Local syntax error' }, errors).jwks_path, 'Local syntax error');
});

test('unchanged normalized blur values preserve server errors, while real edits clear them', () => {
  const form = { hostname: 'app.example', jwks_path: '/jwks', redirect_paths: ['/callback'] };
  const errors = { jwks_path: 'Fetch failed', 'redirect_paths.0': 'Server rejected path' };
  const unchanged = changedClientFields(form, { jwks_path: '/jwks', redirect_paths: ['/callback'] });
  assert.deepEqual(unchanged, {});
  assert.deepEqual(clearEditedServerErrors(errors, unchanged), errors);
  const changed = changedClientFields(form, { jwks_path: '/new-jwks' });
  assert.deepEqual(changed, { jwks_path: '/new-jwks' });
  assert.deepEqual(clearEditedServerErrors(errors, changed), { 'redirect_paths.0': 'Server rejected path' });
});

test('missing-required explanation matches registration eligibility and the selected key mode', () => {
  const form = { client_id: 'app', name: 'Example', hostname: 'app.example',
    redirect_paths: ['/callback'], key_mode: 'uri', jwks_path: '/jwks', jwks_text: '' };
  assert.deepEqual(missingClientFields(form, { isNew: true }), []);
  assert.deepEqual(missingClientFields({ ...form, key_mode: 'inline' }, { isNew: true }), ['Public JWKS']);
  assert.deepEqual(missingClientFields({ ...form, client_id: '', name: ' ', hostname: '', redirect_paths: [''], jwks_path: '' }, { isNew: true }),
    ['Client ID', 'Display name', 'Hostname', 'Redirect path', 'JWKS URL']);
  assert.deepEqual(missingClientFields({ ...form, jwks_path: '' }, { externalJwksUri: 'https://keys.example/jwks' }), []);
  assert.deepEqual(missingClientFields({ ...form, key_mode: 'inline' }, { hasInlineJwks: true }), []);
});
