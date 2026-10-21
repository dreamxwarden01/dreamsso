import test from 'node:test';
import assert from 'node:assert/strict';
import { createSaveFeedback, feedbackTechnical, keyFieldFeedback } from './saveFeedback.js';

function fixture() {
  let time = 0;
  let nextId = 0;
  const jobs = new Map();
  const states = [];
  const feedback = createSaveFeedback({
    emit: (state) => states.push(state), now: () => time,
    schedule: (fn, delay) => { const id = ++nextId; jobs.set(id, { fn, at: time + delay }); return id; },
    cancel: (id) => jobs.delete(id),
  });
  const advance = (delta) => {
    const end = time + delta;
    for (;;) {
      const candidate = [...jobs.entries()].filter(([, job]) => job.at <= end).sort((a, b) => a[1].at - b[1].at)[0];
      if (!candidate) break;
      const [id, job] = candidate;
      jobs.delete(id); time = job.at; job.fn();
    }
    time = end;
  };
  return { feedback, states, advance, jobs };
}

test('fast rejection has minimum pending feedback, two-second result and synchronous duplicate lock', () => {
  const f = fixture();
  assert.equal(f.feedback.begin(), true);
  assert.equal(f.feedback.begin(), false);
  f.feedback.finish('error');
  f.advance(449); assert.deepEqual(f.states, ['pending']);
  f.advance(1); assert.deepEqual(f.states, ['pending', 'error']);
  f.advance(1999); assert.equal(f.feedback.begin(), false);
  f.advance(1); assert.equal(f.states.at(-1), 'returning');
  assert.equal(f.feedback.begin(), false);
  f.advance(220); assert.equal(f.states.at(-1), 'idle');
  assert.equal(f.feedback.begin(), true);
});

test('successful create retains its lock until canonical navigation and never returns to another POST', () => {
  const f = fixture(); let navigations = 0;
  f.feedback.begin(); f.advance(1100);
  f.feedback.finish('success', () => navigations++, true);
  f.advance(0); assert.equal(f.states.at(-1), 'success');
  f.advance(1999); assert.equal(navigations, 0);
  f.advance(1); assert.equal(navigations, 1);
  assert.equal(f.feedback.begin(), false);
  assert.equal(f.states.at(-1), 'success');
});

test('update success resets for later edits without creating another navigation', () => {
  const f = fixture();
  f.feedback.begin(); f.advance(600); f.feedback.finish('success');
  f.advance(2220);
  assert.deepEqual(f.states, ['pending', 'success', 'returning', 'idle']);
  assert.equal(f.feedback.begin(), true);
});

test('dispose and reset invalidate stale completion callbacks, including unreliable cancellation', () => {
  const f = fixture(); let navigated = false;
  f.feedback.begin(); f.feedback.finish('success', () => { navigated = true; }, true);
  const stale = [...f.jobs.values()].map((job) => job.fn);
  f.feedback.dispose(); stale.forEach((fn) => fn());
  assert.deepEqual(f.states, ['pending']); assert.equal(navigated, false);
  f.feedback.begin(); f.feedback.finish('error'); f.feedback.reset(); f.advance(10000);
  assert.deepEqual(f.states, ['pending', 'pending', 'idle']);
});

test('technical disclosure includes only bounded known codes/status and outcome classification', () => {
  assert.equal(feedbackTechnical({ status: 422, code: 'validation_failed', data: { secret: 'never' } }), 'HTTP 422\nCode: validation_failed');
  assert.equal(feedbackTechnical({ status: 0, code: 'request_timeout', uncertain: true }), 'Code: request_timeout\nSave outcome: unconfirmed');
  assert.equal(feedbackTechnical({ status: Infinity, code: 'unexpected_private_payload' }), '');
  assert.equal(feedbackTechnical(null), '');
});


test('known JWKS diagnostics show actionable copy while preserving only parsed safe technical details', () => {
  const message = 'JWKS check failed (ECONNREFUSED: key_transport_or_material_failure)';
  assert.match(keyFieldFeedback('jwks_path', message).message, /refused the connection/);
  assert.equal(keyFieldFeedback('jwks_path', message).technical, 'jwks_path: ECONNREFUSED: key_transport_or_material_failure');
  assert.match(feedbackTechnical({ status: 422, data: { errors: { jwks_uri: message } } }), /jwks_uri: ECONNREFUSED/);
  assert.equal(keyFieldFeedback('jwks_path', 'Must start with /').message, 'Must start with /');
  assert.equal(keyFieldFeedback('name', message).technical, undefined);
  assert.equal(keyFieldFeedback('jwks', 'JWKS check failed (PRIVATE_URL: secret)').technical, undefined);
});
