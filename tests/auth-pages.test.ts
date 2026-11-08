import test from 'node:test';
import assert from 'node:assert/strict';
import { CHALLENGE_HTML } from '../src/challengePage.js';
import { renderLoginPage, renderPasskeyLoginPage, renderChallengePage } from '../src/views.js';

test('the stored Cloudflare page retains its widget contract without origin dependencies', () => {
  for (const token of ['::CF_WIDGET_BOX::', '::RAY_ID::']) {
    assert.equal(CHALLENGE_HTML.split(token).length - 1, 1);
  }
  assert.match(CHALLENGE_HTML, /<head>/);
  assert.doesNotMatch(CHALLENGE_HTML, /<script|_cf_chl_opt|url\(|<link|<img|http-equiv/i);
  assert.match(CHALLENGE_HTML, /name="viewport" content="width=device-width, initial-scale=1"/);
  assert.doesNotMatch(CHALLENGE_HTML, /user-scalable|maximum-scale/);
});

test('motion follows functional login/OTP glue and preserves nonces, normal forms and focus', () => {
  const opts = { txn: 'synthetic-txn', csrf: 'synthetic-csrf', nonce: 'synthetic-nonce',
    siteName: 'Example', passkeyOptions: '{"challenge":"AQ"}' };
  const pages = [renderLoginPage(opts), renderPasskeyLoginPage(opts),
    renderChallengePage({ ...opts, userLabel: 'demo@example.com', method: 'totp', methods: ['totp'] })];
  for (const page of pages) {
    const scripts = [...page.matchAll(/<script([^>]*)>([\s\S]*?)<\/script>/g)];
    assert.ok(scripts.length >= 2);
    for (const script of scripts) assert.equal(script[1], ' nonce="synthetic-nonce"');
    assert.match(scripts.at(-1)![2], /authcard\.geometry\.v1/);
    assert.doesNotMatch(scripts.at(-1)![2], /requestSubmit|preventDefault|credentials\.get|\.focus\(/);
    assert.match(page, /method="post" action="\/login/);
    assert.match(page, /name="txn" value="synthetic-txn"/);
    assert.match(page, /name="csrf" value="synthetic-csrf"/);
    assert.doesNotMatch(page, /user-scalable|maximum-scale/);
  }
  assert.match(pages[0], /autocomplete="username webauthn" autofocus/);
  assert.match(pages[0], /autocomplete="current-password"/);
  assert.match(pages[1], /navigator\.credentials\.get/);
  assert.match(pages[2], /boxes\[0\]\.focus\(\)/);
  assert.match(pages[2], /form\.requestSubmit/);
});
